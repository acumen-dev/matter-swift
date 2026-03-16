// MatterDeviceServer.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel
import MatterCrypto
import MatterProtocol
import MatterTransport
import Logging

/// A Matter device server that listens on UDP, handles PASE commissioning,
/// and routes encrypted Interaction Model messages to a `MatterBridge`.
///
/// `MatterDeviceServer` is the device-side counterpart to `MatterController`.
/// It acts as the SPAKE2+ verifier/responder during PASE, establishes secure
/// sessions, and then proxies encrypted IM traffic to the bridge for processing.
///
/// ```swift
/// let bridge = MatterBridge()
/// bridge.addDimmableLight(name: "Kitchen Pendant")
///
/// let server = MatterDeviceServer(
///     bridge: bridge,
///     transport: AppleUDPTransport(),
///     discovery: AppleDiscovery(),
///     config: .init(
///         discriminator: 3840,
///         passcode: 20202021
///     )
/// )
///
/// try await server.start()
/// // Server is now discoverable and accepting commissioning
/// ```
public actor MatterDeviceServer {

    // MARK: - Config

    /// Server configuration for commissioning and network identity.
    public struct Config: Sendable {
        /// Discriminator (12-bit) for device identification during discovery.
        public let discriminator: UInt16

        /// Setup passcode for PASE commissioning.
        public let passcode: UInt32

        /// UDP listen port (default 5540).
        public let port: UInt16

        /// Vendor ID.
        public let vendorId: UInt16

        /// Product ID.
        public let productId: UInt16

        /// PBKDF2 salt (16-32 bytes). Generated randomly if nil.
        public let salt: Data?

        /// PBKDF2 iteration count (1000-100000).
        public let iterations: Int

        public init(
            discriminator: UInt16 = 3840,
            passcode: UInt32 = 20202021,
            port: UInt16 = 5540,
            vendorId: UInt16 = 0xFFF1,
            productId: UInt16 = 0x8000,
            salt: Data? = nil,
            iterations: Int = 1000
        ) {
            self.discriminator = discriminator
            self.passcode = passcode
            self.port = port
            self.vendorId = vendorId
            self.productId = productId
            self.salt = salt
            self.iterations = iterations
        }
    }

    // MARK: - State

    private let bridge: MatterBridge
    private let transport: any MatterUDPTransport
    private let discovery: any MatterDiscovery
    private let config: Config
    private let logger: Logger

    private var verifier: Spake2pVerifier?
    private var salt: Data = Data()
    private var unsecuredCounter: UInt32 = 0
    private var nextSessionID: UInt16 = 1

    /// Active PASE handshakes keyed by exchange ID.
    private var paseHandshakes: [UInt16: PASEHandshake] = [:]

    /// Active CASE handshakes keyed by exchange ID.
    private var caseHandshakes: [UInt16: CASEHandshake] = [:]

    /// Pending chunked report contexts keyed by exchange ID.
    /// When a report is too large for a single UDP message, subsequent chunks
    /// are sent one at a time as the client acknowledges each with a StatusResponse.
    private var pendingChunkedReports: [UInt16: ChunkedReportContext] = [:]

    /// Established sessions keyed by local session ID.
    private var sessions: [UInt16: SessionEntry] = [:]

    /// Receive loop task.
    private var receiveTask: Task<Void, Never>?

    /// Subscription report loop task.
    private var reportTask: Task<Void, Never>?

    // MARK: - Init

    public init(
        bridge: MatterBridge,
        transport: any MatterUDPTransport,
        discovery: any MatterDiscovery,
        config: Config = Config(),
        logger: Logger = Logger(label: "matter.device.server")
    ) {
        self.bridge = bridge
        self.transport = transport
        self.discovery = discovery
        self.config = config
        self.logger = logger
    }

    // MARK: - Lifecycle

    /// Start the server: compute verifier, bind UDP, advertise via mDNS, begin receive loop.
    public func start() async throws {
        // Generate salt if not provided
        salt = config.salt ?? generateRandomSalt()

        // Compute SPAKE2+ verifier from passcode
        verifier = try Spake2p.computeVerifier(
            passcode: config.passcode,
            salt: salt,
            iterations: config.iterations
        )

        // Load persisted state (fabrics, ACLs, attributes)
        try await bridge.commissioningState.loadFromStore()
        try await bridge.store.loadFromStore()

        // Rebuild CASE-ready fabric info from persisted fabrics
        for (_, fabric) in bridge.commissioningState.fabrics {
            onFabricCommitted(fabric)
        }

        // Hook commissioning state callback for CASE readiness
        bridge.commissioningState.onCommissioningComplete = { [weak self] fabric in
            // Fabric committed — CASE sessions can now be established for this fabric
            Task { [weak self] in
                guard let self else { return }
                await self.onFabricCommitted(fabric)
                await self.bridge.commissioningState.saveToStore()
                await self.bridge.store.saveToStore()
            }
        }

        // Hook fabric removal callback for cleanup
        bridge.commissioningState.onFabricRemoved = { [weak self] fabricIndex in
            Task { [weak self] in
                guard let self else { return }
                await self.onFabricRemoved(fabricIndex)
                await self.bridge.commissioningState.saveToStore()
            }
        }

        // Hook window state callbacks for mDNS updates
        bridge.commissioningState.onWindowOpened = { [weak self] in
            Task { [weak self] in
                guard let self else { return }
                await self.updateCommissioningAdvertisement(open: true)
            }
        }
        bridge.commissioningState.onWindowClosed = { [weak self] in
            Task { [weak self] in
                guard let self else { return }
                await self.updateCommissioningAdvertisement(open: false)
                // Clear any pending PASE handshakes when window closes
                await self.clearPASEHandshakes()
            }
        }

        // Bind UDP transport
        try await transport.bind(port: config.port)

        // Set initial window state based on fabric count.
        // For uncommissioned devices, openBasicWindow fires onWindowOpened → Task { advertise CM=1 }.
        // For commissioned devices, advertise CM=0 directly.
        // Do NOT call advertise() here as well — that would race with the onWindowOpened Task
        // and cause EADDRINUSE when both try to bind the same port concurrently.
        if bridge.commissioningState.fabrics.isEmpty {
            // No fabrics — device is uncommissioned, open basic window.
            // The onWindowOpened callback (set above) will handle mDNS advertisement.
            bridge.commissioningState.openBasicWindow(timeout: 900)
        } else {
            // Already commissioned — advertise commissionable with CM=0 (window closed).
            await updateCommissioningAdvertisement(open: false)
        }

        logger.info("Device server started on port \(config.port)")

        // Start receive loop
        receiveTask = Task { [weak self] in
            guard let self else { return }
            await self.receiveLoop()
        }

        // Start subscription report loop
        reportTask = Task { [weak self] in
            guard let self else { return }
            await self.reportLoop()
        }
    }

    /// Stop the server: cancel loops, stop advertising, close transport.
    public func stop() async {
        receiveTask?.cancel()
        receiveTask = nil
        reportTask?.cancel()
        reportTask = nil

        await discovery.stopAdvertising()
        await transport.close()

        paseHandshakes.removeAll()
        sessions.removeAll()

        logger.info("Device server stopped")
    }

    // MARK: - Receive Loop

    private func receiveLoop() async {
        let stream = transport.receive()
        for await (data, sender) in stream {
            guard !Task.isCancelled else { break }
            do {
                try await handleDatagram(data, from: sender)
            } catch {
                logger.warning("Error handling datagram from \(sender): \(error)")
            }
        }
        logger.debug("Receive loop exited")
    }

    // MARK: - Report Loop

    private func reportLoop() async {
        while !Task.isCancelled {
            do {
                try await Task.sleep(for: .seconds(1))
            } catch {
                break
            }

            let now = Date()

            // Check commissioning window expiry
            if bridge.commissioningState.checkWindowExpiry(now: now) {
                logger.info("Commissioning window expired")
            }

            // Check fail-safe expiry
            if bridge.commissioningState.checkFailSafeExpiry(now: now) {
                logger.info("Fail-safe timer expired")
            }

            // Purge expired timed interaction windows
            await bridge.timedRequestTracker.purgeExpired()

            // Purge stale chunked write buffers
            await bridge.chunkedWriteBuffer.purgeStale()

            // Purge stale chunked invoke buffers
            await bridge.chunkedInvokeBuffer.purgeStale()

            let reports = await bridge.pendingReports(now: now)
            for report in reports {
                guard let chunks = await bridge.buildReport(for: report),
                      let entry = sessionEntry(for: report.sessionID) else {
                    continue
                }

                let exchangeID = allocateExchangeID()

                do {
                    // Send the first chunk
                    guard let firstChunk = chunks.first else { continue }
                    let exchangeHeader = ExchangeHeader(
                        flags: ExchangeFlags(initiator: false, reliableDelivery: true),
                        protocolOpcode: InteractionModelOpcode.reportData.rawValue,
                        exchangeID: exchangeID,
                        protocolID: MatterProtocolID.interactionModel.rawValue
                    )

                    let encrypted = try SecureMessageCodec.encode(
                        exchangeHeader: exchangeHeader,
                        payload: firstChunk.tlvEncode(),
                        session: entry.session,
                        sourceNodeID: NodeID(rawValue: 0)
                    )

                    try await transport.send(encrypted, to: entry.address)
                    await bridge.reportSent(subscriptionID: report.subscriptionID)
                    logger.debug("Sent subscription report \(report.subscriptionID) chunk 1/\(chunks.count) to \(entry.address)")

                    // If there are more chunks, store remainder for delivery on StatusResponse
                    if chunks.count > 1 {
                        let remainingChunks = Array(chunks.dropFirst())
                        pendingChunkedReports[exchangeID] = ChunkedReportContext(chunks: remainingChunks)
                    }
                } catch {
                    logger.warning("Failed to send subscription report: \(error)")
                }
            }
        }
    }

    // MARK: - Datagram Handling

    private func handleDatagram(_ data: Data, from sender: MatterAddress) async throws {
        let (header, headerConsumed) = try MessageHeader.decode(from: data)
        let remaining = Data(data.suffix(from: headerConsumed))

        if header.isUnsecured {
            try await handleUnsecuredMessage(header: header, payload: remaining, from: sender)
        } else if let groupID = header.destinationGroupID, header.securityFlags.sessionType == .group {
            // Group-addressed message (DSIZ = 0x02, session type = group).
            // Route to all member endpoints — no response is sent for group messages (spec §4.16.2).
            try await handleGroupMessage(rawData: data, groupID: groupID, from: sender)
        } else if let entry = sessions[header.sessionID] {
            try await handleSecuredMessage(
                rawData: data,
                session: entry.session,
                address: entry.address,
                fabricIndex: entry.fabricIndex
            )
        } else {
            logger.debug("Dropping message for unknown session \(header.sessionID)")
        }
    }

    // MARK: - Group Message Routing

    /// Route a group-addressed message to all member endpoints.
    ///
    /// Group messages are multicast — the device receives them because it has a session
    /// established for the group key set. They are dispatched to every endpoint that is
    /// a member of the group on the invoking fabric. Responses are suppressed (spec §4.16.2).
    ///
    /// - Note: Full group-key decryption requires matching the group session to a fabric
    ///   via the group key sets installed by `GroupKeyManagementHandler`. For now this
    ///   implementation uses the first available fabric session to decrypt the message
    ///   and then fans out to member endpoints. This covers the single-fabric bridge case.
    private func handleGroupMessage(rawData: Data, groupID: GroupID, from sender: MatterAddress) async throws {
        logger.debug("Group message for group \(groupID.rawValue) — routing to member endpoints")

        // Find a session that can decrypt this group message.
        // In a single-fabric bridge the first CASE session is used. A full implementation
        // would match the group ID to a key set via the GroupKeyMap attribute and derive
        // the operational group key for decryption.
        guard let entry = sessions.values.first(where: { $0.fabricIndex.rawValue != 0 }) else {
            logger.debug("No CASE session available to decrypt group message for group \(groupID.rawValue)")
            return
        }

        let fabricIndex = entry.fabricIndex
        let memberEndpointIDs = bridge.groupMembershipTable.endpoints(
            fabricIndex: fabricIndex.rawValue,
            groupID: groupID.rawValue
        )

        guard !memberEndpointIDs.isEmpty else {
            logger.debug("No member endpoints for group \(groupID.rawValue) on fabric \(fabricIndex)")
            return
        }

        // Attempt to decrypt and decode the message using the CASE session.
        // If decryption fails (wrong key), drop silently — not intended for us.
        let (_, exchangeHeader, payload): (MessageHeader, ExchangeHeader, Data)
        do {
            (_, exchangeHeader, payload) = try SecureMessageCodec.decode(data: rawData, session: entry.session)
        } catch {
            logger.debug("Group message decryption failed for group \(groupID.rawValue): \(error)")
            return
        }

        guard exchangeHeader.protocolID == MatterProtocolID.interactionModel.rawValue,
              let opcode = InteractionModelOpcode(rawValue: exchangeHeader.protocolOpcode) else {
            logger.debug("Group message is not an IM message for group \(groupID.rawValue)")
            return
        }

        // Build a request context that marks this as a group message (no response).
        let requestContext = IMRequestContext(
            checkerContext: ACLChecker.RequestContext(
                isPASE: false,
                subjectNodeID: entry.session.peerNodeID.rawValue,
                fabricIndex: fabricIndex,
                isGroupMessage: true,
                groupID: groupID.rawValue
            ),
            acls: bridge.commissioningState.committedACLs[fabricIndex] ?? [],
            isGroupMessage: true
        )

        bridge.commissioningState.invokingFabricIndex = fabricIndex

        // Dispatch the IM operation to each member endpoint, discarding responses.
        // For group invokes each endpoint processes the command independently.
        for endpointIDRaw in memberEndpointIDs {
            let _ = try? await bridge.handleIM(
                opcode: opcode,
                payload: payload,
                sessionID: entry.session.localSessionID,
                fabricIndex: fabricIndex,
                exchangeID: exchangeHeader.exchangeID,
                requestContext: requestContext
            )
            logger.debug("Dispatched group message to endpoint \(endpointIDRaw) for group \(groupID.rawValue)")
        }
        // No response sent — group messages are fire-and-forget (spec §4.16.2.1)
    }

    // MARK: - Unsecured Message Handling (PASE)

    private func handleUnsecuredMessage(
        header: MessageHeader,
        payload: Data,
        from sender: MatterAddress
    ) async throws {
        let (exchangeHeader, exchConsumed) = try ExchangeHeader.decode(from: payload)
        let body = Data(payload.suffix(from: exchConsumed))

        guard exchangeHeader.protocolID == MatterProtocolID.secureChannel.rawValue else {
            logger.debug("Ignoring unsecured message with protocol \(exchangeHeader.protocolID)")
            return
        }

        guard let opcode = SecureChannelOpcode(rawValue: exchangeHeader.protocolOpcode) else {
            logger.debug("Unknown secure channel opcode: \(exchangeHeader.protocolOpcode)")
            return
        }

        switch opcode {
        case .pbkdfParamRequest:
            try await handlePBKDFParamRequest(body, exchangeID: exchangeHeader.exchangeID, from: sender)
        case .pasePake1:
            try await handlePake1(body, exchangeID: exchangeHeader.exchangeID, from: sender)
        case .pasePake3:
            try await handlePake3(body, exchangeID: exchangeHeader.exchangeID, from: sender)
        case .caseSigma1:
            try await handleSigma1(body, exchangeID: exchangeHeader.exchangeID, from: sender)
        case .caseSigma3:
            try await handleSigma3(body, exchangeID: exchangeHeader.exchangeID, from: sender)
        default:
            logger.debug("Ignoring unsecured opcode \(opcode) on exchange \(exchangeHeader.exchangeID)")
        }
    }

    // MARK: - PASE Step 1: PBKDFParamRequest → PBKDFParamResponse

    private func handlePBKDFParamRequest(
        _ data: Data,
        exchangeID: UInt16,
        from sender: MatterAddress
    ) async throws {
        let request = try PASEMessages.PBKDFParamRequest.fromTLV(data)

        let responderSessionID = allocateSessionID()
        var responderRandom = Data(count: 32)
        responderRandom.withUnsafeMutableBytes { buf in
            var rng = SystemRandomNumberGenerator()
            buf.storeBytes(of: rng.next(), toByteOffset: 0,  as: UInt64.self)
            buf.storeBytes(of: rng.next(), toByteOffset: 8,  as: UInt64.self)
            buf.storeBytes(of: rng.next(), toByteOffset: 16, as: UInt64.self)
            buf.storeBytes(of: rng.next(), toByteOffset: 24, as: UInt64.self)
        }

        let response = PASEMessages.PBKDFParamResponse(
            initiatorRandom: request.initiatorRandom,
            responderRandom: responderRandom,
            responderSessionID: responderSessionID,
            iterations: UInt32(config.iterations),
            salt: salt
        )

        let requestTLV = request.tlvEncode()
        let responseTLV = response.tlvEncode()

        // Store handshake state
        paseHandshakes[exchangeID] = PASEHandshake(
            exchangeID: exchangeID,
            sender: sender,
            initiatorSessionID: request.initiatorSessionID,
            responderSessionID: responderSessionID,
            pbkdfParamRequestData: requestTLV,
            pbkdfParamResponseData: responseTLV
        )

        let message = buildUnsecuredMessage(
            payload: responseTLV,
            opcode: .pbkdfParamResponse,
            exchangeID: exchangeID,
            isInitiator: false
        )

        try await transport.send(message, to: sender)
        logger.debug("Sent PBKDFParamResponse on exchange \(exchangeID)")
    }

    // MARK: - PASE Step 2: Pake1 → Pake2

    private func handlePake1(
        _ data: Data,
        exchangeID: UInt16,
        from sender: MatterAddress
    ) async throws {
        guard var handshake = paseHandshakes[exchangeID] else {
            logger.warning("Pake1 for unknown exchange \(exchangeID)")
            return
        }
        guard let verifier else {
            logger.error("No verifier computed")
            return
        }

        let pake1 = try PASEMessages.Pake1Message.fromTLV(data)

        // Compute hash context from the PBKDF param exchange
        let hashContext = Spake2p.computeHashContext(
            pbkdfParamRequest: handshake.pbkdfParamRequestData,
            pbkdfParamResponse: handshake.pbkdfParamResponseData
        )

        // Verifier step 1: compute pB and cB
        let (verifierContext, pB, cB) = try Spake2p.verifierStep1(
            pA: pake1.pA,
            verifier: verifier,
            hashContext: hashContext
        )

        handshake.verifierContext = verifierContext
        paseHandshakes[exchangeID] = handshake

        let pake2 = PASEMessages.Pake2Message(pB: pB, cB: cB)
        let message = buildUnsecuredMessage(
            payload: pake2.tlvEncode(),
            opcode: .pasePake2,
            exchangeID: exchangeID,
            isInitiator: false
        )

        try await transport.send(message, to: sender)
        logger.debug("Sent Pake2 on exchange \(exchangeID)")
    }

    // MARK: - PASE Step 3: Pake3 → Session Established

    private func handlePake3(
        _ data: Data,
        exchangeID: UInt16,
        from sender: MatterAddress
    ) async throws {
        guard let handshake = paseHandshakes[exchangeID] else {
            logger.warning("Pake3 for unknown exchange \(exchangeID)")
            return
        }
        guard let verifierContext = handshake.verifierContext else {
            logger.warning("Pake3 before Pake2 on exchange \(exchangeID)")
            return
        }

        let pake3 = try PASEMessages.Pake3Message.fromTLV(data)

        // Verifier step 2: verify cA and get shared secret
        let ke = try Spake2p.verifierStep2(
            context: verifierContext,
            cA: pake3.cA
        )

        // Derive session keys from shared secret
        let sessionKeys = KeyDerivation.deriveSessionKeys(sharedSecret: ke)

        // Device is responder: encrypt with R2I, decrypt with I2R
        let session = SecureSession(
            localSessionID: handshake.responderSessionID,
            peerSessionID: handshake.initiatorSessionID,
            establishment: .pase,
            peerNodeID: NodeID(rawValue: 0),
            encryptKey: sessionKeys.r2iKey,
            decryptKey: sessionKeys.i2rKey,
            attestationKey: sessionKeys.attestationKey
        )

        let fabricIndex = FabricIndex(rawValue: 0)
        sessions[handshake.responderSessionID] = SessionEntry(
            session: session,
            address: sender,
            fabricIndex: fabricIndex
        )

        paseHandshakes.removeValue(forKey: exchangeID)

        // Store attestation challenge for use in AttestationRequest handling.
        // The attestation key (bytes 32-47 of HKDF output) is the challenge value.
        if let attKey = session.attestationKey {
            let challengeData = attKey.withUnsafeBytes { Data($0) }
            bridge.commissioningState.attestationChallenge = challengeData
        }

        // Send status report success
        let statusReport = StatusReportMessage(
            generalStatus: .success,
            protocolID: UInt32(MatterProtocolID.secureChannel.rawValue),
            protocolStatus: SecureChannelStatusCode.success.rawValue
        )

        let message = buildUnsecuredMessage(
            payload: statusReport.encode(),
            opcode: .statusReport,
            exchangeID: exchangeID,
            isInitiator: false
        )

        try await transport.send(message, to: sender)
        logger.info("PASE session established: local=\(handshake.responderSessionID) peer=\(handshake.initiatorSessionID)")
    }

    // MARK: - CASE Step 1: Sigma1 → Sigma2

    private func handleSigma1(
        _ data: Data,
        exchangeID: UInt16,
        from sender: MatterAddress
    ) async throws {
        // Find a committed fabric that matches the destination ID in Sigma1
        guard let (fabricInfo, _) = findMatchingFabric(sigma1Data: data) else {
            logger.warning("No matching fabric for Sigma1 on exchange \(exchangeID)")
            return
        }

        let handler = CASEProtocolHandler(fabricInfo: fabricInfo)
        let responderSessionID = allocateSessionID()

        let (sigma2Data, handshakeCtx) = try handler.handleSigma1(
            payload: data,
            responderSessionID: responderSessionID
        )

        caseHandshakes[exchangeID] = CASEHandshake(
            exchangeID: exchangeID,
            sender: sender,
            responderSessionID: responderSessionID,
            handlerContext: handshakeCtx,
            fabricInfo: fabricInfo
        )

        let message = buildUnsecuredMessage(
            payload: sigma2Data,
            opcode: .caseSigma2,
            exchangeID: exchangeID,
            isInitiator: false
        )

        try await transport.send(message, to: sender)
        logger.debug("Sent Sigma2 on exchange \(exchangeID)")
    }

    // MARK: - CASE Step 2: Sigma3 → Session Established

    private func handleSigma3(
        _ data: Data,
        exchangeID: UInt16,
        from sender: MatterAddress
    ) async throws {
        guard let handshake = caseHandshakes[exchangeID] else {
            logger.warning("Sigma3 for unknown exchange \(exchangeID)")
            return
        }

        let handler = CASEProtocolHandler(fabricInfo: handshake.fabricInfo)

        // Use the responderSessionID allocated during Sigma1 — this is the ID
        // the controller will use as peerSessionID when sending encrypted messages.
        let session = try handler.handleSigma3(
            payload: data,
            context: handshake.handlerContext,
            initiatorRCAC: handshake.fabricInfo.rcac,
            localSessionID: handshake.responderSessionID
        )

        sessions[session.localSessionID] = SessionEntry(
            session: session,
            address: sender,
            fabricIndex: handshake.fabricInfo.fabricIndex
        )

        caseHandshakes.removeValue(forKey: exchangeID)

        // Send status report success
        let statusReport = StatusReportMessage(
            generalStatus: .success,
            protocolID: UInt32(MatterProtocolID.secureChannel.rawValue),
            protocolStatus: SecureChannelStatusCode.success.rawValue
        )

        let message = buildUnsecuredMessage(
            payload: statusReport.encode(),
            opcode: .statusReport,
            exchangeID: exchangeID,
            isInitiator: false
        )

        try await transport.send(message, to: sender)
        logger.info("CASE session established: local=\(handshake.responderSessionID) fabric=\(handshake.fabricInfo.fabricIndex)")
    }

    // MARK: - Fabric Management

    /// Committed fabrics available for CASE session establishment.
    private var committedFabrics: [FabricIndex: FabricInfo] = [:]

    private func onFabricCommitted(_ fabric: CommittedFabric) {
        do {
            let fabricInfo = try fabric.fabricInfo()
            committedFabrics[fabric.fabricIndex] = fabricInfo

            // Advertise operational service for this fabric
            let opName = OperationalInstanceName(
                compressedFabricID: fabricInfo.compressedFabricID(),
                nodeID: fabricInfo.nodeID.rawValue
            )

            let port = config.port
            let discovery = self.discovery
            Task {
                try? await discovery.advertise(service: MatterServiceRecord(
                    name: opName.instanceName,
                    serviceType: .operational,
                    host: "",
                    port: port,
                    txtRecords: [:]
                ))
            }

            logger.info("Fabric \(fabric.fabricIndex) committed, CASE ready, advertising \(opName.instanceName)")
        } catch {
            logger.error("Failed to build FabricInfo from committed fabric: \(error)")
        }
    }

    /// Find a committed fabric matching the Sigma1 destination ID.
    private func findMatchingFabric(sigma1Data: Data) -> (FabricInfo, FabricIndex)? {
        for (index, info) in committedFabrics {
            // Try to create a responder step1 — if destination ID matches, it succeeds
            let handler = CASEProtocolHandler(fabricInfo: info)
            if let _ = try? handler.handleSigma1(payload: sigma1Data, responderSessionID: 0) {
                return (info, index)
            }
        }
        return nil
    }

    // MARK: - Secured Message Handling (IM)

    private func handleSecuredMessage(
        rawData: Data,
        session: SecureSession,
        address: MatterAddress,
        fabricIndex: FabricIndex
    ) async throws {
        let (_, exchangeHeader, payload) = try SecureMessageCodec.decode(
            data: rawData,
            session: session
        )

        // Route based on protocol ID
        if exchangeHeader.protocolID == MatterProtocolID.interactionModel.rawValue {
            guard let opcode = InteractionModelOpcode(rawValue: exchangeHeader.protocolOpcode) else {
                logger.debug("Unknown IM opcode: \(exchangeHeader.protocolOpcode)")
                return
            }

            // Construct ACL request context from session
            let requestContext = IMRequestContext(
                checkerContext: ACLChecker.RequestContext(
                    isPASE: session.establishment == .pase,
                    subjectNodeID: session.peerNodeID.rawValue,
                    fabricIndex: fabricIndex
                ),
                acls: bridge.commissioningState.committedACLs[fabricIndex] ?? []
            )

            // Set invoking fabric context for commands that need it
            bridge.commissioningState.invokingFabricIndex = fabricIndex

            // Check if this is a StatusResponse on an exchange with pending chunks
            if opcode == .statusResponse, var context = pendingChunkedReports[exchangeHeader.exchangeID] {
                // Client acknowledged the previous chunk — send the next one
                if let nextChunk = context.nextChunk() {
                    let chunkHeader = ExchangeHeader(
                        flags: ExchangeFlags(initiator: false, reliableDelivery: true),
                        protocolOpcode: InteractionModelOpcode.reportData.rawValue,
                        exchangeID: exchangeHeader.exchangeID,
                        protocolID: MatterProtocolID.interactionModel.rawValue
                    )
                    let encrypted = try SecureMessageCodec.encode(
                        exchangeHeader: chunkHeader,
                        payload: nextChunk.tlvEncode(),
                        session: session,
                        sourceNodeID: NodeID(rawValue: 0)
                    )
                    try await transport.send(encrypted, to: address)
                }

                if context.isComplete {
                    pendingChunkedReports.removeValue(forKey: exchangeHeader.exchangeID)
                    // Send any trailing responses (e.g., SubscribeResponse after final chunk)
                    for (trailingOpcode, trailingData) in context.trailingResponses {
                        let trailingHeader = ExchangeHeader(
                            flags: ExchangeFlags(initiator: false, reliableDelivery: true),
                            protocolOpcode: trailingOpcode.rawValue,
                            exchangeID: exchangeHeader.exchangeID,
                            protocolID: MatterProtocolID.interactionModel.rawValue
                        )
                        let encrypted = try SecureMessageCodec.encode(
                            exchangeHeader: trailingHeader,
                            payload: trailingData,
                            session: session,
                            sourceNodeID: NodeID(rawValue: 0)
                        )
                        try await transport.send(encrypted, to: address)
                    }
                } else {
                    pendingChunkedReports[exchangeHeader.exchangeID] = context
                }
                return
            }

            let result = try await bridge.handleIM(
                opcode: opcode,
                payload: payload,
                sessionID: session.localSessionID,
                fabricIndex: fabricIndex,
                exchangeID: exchangeHeader.exchangeID,
                requestContext: requestContext
            )

            switch result {
            case .responses(let pairs):
                for (responseOpcode, responseData) in pairs {
                    let responseExchangeHeader = ExchangeHeader(
                        flags: ExchangeFlags(
                            initiator: false,
                            reliableDelivery: true
                        ),
                        protocolOpcode: responseOpcode.rawValue,
                        exchangeID: exchangeHeader.exchangeID,
                        protocolID: MatterProtocolID.interactionModel.rawValue
                    )

                    let encrypted = try SecureMessageCodec.encode(
                        exchangeHeader: responseExchangeHeader,
                        payload: responseData,
                        session: session,
                        sourceNodeID: NodeID(rawValue: 0)
                    )

                    try await transport.send(encrypted, to: address)
                }

            case .chunkedReport(var context):
                // Send first chunk immediately
                if let firstChunk = context.nextChunk() {
                    let chunkHeader = ExchangeHeader(
                        flags: ExchangeFlags(initiator: false, reliableDelivery: true),
                        protocolOpcode: InteractionModelOpcode.reportData.rawValue,
                        exchangeID: exchangeHeader.exchangeID,
                        protocolID: MatterProtocolID.interactionModel.rawValue
                    )
                    let encrypted = try SecureMessageCodec.encode(
                        exchangeHeader: chunkHeader,
                        payload: firstChunk.tlvEncode(),
                        session: session,
                        sourceNodeID: NodeID(rawValue: 0)
                    )
                    try await transport.send(encrypted, to: address)
                }
                // Store remaining chunks for delivery on subsequent StatusResponse messages
                if !context.isComplete {
                    pendingChunkedReports[exchangeHeader.exchangeID] = context
                } else if !context.trailingResponses.isEmpty {
                    // Single chunk but has trailing responses — send them now
                    for (trailingOpcode, trailingData) in context.trailingResponses {
                        let trailingHeader = ExchangeHeader(
                            flags: ExchangeFlags(initiator: false, reliableDelivery: true),
                            protocolOpcode: trailingOpcode.rawValue,
                            exchangeID: exchangeHeader.exchangeID,
                            protocolID: MatterProtocolID.interactionModel.rawValue
                        )
                        let encrypted = try SecureMessageCodec.encode(
                            exchangeHeader: trailingHeader,
                            payload: trailingData,
                            session: session,
                            sourceNodeID: NodeID(rawValue: 0)
                        )
                        try await transport.send(encrypted, to: address)
                    }
                }
            }
        } else if exchangeHeader.protocolID == MatterProtocolID.secureChannel.rawValue {
            // Handle secure channel messages (e.g., MRP acks, close session)
            logger.debug("Secure channel message on session \(session.localSessionID)")
        } else {
            logger.debug("Unknown protocol \(exchangeHeader.protocolID) on session \(session.localSessionID)")
        }
    }

    // MARK: - Message Building

    private func buildUnsecuredMessage(
        payload: Data,
        opcode: SecureChannelOpcode,
        exchangeID: UInt16,
        isInitiator: Bool
    ) -> Data {
        let messageHeader = MessageHeader(
            sessionID: 0,
            messageCounter: nextUnsecuredCounter(),
            sourceNodeID: nil
        )

        let exchangeHeader = ExchangeHeader(
            flags: ExchangeFlags(
                initiator: isInitiator,
                reliableDelivery: true
            ),
            protocolOpcode: opcode.rawValue,
            exchangeID: exchangeID,
            protocolID: MatterProtocolID.secureChannel.rawValue
        )

        var message = messageHeader.encode()
        message.append(exchangeHeader.encode())
        message.append(payload)
        return message
    }

    // MARK: - Helpers

    private func nextUnsecuredCounter() -> UInt32 {
        unsecuredCounter &+= 1
        return unsecuredCounter
    }

    private func allocateSessionID() -> UInt16 {
        let id = nextSessionID
        nextSessionID &+= 1
        if nextSessionID == 0 { nextSessionID = 1 }
        return id
    }

    private var nextExchangeIDValue: UInt16 = 0

    private func allocateExchangeID() -> UInt16 {
        nextExchangeIDValue &+= 1
        return nextExchangeIDValue
    }

    private func sessionEntry(for sessionID: UInt16) -> SessionEntry? {
        sessions[sessionID]
    }

    private func generateRandomSalt() -> Data {
        var salt = Data(count: 32)
        salt.withUnsafeMutableBytes { buf in
            var rng = SystemRandomNumberGenerator()
            buf.storeBytes(of: rng.next(), toByteOffset: 0,  as: UInt64.self)
            buf.storeBytes(of: rng.next(), toByteOffset: 8,  as: UInt64.self)
            buf.storeBytes(of: rng.next(), toByteOffset: 16, as: UInt64.self)
            buf.storeBytes(of: rng.next(), toByteOffset: 24, as: UInt64.self)
        }
        return salt
    }

    // MARK: - Fabric Removal

    private func onFabricRemoved(_ fabricIndex: FabricIndex) {
        // Remove CASE-ready fabric info
        committedFabrics.removeValue(forKey: fabricIndex)

        // Close any sessions for this fabric
        let sessionsToRemove = sessions.filter { $0.value.fabricIndex == fabricIndex }
        for (sessionID, _) in sessionsToRemove {
            sessions.removeValue(forKey: sessionID)
        }

        logger.info("Fabric \(fabricIndex) removed, \(sessionsToRemove.count) sessions closed")
    }

    // MARK: - Commissioning Window Management

    /// Update mDNS commissionable advertisement based on window state.
    private func updateCommissioningAdvertisement(open: Bool) async {
        let cmValue = open ? "1" : "0"
        let shortDisc = (config.discriminator >> 8) & 0x0F
        let txtRecords = [
            "D":  "\(config.discriminator)",
            "VP": "\(config.vendorId)+\(config.productId)",
            "CM": cmValue,
            "DN": "SwiftMatter Bridge",
        ]

        // DNS-SD subtypes required for Matter commissioning discovery (Matter spec §4.3.1.1).
        // Apple Home browses for _L<disc>._sub._matterc._udp to find devices by discriminator.
        // _CM subtype signals that the commissioning window is open.
        let subtypes: [String] = open
            ? ["_CM", "_L\(config.discriminator)", "_S\(shortDisc)"]
            : []

        do {
            try await discovery.advertise(service: MatterServiceRecord(
                name: "SwiftMatter-\(config.discriminator)",
                serviceType: .commissionable,
                host: "",
                port: config.port,
                txtRecords: txtRecords,
                subtypes: subtypes
            ))
            logger.debug("Updated commissionable mDNS: CM=\(cmValue)")
        } catch {
            logger.warning("Failed to update commissionable mDNS: \(error)")
        }
    }

    /// Clear all pending PASE handshakes (called when window closes).
    private func clearPASEHandshakes() {
        if !paseHandshakes.isEmpty {
            logger.debug("Clearing \(paseHandshakes.count) pending PASE handshakes")
            paseHandshakes.removeAll()
        }
    }
}

// MARK: - Supporting Types

extension MatterDeviceServer {

    /// Active PASE handshake state.
    struct PASEHandshake {
        let exchangeID: UInt16
        let sender: MatterAddress
        let initiatorSessionID: UInt16
        let responderSessionID: UInt16
        let pbkdfParamRequestData: Data
        let pbkdfParamResponseData: Data
        var verifierContext: Spake2pVerifierContext?
    }

    /// An established session with its associated network address.
    struct SessionEntry {
        let session: SecureSession
        let address: MatterAddress
        let fabricIndex: FabricIndex
    }

    /// Active CASE handshake state.
    struct CASEHandshake {
        let exchangeID: UInt16
        let sender: MatterAddress
        let responderSessionID: UInt16
        let handlerContext: CASEProtocolHandler.ResponderHandshakeContext
        let fabricInfo: FabricInfo
    }
}
