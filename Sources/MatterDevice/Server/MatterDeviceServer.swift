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

        /// Device name shown in the controller UI during commissioning (DN TXT record).
        public let deviceName: String

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
            deviceName: String = "Matter Bridge",
            salt: Data? = nil,
            iterations: Int = 1000
        ) {
            self.discriminator = discriminator
            self.passcode = passcode
            self.port = port
            self.vendorId = vendorId
            self.productId = productId
            self.deviceName = deviceName
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
    private var iterations: Int = 1000
    /// Unsecured session message counter. Per Matter spec §4.10.2.3 the initial value
    /// MUST be a fresh random 32-bit value so the iPhone's per-peer replay-protection
    /// window doesn't reject messages from a previous commissioning attempt.
    private var unsecuredCounter: UInt32 = UInt32.random(in: 0...UInt32.max)
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

    /// Operational instance name advertised after AddNOC but before CommissioningComplete.
    ///
    /// Per Matter spec §4.3.5, the device SHALL start operational mDNS advertising after the
    /// NOC is installed (staged). This name is used to withdraw the advertisement if the
    /// fail-safe expires before CommissioningComplete is received.
    private var stagedOperationalInstanceName: String?

    /// Interface name on which the active PASE session was established.
    ///
    /// Captured from the PASE Pake3 sender address (e.g. `"fe80::...%en1"` → `"en1"`).
    /// Passed as `preferredInterface` when advertising the operational mDNS record so that
    /// `matter-bridge.local.` AAAA is registered only on this interface — preventing the
    /// commissioner from receiving a link-local address for a different interface (e.g.
    /// Ethernet) that is unreachable from its Wi-Fi network segment.
    private var paseCommissioningInterface: String?

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
        // Load persisted state first — we need the PBKDF salt before computing the verifier.
        // Controllers (e.g. Apple Home) cache PBKDF parameters after a successful PASE session
        // and send `hasPBKDFParameters = true` on subsequent commissioning attempts. The server
        // must respond with the same salt it used before, or SPAKE2+ will fail.
        try await bridge.commissioningState.loadFromStore()
        try await bridge.store.loadFromStore()

        // Resolve salt: persisted (stable across restarts) > config-provided > random (first run)
        let commState = bridge.commissioningState
        if let persistedSalt = commState.pbkdfSalt {
            salt = persistedSalt
            iterations = commState.pbkdfIterations
        } else {
            salt = config.salt ?? generateRandomSalt()
            iterations = config.iterations
            commState.pbkdfSalt = salt
            commState.pbkdfIterations = iterations
            await commState.saveToStore()
            logger.debug("Generated and persisted new PBKDF salt (\(salt.count) bytes, \(iterations) iterations)")
        }

        // Compute SPAKE2+ verifier from passcode + stable salt
        verifier = try Spake2p.computeVerifier(
            passcode: config.passcode,
            salt: salt,
            iterations: iterations
        )

        // Generate Device Attestation Credentials (PAA → PAI → DAC chain) if not already set.
        // These are used during commissioning for CertificateChainRequest and AttestationRequest.
        if bridge.commissioningState.attestationCredentials == nil {
            let dac = try DeviceAttestationCredentials.testCredentials(
                vendorID: config.vendorId,
                productID: config.productId
            )
            bridge.commissioningState.attestationCredentials = dac
            logger.debug("Generated test attestation credentials (VID=0x\(String(config.vendorId, radix: 16)) PID=0x\(String(config.productId, radix: 16)))")
        }

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

        // Hook NOC staging callback for pre-CommissioningComplete operational mDNS advertisement.
        // Per Matter spec §4.3.5, operational advertisement MUST begin after AddNOC, not after
        // CommissioningComplete. Apple Home waits for this advertisement before sending
        // CommissioningComplete, causing the commissioning to time out if we don't advertise.
        bridge.commissioningState.onNOCStaged = { [weak self] in
            Task { [weak self] in
                guard let self else { return }
                await self.advertiseStagedNOC()
            }
        }

        // Hook NOC reverted callback to withdraw the staged advertisement on fail-safe expiry.
        bridge.commissioningState.onNOCReverted = { [weak self] in
            Task { [weak self] in
                guard let self else { return }
                await self.revokeStagedNOCAdvertisement()
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
            do {
                try await handleSecuredMessage(
                    rawData: data,
                    session: entry.session,
                    address: sender,
                    fabricIndex: entry.fabricIndex
                )
            } catch {
                // Decryption failure on an established session typically means a stale
                // retransmit from a previous commissioning attempt (wrong session keys).
                logger.warning("Secured message error for session \(header.sessionID) counter=\(header.messageCounter) from \(sender): \(error)")
            }
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
            logger.debug("Unknown secure channel opcode: \(exchangeHeader.protocolOpcode) exchange=\(exchangeHeader.exchangeID) ack=\(String(describing: exchangeHeader.acknowledgedMessageCounter))")
            return
        }

        logger.debug("Unsecured opcode=\(opcode) exchange=\(exchangeHeader.exchangeID) ack=\(String(describing: exchangeHeader.acknowledgedMessageCounter)) bodyLen=\(body.count)")

        switch opcode {
        case .pbkdfParamRequest:
            try await handlePBKDFParamRequest(body, exchangeID: exchangeHeader.exchangeID,
                                              messageCounter: header.messageCounter,
                                              initiatorNodeID: header.sourceNodeID, from: sender)
        case .pasePake1:
            try await handlePake1(body, exchangeID: exchangeHeader.exchangeID,
                                  messageCounter: header.messageCounter,
                                  initiatorNodeID: header.sourceNodeID, from: sender)
        case .pasePake3:
            try await handlePake3(body, exchangeID: exchangeHeader.exchangeID,
                                  messageCounter: header.messageCounter,
                                  initiatorNodeID: header.sourceNodeID, from: sender)
        case .caseSigma1:
            try await handleSigma1(body, exchangeID: exchangeHeader.exchangeID,
                                   messageCounter: header.messageCounter,
                                   initiatorNodeID: header.sourceNodeID, from: sender)
        case .caseSigma3:
            try await handleSigma3(body, exchangeID: exchangeHeader.exchangeID,
                                   messageCounter: header.messageCounter,
                                   initiatorNodeID: header.sourceNodeID, from: sender)
        case .statusReport:
            if let report = try? StatusReportMessage.decode(from: body) {
                logger.warning("[CASE] StatusReport on exchange \(exchangeHeader.exchangeID): general=\(report.generalStatus) protocolID=0x\(String(report.protocolID, radix: 16)) protocolStatus=0x\(String(report.protocolStatus, radix: 16))")
            } else {
                logger.warning("[CASE] StatusReport on exchange \(exchangeHeader.exchangeID): body=\(body.map { String(format: "%02X", $0) }.joined())")
            }
        default:
            logger.debug("Ignoring unsecured opcode \(opcode) on exchange \(exchangeHeader.exchangeID)")
        }
    }

    // MARK: - PASE Step 1: PBKDFParamRequest → PBKDFParamResponse

    private func handlePBKDFParamRequest(
        _ data: Data,
        exchangeID: UInt16,
        messageCounter: UInt32,
        initiatorNodeID: NodeID?,
        from sender: MatterAddress
    ) async throws {
        // Duplicate detection: if Apple Home retransmits (because it didn't get an MRP ACK),
        // resend the original response using the stored TLV — don't regenerate new random data.
        if let existing = paseHandshakes[exchangeID] {
            let message = buildUnsecuredMessage(
                payload: existing.pbkdfParamResponseData,
                opcode: .pbkdfParamResponse,
                exchangeID: exchangeID,
                isInitiator: false,
                ackMessageCounter: messageCounter,
                destinationNodeID: existing.initiatorNodeID
            )
            logger.debug("Resend PBKDFParamResponse exchange=\(exchangeID) counter=\(messageCounter) bytes=\(message.hexDump)")
            try await transport.send(message, to: sender)
            logger.debug("Resent PBKDFParamResponse (duplicate) on exchange \(exchangeID)")
            return
        }

        logger.debug("PBKDFParamRequest raw (\(data.count)B): \(data.hexDump)")

        let request = try PASEMessages.PBKDFParamRequest.fromTLV(data)
        logger.debug("PBKDFParamRequest: exchange=\(exchangeID) hasPBKDFParams=\(request.hasPBKDFParameters) sessID=\(request.initiatorSessionID) passcodeID=\(request.passcodeID) sender=\(sender.host):\(sender.port) counter=\(messageCounter)")

        let responderSessionID = allocateSessionID()
        var responderRandom = Data(count: 32)
        responderRandom.withUnsafeMutableBytes { buf in
            var rng = SystemRandomNumberGenerator()
            buf.storeBytes(of: rng.next(), toByteOffset: 0,  as: UInt64.self)
            buf.storeBytes(of: rng.next(), toByteOffset: 8,  as: UInt64.self)
            buf.storeBytes(of: rng.next(), toByteOffset: 16, as: UInt64.self)
            buf.storeBytes(of: rng.next(), toByteOffset: 24, as: UInt64.self)
        }

        // If hasPBKDFParameters is true, the initiator has cached our PBKDF params from a
        // previous session and will use them. Per Matter spec §5.3.2.1 we MUST omit tag 4
        // (pbkdf_parameters) from the response — including it causes the initiator to reject
        // the response and retransmit indefinitely (observed with Apple Home).
        if request.hasPBKDFParameters {
            logger.debug("Initiator has cached PBKDF params (hasPBKDFParameters=true) — omitting tag 4")
        }

        let response = PASEMessages.PBKDFParamResponse(
            initiatorRandom: request.initiatorRandom,
            responderRandom: responderRandom,
            responderSessionID: responderSessionID,
            iterations: UInt32(iterations),
            salt: salt
        )

        // Use the RAW bytes as received for the SPAKE2+ transcript hash (TT).
        // Re-encoding would drop any optional fields (e.g., tag 5 initiatorSessionParams)
        // the initiator included, producing a different byte sequence and a hash mismatch
        // that would fail Pake3 verification.
        let requestTLV = data

        let responseTLV = response.tlvEncode(includePBKDFParams: !request.hasPBKDFParameters)

        // Store handshake state
        paseHandshakes[exchangeID] = PASEHandshake(
            exchangeID: exchangeID,
            sender: sender,
            initiatorSessionID: request.initiatorSessionID,
            responderSessionID: responderSessionID,
            pbkdfParamRequestData: requestTLV,
            pbkdfParamResponseData: responseTLV,
            initiatorNodeID: initiatorNodeID
        )

        let message = buildUnsecuredMessage(
            payload: responseTLV,
            opcode: .pbkdfParamResponse,
            exchangeID: exchangeID,
            isInitiator: false,
            ackMessageCounter: messageCounter,
            destinationNodeID: initiatorNodeID
        )

        logger.debug("PBKDFParamResponse exchange=\(exchangeID) tlvLen=\(responseTLV.count) includePBKDF=\(!request.hasPBKDFParameters) ackCounter=\(messageCounter) wire(\(message.count)B): \(message.hexDump)")
        try await transport.send(message, to: sender)
        logger.debug("Sent PBKDFParamResponse on exchange \(exchangeID) to \(sender.host):\(sender.port) includedPBKDFParams=\(!request.hasPBKDFParameters) tlvLen=\(responseTLV.count) msgLen=\(message.count)")
    }

    // MARK: - PASE Step 2: Pake1 → Pake2

    private func handlePake1(
        _ data: Data,
        exchangeID: UInt16,
        messageCounter: UInt32,
        initiatorNodeID: NodeID?,
        from sender: MatterAddress
    ) async throws {
        guard var handshake = paseHandshakes[exchangeID] else {
            logger.warning("Pake1 for unknown exchange \(exchangeID)")
            return
        }

        // Duplicate detection: if the initiator retransmits Pake1 (because it
        // didn't get an MRP ACK for Pake2), resend the stored Pake2 response.
        // Regenerating a new Pake2 with fresh SPAKE2+ random values would
        // invalidate any in-flight Pake3 and break the handshake.
        if let storedPake2 = handshake.pake2ResponsePayload {
            let message = buildUnsecuredMessage(
                payload: storedPake2,
                opcode: .pasePake2,
                exchangeID: exchangeID,
                isInitiator: false,
                ackMessageCounter: messageCounter,
                destinationNodeID: handshake.initiatorNodeID
            )
            try await transport.send(message, to: sender)
            logger.debug("Resent Pake2 (duplicate Pake1) on exchange \(exchangeID)")
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

        let pake2 = PASEMessages.Pake2Message(pB: pB, cB: cB)
        let pake2Payload = pake2.tlvEncode()
        handshake.pake2ResponsePayload = pake2Payload
        paseHandshakes[exchangeID] = handshake

        let message = buildUnsecuredMessage(
            payload: pake2Payload,
            opcode: .pasePake2,
            exchangeID: exchangeID,
            isInitiator: false,
            ackMessageCounter: messageCounter,
            destinationNodeID: handshake.initiatorNodeID
        )

        try await transport.send(message, to: sender)
        logger.debug("Sent Pake2 on exchange \(exchangeID)")
    }

    // MARK: - PASE Step 3: Pake3 → Session Established

    private func handlePake3(
        _ data: Data,
        exchangeID: UInt16,
        messageCounter: UInt32,
        initiatorNodeID: NodeID?,
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
            isInitiator: false,
            ackMessageCounter: messageCounter,
            destinationNodeID: handshake.initiatorNodeID
        )

        try await transport.send(message, to: sender)
        logger.info("PASE session established: local=\(handshake.responderSessionID) peer=\(handshake.initiatorSessionID)")

        // Record the interface the commissioner used so CASE address resolution is
        // restricted to the same interface (prevents link-local confusion on dual-homed hosts).
        if let pct = sender.host.firstIndex(of: "%") {
            let ifName = String(sender.host[sender.host.index(after: pct)...])
            if !ifName.isEmpty {
                paseCommissioningInterface = ifName
                logger.debug("PASE: commissioning interface \(ifName) — will restrict operational AAAA to this interface")
            }
        }
    }

    // MARK: - CASE Step 1: Sigma1 → Sigma2

    private func handleSigma1(
        _ data: Data,
        exchangeID: UInt16,
        messageCounter: UInt32,
        initiatorNodeID: NodeID?,
        from sender: MatterAddress
    ) async throws {
        logger.info("CASE Sigma1 received from \(sender) on exchange \(exchangeID)")

        // MRP retransmit detection: if we already have a handshake for this exchange the
        // initiator is retransmitting Sigma1 because our Sigma2 was lost.  Re-send the
        // stored Sigma2 payload so the initiator can continue with the original ephemeral
        // key material — generating a fresh Sigma2 would invalidate any Sigma3 that Apple
        // Home has already computed against the first Sigma2.
        if let existing = caseHandshakes[exchangeID] {
            logger.info("CASE Sigma1 retransmit on exchange \(exchangeID) — resending stored Sigma2")
            let message = buildUnsecuredMessage(
                payload: existing.sigma2Payload,
                opcode: .caseSigma2,
                exchangeID: exchangeID,
                isInitiator: false,
                ackMessageCounter: messageCounter,
                destinationNodeID: existing.initiatorNodeID
            )
            try await transport.send(message, to: sender)
            return
        }

        // Find a committed fabric that matches the destination ID in Sigma1
        guard let (fabricInfo, _) = findMatchingFabric(sigma1Data: data) else {
            logger.warning("No matching fabric for Sigma1 on exchange \(exchangeID) — IPK mismatch or unknown fabric")
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
            fabricInfo: fabricInfo,
            initiatorNodeID: initiatorNodeID,
            sigma2Payload: sigma2Data
        )

        let message = buildUnsecuredMessage(
            payload: sigma2Data,
            opcode: .caseSigma2,
            exchangeID: exchangeID,
            isInitiator: false,
            ackMessageCounter: messageCounter,
            destinationNodeID: initiatorNodeID
        )

        try await transport.send(message, to: sender)
        logger.debug("Sent Sigma2 on exchange \(exchangeID)")
    }

    // MARK: - CASE Step 2: Sigma3 → Session Established

    private func handleSigma3(
        _ data: Data,
        exchangeID: UInt16,
        messageCounter: UInt32,
        initiatorNodeID: NodeID?,
        from sender: MatterAddress
    ) async throws {
        guard let handshake = caseHandshakes[exchangeID] else {
            logger.warning("Sigma3 for unknown exchange \(exchangeID)")
            return
        }

        let handler = CASEProtocolHandler(fabricInfo: handshake.fabricInfo)

        // Use the responderSessionID allocated during Sigma1 — this is the ID
        // the controller will use as peerSessionID when sending encrypted messages.
        let session: SecureSession
        do {
            session = try handler.handleSigma3(
                payload: data,
                context: handshake.handlerContext,
                initiatorRCAC: handshake.fabricInfo.rcac,
                localSessionID: handshake.responderSessionID
            )
        } catch {
            logger.error("CASE Sigma3 failed on exchange \(exchangeID) (fabric=\(handshake.fabricInfo.fabricIndex)): \(error)")
            caseHandshakes.removeValue(forKey: exchangeID)
            throw error
        }

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
            isInitiator: false,
            ackMessageCounter: messageCounter,
            destinationNodeID: handshake.initiatorNodeID
        )

        try await transport.send(message, to: sender)
        logger.info("CASE session established: local=\(handshake.responderSessionID) fabric=\(handshake.fabricInfo.fabricIndex)")
    }

    // MARK: - Fabric Management

    /// Committed fabrics available for CASE session establishment.
    private var committedFabrics: [FabricIndex: FabricInfo] = [:]

    /// Staged fabric info available for CASE during the commissioning window.
    ///
    /// Set when AddNOC is processed (before CommissioningComplete). This allows the
    /// commissioner to establish a CASE session — required to *send* CommissioningComplete
    /// per spec §5.5.2. Cleared when the fabric is committed or the fail-safe expires.
    private var stagedFabricInfo: FabricInfo?

    private func onFabricCommitted(_ fabric: CommittedFabric) {
        // Clear staged state — the fabric is now committed.
        stagedOperationalInstanceName = nil
        stagedFabricInfo = nil

        func hexDump(_ data: Data) -> String {
            stride(from: 0, to: data.count, by: 16).map { i in
                let chunk = data[i..<min(i + 16, data.count)]
                let hex = chunk.map { String(format: "%02X", $0) }.joined(separator: " ")
                return String(format: "    %04X: %@", i, hex)
            }.joined(separator: "\n")
        }

        let rcac: MatterCertificate
        do { rcac = try MatterCertificate.fromTLV(fabric.rcacTLV) }
        catch {
            logger.error("onFabricCommitted: RCAC parse failed — fabric \(fabric.fabricIndex) not committed: \(error)")
            logger.error("  RCAC (\(fabric.rcacTLV.count) bytes):\n\(hexDump(fabric.rcacTLV))")
            return
        }

        let noc: MatterCertificate
        do { noc = try MatterCertificate.fromTLV(fabric.nocTLV) }
        catch {
            logger.error("onFabricCommitted: NOC parse failed — fabric \(fabric.fabricIndex) not committed: \(error)")
            logger.error("  NOC (\(fabric.nocTLV.count) bytes):\n\(hexDump(fabric.nocTLV))")
            return
        }

        // ICAC: non-fatal. If Apple's ICAC can't be parsed we still register the fabric so
        // CASE Sigma1 can be processed. Chain validation during Sigma3 will warn if ICAC is absent.
        var icac: MatterCertificate?
        if let icacBytes = fabric.icacTLV {
            do { icac = try MatterCertificate.fromTLV(icacBytes) }
            catch {
                logger.warning("onFabricCommitted: ICAC parse failed (fabric \(fabric.fabricIndex) registered without ICAC): \(error)")
                logger.warning("  ICAC (\(icacBytes.count) bytes):\n\(hexDump(icacBytes))")
            }
        }

        let fabricInfo = FabricInfo(
            fabricIndex: fabric.fabricIndex,
            fabricID: noc.subject.fabricID ?? FabricID(rawValue: 0),
            nodeID: noc.subject.nodeID ?? NodeID(rawValue: 0),
            rcac: rcac,
            icac: icac,
            rawICAC: fabric.icacTLV,   // forward raw bytes for CASE even if parsing failed
            noc: noc,
            rawNOC: fabric.nocTLV,     // forward raw bytes for CASE to avoid re-encoding roundtrip
            operationalKey: fabric.operationalKey,
            ipkEpochKey: fabric.ipkEpochKey
        )
        committedFabrics[fabric.fabricIndex] = fabricInfo

        // Advertise operational service for this fabric
        let opName = OperationalInstanceName(
            compressedFabricID: fabricInfo.compressedFabricID(),
            nodeID: fabricInfo.nodeID.rawValue
        )
        let cfidSubtype = String(format: "_I%016llX", fabricInfo.compressedFabricID())

        let port = config.port
        let discovery = self.discovery
        let opNameInstance = opName.instanceName
        let preferredIface = paseCommissioningInterface
        Task {
            do {
                try await discovery.advertise(service: MatterServiceRecord(
                    name: opNameInstance,
                    serviceType: .operational,
                    host: "",
                    port: port,
                    txtRecords: ["SII": "5000", "SAI": "300", "T": "0"],
                    subtypes: [cfidSubtype],
                    preferredInterface: preferredIface
                ))
            } catch {
                logger.error("onFabricCommitted: mDNS registration failed for '\(opNameInstance)': \(error)")
            }
        }

        if icac == nil && fabric.icacTLV != nil {
            logger.warning("Fabric \(fabric.fabricIndex) committed without ICAC — CASE chain validation will skip intermediate cert")
        } else {
            logger.info("Fabric \(fabric.fabricIndex) committed, CASE ready, advertising \(opName.instanceName)")
        }
    }

    /// Advertise the staged operational mDNS record immediately after AddNOC.
    ///
    /// Per Matter spec §4.3.5, the device SHALL begin advertising its operational instance
    /// name as soon as the NOC is installed (staged), before CommissioningComplete. This
    /// allows Apple Home to discover the device operationally and send CommissioningComplete.
    ///
    /// The staged fabric is not yet committed — `committedFabrics` is NOT updated here.
    /// When CommissioningComplete fires, `onFabricCommitted` re-advertises the same name
    /// and adds it to `committedFabrics` so CASE sessions can be established.
    private func advertiseStagedNOC() {
        let cs = bridge.commissioningState
        guard let nocData = cs.stagedNOC,
              let rcacData = cs.stagedRCAC,
              let opKey = cs.operationalKey else {
            logger.warning("advertiseStagedNOC: missing staged credentials, skipping advertisement")
            return
        }

        let icacData = cs.stagedICAC
        let icacDesc = icacData.map { "\($0.count) bytes" } ?? "absent"
        logger.debug("advertiseStagedNOC: RCAC \(rcacData.count) bytes, NOC \(nocData.count) bytes, ICAC \(icacDesc)")

        // Per spec §4.3.5, operational mDNS advertisement only requires the compressed fabric ID
        // (from RCAC public key + fabric ID) and the node ID (from NOC subject). Parse them first.
        // ICAC parsing is needed for full chain validation during CASE but NOT for this advertisement,
        // so ICAC parse failures are treated as non-fatal here (we warn and continue without ICAC).

        func hexDump(_ data: Data) -> String {
            stride(from: 0, to: data.count, by: 16).map { i in
                let chunk = data[i..<min(i + 16, data.count)]
                let hex = chunk.map { String(format: "%02X", $0) }.joined(separator: " ")
                return String(format: "    %04X: %@", i, hex)
            }.joined(separator: "\n")
        }

        let rcac: MatterCertificate
        do { rcac = try MatterCertificate.fromTLV(rcacData) }
        catch {
            logger.error("advertiseStagedNOC: RCAC parse failed: \(error)")
            logger.error("  RCAC (\(rcacData.count) bytes):\n\(hexDump(rcacData))")
            return
        }

        let noc: MatterCertificate
        do { noc = try MatterCertificate.fromTLV(nocData) }
        catch {
            logger.error("advertiseStagedNOC: NOC parse failed: \(error)")
            logger.error("  NOC (\(nocData.count) bytes):\n\(hexDump(nocData))")
            return
        }

        // ICAC is optional for the operational name computation; warn on parse failure but continue.
        var icac: MatterCertificate?
        if let icacBytes = icacData {
            do { icac = try MatterCertificate.fromTLV(icacBytes) }
            catch {
                logger.warning("advertiseStagedNOC: ICAC parse failed (non-fatal for mDNS): \(error)")
                logger.warning("  ICAC (\(icacBytes.count) bytes):\n\(hexDump(icacBytes))")
                // Continue — ICAC is not required for the operational instance name.
            }
        }

        let fabricIndex = FabricIndex(rawValue: UInt8(cs.fabrics.count + 1))
        let fabricInfo = FabricInfo(
            fabricIndex: fabricIndex,
            fabricID: noc.subject.fabricID ?? FabricID(rawValue: 0),
            nodeID: noc.subject.nodeID ?? NodeID(rawValue: 0),
            rcac: rcac,
            icac: icac,
            rawICAC: icacData,          // forward raw bytes for CASE even if parsing failed
            noc: noc,
            rawNOC: nocData,            // forward raw bytes for CASE to avoid re-encoding roundtrip
            operationalKey: opKey,
            ipkEpochKey: cs.stagedIPK ?? Data(repeating: 0, count: 16)
        )

        // Make the staged fabric available for CASE session matching.
        // The commissioner MUST establish a CASE session (per spec §5.5.2) to send
        // CommissioningComplete. Without this, findMatchingFabric() can't find the fabric
        // and Sigma1 is rejected, creating a deadlock where neither side can proceed.
        stagedFabricInfo = fabricInfo

        let opName = OperationalInstanceName(
            compressedFabricID: fabricInfo.compressedFabricID(),
            nodeID: fabricInfo.nodeID.rawValue
        )
        stagedOperationalInstanceName = opName.instanceName

        // Per Matter spec §4.3.1.3, operational advertisements MUST include SII and SAI
        // TXT records. Apple Home validates these before establishing a CASE session.
        let cfidSubtype = String(format: "_I%016llX", fabricInfo.compressedFabricID())

        let port = config.port
        let discovery = self.discovery
        let preferredIfaceStaged = paseCommissioningInterface
        Task {
            do {
                try await discovery.advertise(service: MatterServiceRecord(
                    name: opName.instanceName,
                    serviceType: .operational,
                    host: "",
                    port: port,
                    txtRecords: ["SII": "5000", "SAI": "300", "T": "0"],
                    subtypes: [cfidSubtype],
                    preferredInterface: preferredIfaceStaged
                ))
            } catch {
                logger.error("advertiseStagedNOC: mDNS registration failed for '\(opName.instanceName)': \(error)")
            }
        }

        logger.info("AddNOC: advertising staged operational name \(opName.instanceName) cfid=\(cfidSubtype) ipkLen=\(cs.stagedIPK?.count ?? 0) (pre-CommissioningComplete)")
    }

    /// Withdraw the staged operational mDNS advertisement when the fail-safe expires.
    ///
    /// Called when `disarmFailSafe()` clears staged credentials without a CommissioningComplete.
    private func revokeStagedNOCAdvertisement() {
        guard let instanceName = stagedOperationalInstanceName else { return }
        stagedOperationalInstanceName = nil
        stagedFabricInfo = nil   // no longer needed

        let discovery = self.discovery
        Task {
            await discovery.stopAdvertising(name: instanceName)
        }

        logger.info("Fail-safe expired: withdrew staged operational advertisement \(instanceName)")
    }

    /// Find a fabric matching the Sigma1 destination ID.
    ///
    /// Checks both committed fabrics (for post-CommissioningComplete CASE) and the
    /// staged fabric (for the initial CommissioningComplete exchange, per spec §5.5.2).
    private func findMatchingFabric(sigma1Data: Data) -> (FabricInfo, FabricIndex)? {
        // Check committed fabrics first (most common path after commissioning)
        for (index, info) in committedFabrics {
            let handler = CASEProtocolHandler(fabricInfo: info)
            do {
                let _ = try handler.handleSigma1(payload: sigma1Data, responderSessionID: 0)
                return (info, index)
            } catch {
                logger.debug("CASE: committed fabric \(index) did not match Sigma1: \(error)")
            }
        }

        // Check the staged fabric — needed for the initial CASE session that carries
        // CommissioningComplete. The fabric is staged after AddNOC but not yet committed.
        if let staged = stagedFabricInfo {
            let handler = CASEProtocolHandler(fabricInfo: staged)
            do {
                let _ = try handler.handleSigma1(payload: sigma1Data, responderSessionID: 0)
                return (staged, staged.fabricIndex)
            } catch {
                logger.warning("CASE: staged fabric \(staged.fabricIndex) did not match Sigma1: \(error) — IPK or destinationId mismatch")
            }
        } else {
            logger.warning("CASE: no staged fabric available for Sigma1 matching")
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
        let (msgHeader, exchangeHeader, payload) = try SecureMessageCodec.decode(
            data: rawData,
            session: session
        )

        logger.debug("Secured msg: session=\(session.localSessionID) exchange=\(exchangeHeader.exchangeID) proto=\(exchangeHeader.protocolID) opcode=\(exchangeHeader.protocolOpcode) counter=\(msgHeader.messageCounter) payload=\(payload.count)B")

        // ACK counter to piggyback on the first response for this message.
        // MRP requires ACKing any message with reliableDelivery=true; piggybacking
        // on the response avoids the need for a separate standalone ACK datagram.
        var pendingAck: UInt32? = exchangeHeader.flags.reliableDelivery ? msgHeader.messageCounter : nil

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
                        protocolID: MatterProtocolID.interactionModel.rawValue,
                        acknowledgedMessageCounter: pendingAck
                    )
                    pendingAck = nil
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
                            protocolID: MatterProtocolID.interactionModel.rawValue,
                            acknowledgedMessageCounter: pendingAck
                        )
                        pendingAck = nil
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
                        protocolID: MatterProtocolID.interactionModel.rawValue,
                        acknowledgedMessageCounter: pendingAck
                    )
                    pendingAck = nil

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
                        protocolID: MatterProtocolID.interactionModel.rawValue,
                        acknowledgedMessageCounter: pendingAck
                    )
                    pendingAck = nil
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
                            protocolID: MatterProtocolID.interactionModel.rawValue,
                            acknowledgedMessageCounter: pendingAck
                        )
                        pendingAck = nil
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
            logger.debug("Secure channel message on session \(session.localSessionID): opcode=\(exchangeHeader.protocolOpcode)")
        } else {
            logger.debug("Unknown protocol \(exchangeHeader.protocolID) on session \(session.localSessionID)")
        }
    }

    // MARK: - Message Building

    private func buildUnsecuredMessage(
        payload: Data,
        opcode: SecureChannelOpcode,
        exchangeID: UInt16,
        isInitiator: Bool,
        ackMessageCounter: UInt32? = nil,
        destinationNodeID: NodeID? = nil
    ) -> Data {
        let messageHeader = MessageHeader(
            sessionID: 0,
            messageCounter: nextUnsecuredCounter(),
            sourceNodeID: nil,
            destinationNodeID: destinationNodeID
        )

        let exchangeHeader = ExchangeHeader(
            flags: ExchangeFlags(
                initiator: isInitiator,
                reliableDelivery: true
            ),
            protocolOpcode: opcode.rawValue,
            exchangeID: exchangeID,
            protocolID: MatterProtocolID.secureChannel.rawValue,
            acknowledgedMessageCounter: ackMessageCounter
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
            "DN": config.deviceName,
        ]

        // DNS-SD subtypes required for Matter commissioning discovery (Matter spec §4.3.1.1).
        // Apple Home browses for _L<disc>._sub._matterc._udp to find devices by discriminator.
        // _CM subtype signals that the commissioning window is open.
        let subtypes: [String] = open
            ? ["_CM", "_L\(config.discriminator)", "_S\(shortDisc)"]
            : []

        do {
            try await discovery.advertise(service: MatterServiceRecord(
                name: "\(config.deviceName)-\(config.discriminator)",
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
        /// Source node ID from the initiator's PBKDFParamRequest header.
        /// Echoed as destinationNodeID in all PASE responses so Apple Home's MRP
        /// layer recognises the message as addressed to it (CHIP SDK behaviour).
        let initiatorNodeID: NodeID?
        var verifierContext: Spake2pVerifierContext?
        /// The raw Pake2 payload bytes — stored so we can re-send idempotently
        /// if the initiator retransmits Pake1 on the same exchange ID (MRP behaviour).
        var pake2ResponsePayload: Data?
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
        /// Source node ID from the initiator's Sigma1 message header.
        /// Echoed as destinationNodeID in Sigma2 and StatusReport responses.
        let initiatorNodeID: NodeID?
        /// The raw Sigma2 payload bytes — stored so we can re-send idempotently
        /// if the initiator retransmits Sigma1 on the same exchange ID (MRP behaviour).
        let sigma2Payload: Data
    }
}

// MARK: - Debug Hex Dump

private extension Data {
    /// Hex dump: groups of 8 bytes separated by spaces, 16 per line, with byte offsets.
    ///
    /// Example output:
    /// ```
    /// 0000: 00 00 00 00 01 00 00 00  06 21 34 12 00 00 05 00
    /// 0010: 00 00 15 30 01 20 ...
    /// ```
    var hexDump: String {
        guard !isEmpty else { return "<empty>" }
        var lines: [String] = []
        var offset = 0
        while offset < count {
            let chunk = Array(self[offset..<Swift.min(offset + 16, count)])
            let hexParts = chunk.enumerated().map { i, b -> String in
                i == 8 ? " \(String(format: "%02x", b))" : String(format: "%02x", b)
            }
            lines.append(String(format: "%04x: %@", offset, hexParts.joined(separator: " ")))
            offset += 16
        }
        return "\n" + lines.joined(separator: "\n")
    }
}
