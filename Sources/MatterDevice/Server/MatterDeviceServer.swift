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

        // Hook commissioning state callback for CASE readiness
        bridge.commissioningState.onCommissioningComplete = { [weak self] fabric in
            // Fabric committed — CASE sessions can now be established for this fabric
            Task { [weak self] in
                guard let self else { return }
                await self.onFabricCommitted(fabric)
            }
        }

        // Bind UDP transport
        try await transport.bind(port: config.port)

        // Advertise via mDNS
        let txtRecords = [
            "D": "\(config.discriminator)",
            "VP": "\(config.vendorId)+\(config.productId)",
            "CM": "1",  // Commissioning mode: basic
        ]

        try await discovery.advertise(service: MatterServiceRecord(
            name: "SwiftMatter-\(config.discriminator)",
            serviceType: .commissionable,
            host: "",
            port: config.port,
            txtRecords: txtRecords
        ))

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

            let reports = await bridge.pendingReports(now: Date())
            for report in reports {
                guard let reportData = await bridge.buildReport(for: report),
                      let entry = sessionEntry(for: report.sessionID) else {
                    continue
                }

                do {
                    let exchangeHeader = ExchangeHeader(
                        flags: ExchangeFlags(initiator: false, reliableDelivery: true),
                        protocolOpcode: InteractionModelOpcode.reportData.rawValue,
                        exchangeID: allocateExchangeID(),
                        protocolID: MatterProtocolID.interactionModel.rawValue
                    )

                    let encrypted = try SecureMessageCodec.encode(
                        exchangeHeader: exchangeHeader,
                        payload: reportData,
                        session: entry.session,
                        sourceNodeID: NodeID(rawValue: 0)
                    )

                    try await transport.send(encrypted, to: entry.address)
                    await bridge.reportSent(subscriptionID: report.subscriptionID)
                    logger.debug("Sent subscription report \(report.subscriptionID) to \(entry.address)")
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
        responderRandom.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }

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
            logger.info("Fabric \(fabric.fabricIndex) committed, CASE ready")
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

            let responses = try await bridge.handleIM(
                opcode: opcode,
                payload: payload,
                sessionID: session.localSessionID,
                fabricIndex: fabricIndex
            )

            for (responseOpcode, responseData) in responses {
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
        salt.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        return salt
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
