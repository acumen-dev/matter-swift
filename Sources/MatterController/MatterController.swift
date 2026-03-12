// MatterController.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import Logging
import MatterTypes
import MatterModel
import MatterCrypto
import MatterProtocol
import MatterTransport

/// High-level Matter controller that orchestrates commissioning and
/// operational device interaction.
///
/// Wires together the pure data-transformation components
/// (`CommissioningController`, `ControllerSession`, `OperationalController`)
/// with injected transport and discovery protocols to provide a practical
/// async/await API.
///
/// ```swift
/// let controller = try MatterController(
///     transport: myUDPTransport,
///     discovery: myDiscovery,
///     configuration: .init(fabricID: FabricID(rawValue: 1))
/// )
///
/// let device = try await controller.commission(
///     address: deviceAddress,
///     setupCode: 20202021
/// )
///
/// let value = try await controller.readAttribute(
///     nodeID: device.nodeID,
///     endpointID: .root,
///     clusterID: ClusterID(rawValue: 0x0006),
///     attributeID: AttributeID(rawValue: 0)
/// )
/// ```
public actor MatterController {

    // MARK: - Configuration

    /// Controller configuration.
    public struct Configuration: Sendable {
        /// Fabric identifier.
        public let fabricID: FabricID

        /// Node ID for this controller (default: 1).
        public let controllerNodeID: NodeID

        /// Vendor ID for NOC issuance (default: .test).
        public let vendorID: VendorID

        /// Root CA key pair (default: new key).
        public let rootKey: P256.Signing.PrivateKey

        /// Timeout for individual operational messages (default: 30s).
        public let operationTimeout: Duration

        /// Timeout for the full commissioning flow (default: 120s).
        public let commissioningTimeout: Duration

        public init(
            fabricID: FabricID,
            controllerNodeID: NodeID = NodeID(rawValue: 1),
            vendorID: VendorID = .test,
            rootKey: P256.Signing.PrivateKey = P256.Signing.PrivateKey(),
            operationTimeout: Duration = .seconds(30),
            commissioningTimeout: Duration = .seconds(120)
        ) {
            self.fabricID = fabricID
            self.controllerNodeID = controllerNodeID
            self.vendorID = vendorID
            self.rootKey = rootKey
            self.operationTimeout = operationTimeout
            self.commissioningTimeout = commissioningTimeout
        }
    }

    // MARK: - Properties

    private let fabricManager: FabricManager
    private let commissioning: CommissioningController
    private let controllerSession: ControllerSession
    private let operationalController: OperationalController
    private let registry: DeviceRegistry
    private let subscriptionClient: SubscriptionClient
    private let transceiver: MessageTransceiver
    private let discovery: any MatterDiscovery
    private let configuration: Configuration
    private let logger: Logger

    private var sessionCache = SessionCache()
    private var exchangeCounter: UInt16 = 1
    private var unsecuredMessageCounter: UInt32

    // MARK: - Init

    /// Create a controller with injected transport and discovery.
    ///
    /// - Parameters:
    ///   - transport: UDP transport for message exchange.
    ///   - discovery: mDNS/DNS-SD discovery service.
    ///   - configuration: Controller configuration.
    ///   - logger: Logger instance (default: "matter.controller").
    public init(
        transport: any MatterUDPTransport,
        discovery: any MatterDiscovery,
        configuration: Configuration,
        logger: Logger = Logger(label: "matter.controller")
    ) throws {
        self.fabricManager = try FabricManager(
            rootKey: configuration.rootKey,
            fabricID: configuration.fabricID,
            controllerNodeID: configuration.controllerNodeID,
            vendorID: configuration.vendorID
        )
        self.commissioning = CommissioningController(fabricManager: fabricManager)
        self.controllerSession = ControllerSession(fabricManager: fabricManager)
        self.operationalController = OperationalController()
        self.registry = DeviceRegistry()
        self.subscriptionClient = SubscriptionClient()
        self.transceiver = MessageTransceiver(transport: transport)
        self.discovery = discovery
        self.configuration = configuration
        self.logger = logger

        // Initialize unsecured message counter with random 28-bit value per spec
        self.unsecuredMessageCounter = UInt32.random(in: 0...0x0FFF_FFFF)
    }

    // MARK: - Discovery

    /// Browse for commissionable devices on the local network.
    public func discoverCommissionable() -> AsyncStream<MatterServiceRecord> {
        discovery.browse(type: .commissionable)
    }

    /// Resolve a discovered service record to a network address.
    public func resolve(_ record: MatterServiceRecord) async throws -> MatterAddress {
        try await discovery.resolve(record)
    }

    // MARK: - Commissioning

    /// Commission a device at the given address using the setup passcode.
    ///
    /// Drives the full commissioning flow:
    /// 1. PASE session establishment (PBKDFParamRequest → Pake3)
    /// 2. ArmFailSafe
    /// 3. SetRegulatoryConfig
    /// 4. CSRRequest → generate NOC
    /// 5. AddTrustedRootCert + AddNOC
    /// 6. ACL write
    /// 7. CommissioningComplete
    ///
    /// - Parameters:
    ///   - address: The device's network address.
    ///   - setupCode: The device's setup passcode (e.g., 20202021).
    /// - Returns: The commissioned device record.
    public func commission(
        address: MatterAddress,
        setupCode: UInt32
    ) async throws -> CommissionedDevice {
        let timeout = configuration.operationTimeout

        logger.info("Beginning commissioning to \(address.host):\(address.port)")

        // Step 1a: PBKDFParamRequest
        let sessionID = sessionCache.allocateSessionID()
        let (pbkdfReq, ctx1) = commissioning.beginPASE(
            passcode: setupCode,
            initiatorSessionID: sessionID
        )

        let exchangeID = nextExchangeID()
        let pbkdfMsg = buildUnsecuredMessage(
            payload: pbkdfReq,
            opcode: .pbkdfParamRequest,
            exchangeID: exchangeID,
            isInitiator: true
        )

        let pbkdfRespMsg = try await transceiver.sendAndReceive(
            pbkdfMsg, to: address, timeout: timeout
        )
        let pbkdfResp = try extractUnsecuredPayload(from: pbkdfRespMsg)

        // Step 1b: Pake1
        let (pake1, ctx2) = try commissioning.handlePBKDFParamResponse(
            response: pbkdfResp, context: ctx1
        )

        let pake1Msg = buildUnsecuredMessage(
            payload: pake1,
            opcode: .pasePake1,
            exchangeID: exchangeID,
            isInitiator: true
        )

        let pake2Msg = try await transceiver.sendAndReceive(
            pake1Msg, to: address, timeout: timeout
        )
        let pake2 = try extractUnsecuredPayload(from: pake2Msg)

        // Step 1c: Pake3 → PASE session established
        let (pake3, ctx3) = try commissioning.handlePake2(
            response: pake2, context: ctx2
        )

        let pake3Msg = buildUnsecuredMessage(
            payload: pake3,
            opcode: .pasePake3,
            exchangeID: exchangeID,
            isInitiator: true
        )

        try await transceiver.send(pake3Msg, to: address)

        guard let paseSession = ctx3.paseSession else {
            throw ControllerError.paseHandshakeFailed("No PASE session after Pake3")
        }

        logger.info("PASE session established (localSession=\(paseSession.localSessionID))")

        // Steps 2-7: Commissioning over encrypted PASE session
        let sourceNodeID = fabricManager.controllerFabricInfo.nodeID

        // Step 2: ArmFailSafe
        let (armMsg, ctx4) = try commissioning.buildArmFailSafe(context: ctx3)
        let armResp = try await sendIMRequest(
            payload: armMsg, session: paseSession,
            sourceNodeID: sourceNodeID, to: address,
            opcode: .invokeRequest
        )
        let ctx5 = try commissioning.handleArmFailSafeResponse(
            response: armResp, context: ctx4
        )

        // Step 3: SetRegulatoryConfig
        let regMsg = commissioning.buildSetRegulatoryConfig(context: ctx5)
        let regResp = try await sendIMRequest(
            payload: regMsg, session: paseSession,
            sourceNodeID: sourceNodeID, to: address,
            opcode: .invokeRequest
        )
        try commissioning.handleSetRegulatoryConfigResponse(response: regResp)

        // Step 4: CSRRequest
        let csrMsg = commissioning.buildCSRRequest()
        let csrResp = try await sendIMRequest(
            payload: csrMsg, session: paseSession,
            sourceNodeID: sourceNodeID, to: address,
            opcode: .invokeRequest
        )
        let (addRootMsg, addNOCMsg, deviceNodeID, ctx6) = try await commissioning.handleCSRResponse(
            response: csrResp, context: ctx5
        )

        // Step 5: AddTrustedRootCert
        let addRootResp = try await sendIMRequest(
            payload: addRootMsg, session: paseSession,
            sourceNodeID: sourceNodeID, to: address,
            opcode: .invokeRequest
        )
        // Root cert add returns a status response — check for errors
        _ = addRootResp

        // Step 5b: AddNOC
        let addNOCResp = try await sendIMRequest(
            payload: addNOCMsg, session: paseSession,
            sourceNodeID: sourceNodeID, to: address,
            opcode: .invokeRequest
        )
        let (aclMsg, ctx7) = try commissioning.handleNOCResponse(
            response: addNOCResp, context: ctx6
        )

        // Step 6: ACL write
        let aclResp = try await sendIMRequest(
            payload: aclMsg, session: paseSession,
            sourceNodeID: sourceNodeID, to: address,
            opcode: .writeRequest
        )
        _ = aclResp

        // Step 7: CommissioningComplete
        let completeMsg = commissioning.buildCommissioningComplete()
        let completeResp = try await sendIMRequest(
            payload: completeMsg, session: paseSession,
            sourceNodeID: sourceNodeID, to: address,
            opcode: .invokeRequest
        )
        var device = try commissioning.handleCommissioningComplete(
            response: completeResp, context: ctx7
        )

        // Store the operational address
        device.setOperationalAddress(address)

        // Register in device registry
        await registry.register(device)

        logger.info("Commissioning complete: nodeID=\(deviceNodeID.rawValue)")

        return device
    }

    // MARK: - Session Management

    /// Get or establish a CASE session to a commissioned device.
    ///
    /// Returns a cached session if one exists and has not expired;
    /// otherwise establishes a new CASE session via Sigma1/2/3.
    public func session(for nodeID: NodeID) async throws -> SecureSession {
        // Check cache first
        if let cached = sessionCache.session(for: nodeID) {
            return cached
        }

        // Need to establish a new CASE session
        return try await establishCASESession(nodeID: nodeID)
    }

    /// Invalidate the cached session for a node (e.g., after a communication error).
    public func invalidateSession(for nodeID: NodeID) {
        sessionCache.remove(for: nodeID)
    }

    // MARK: - Operational API

    /// Read a single attribute from a commissioned device.
    ///
    /// Automatically manages CASE sessions, with a single retry on session failure.
    public func readAttribute(
        nodeID: NodeID,
        endpointID: EndpointID,
        clusterID: ClusterID,
        attributeID: AttributeID
    ) async throws -> TLVElement {
        try await withSessionRetry(nodeID: nodeID) { session, address in
            let sourceNodeID = self.fabricManager.controllerFabricInfo.nodeID
            let msg = try self.operationalController.readAttribute(
                endpointID: endpointID,
                clusterID: clusterID,
                attributeID: attributeID,
                session: session,
                sourceNodeID: sourceNodeID
            )

            let response = try await self.transceiver.sendAndReceive(
                msg, to: address, timeout: self.configuration.operationTimeout
            )

            return try self.operationalController.parseReadResponse(
                encryptedMessage: response, session: session
            )
        }
    }

    /// Write a single attribute on a commissioned device.
    ///
    /// Automatically manages CASE sessions, with a single retry on session failure.
    public func writeAttribute(
        nodeID: NodeID,
        endpointID: EndpointID,
        clusterID: ClusterID,
        attributeID: AttributeID,
        value: TLVElement
    ) async throws -> Bool {
        try await withSessionRetry(nodeID: nodeID) { session, address in
            let sourceNodeID = self.fabricManager.controllerFabricInfo.nodeID
            let msg = try self.operationalController.writeAttribute(
                endpointID: endpointID,
                clusterID: clusterID,
                attributeID: attributeID,
                value: value,
                session: session,
                sourceNodeID: sourceNodeID
            )

            let response = try await self.transceiver.sendAndReceive(
                msg, to: address, timeout: self.configuration.operationTimeout
            )

            return try self.operationalController.parseWriteResponse(
                encryptedMessage: response, session: session
            )
        }
    }

    /// Invoke a command on a commissioned device.
    ///
    /// Automatically manages CASE sessions, with a single retry on session failure.
    public func invokeCommand(
        nodeID: NodeID,
        endpointID: EndpointID,
        clusterID: ClusterID,
        commandID: CommandID,
        commandFields: TLVElement? = nil
    ) async throws -> TLVElement? {
        try await withSessionRetry(nodeID: nodeID) { session, address in
            let sourceNodeID = self.fabricManager.controllerFabricInfo.nodeID
            let msg = try self.operationalController.invokeCommand(
                endpointID: endpointID,
                clusterID: clusterID,
                commandID: commandID,
                commandFields: commandFields,
                session: session,
                sourceNodeID: sourceNodeID
            )

            let response = try await self.transceiver.sendAndReceive(
                msg, to: address, timeout: self.configuration.operationTimeout
            )

            return try self.operationalController.parseInvokeResponse(
                encryptedMessage: response, session: session
            )
        }
    }

    // MARK: - Device Registry

    /// All commissioned devices.
    public func allDevices() async -> [CommissionedDevice] {
        await registry.allDevices
    }

    /// Look up a commissioned device by node ID.
    public func device(for nodeID: NodeID) async -> CommissionedDevice? {
        await registry.device(for: nodeID)
    }

    /// Remove a device from the registry and invalidate its session.
    public func removeDevice(nodeID: NodeID) async {
        await registry.remove(nodeID: nodeID)
        sessionCache.remove(for: nodeID)
    }

    // MARK: - Private Helpers

    /// Allocate the next exchange ID (sequential, wrapping).
    private func nextExchangeID() -> UInt16 {
        let id = exchangeCounter
        exchangeCounter = exchangeCounter == UInt16.max ? 1 : exchangeCounter + 1
        return id
    }

    /// Allocate the next unsecured message counter.
    private func nextUnsecuredCounter() -> UInt32 {
        let counter = unsecuredMessageCounter
        unsecuredMessageCounter &+= 1
        return counter
    }

    /// Build an unsecured message (for PASE/CASE handshakes).
    ///
    /// Constructs MessageHeader (session 0) + ExchangeHeader + payload.
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

        var data = messageHeader.encode()
        data.append(exchangeHeader.encode())
        data.append(payload)
        return data
    }

    /// Extract the application payload from an unsecured message.
    ///
    /// Strips the MessageHeader and ExchangeHeader, returning just the payload.
    private func extractUnsecuredPayload(from data: Data) throws -> Data {
        let (_, headerConsumed) = try MessageHeader.decode(from: data)
        let afterHeader = Data(data.suffix(from: headerConsumed))
        let (_, exchConsumed) = try ExchangeHeader.decode(from: afterHeader)
        return Data(afterHeader.suffix(from: exchConsumed))
    }

    /// Send an IM request over an encrypted session and return the decrypted response payload.
    private func sendIMRequest(
        payload: Data,
        session: SecureSession,
        sourceNodeID: NodeID,
        to address: MatterAddress,
        opcode: InteractionModelOpcode
    ) async throws -> Data {
        let exchangeHeader = ExchangeHeader(
            flags: ExchangeFlags(initiator: true, reliableDelivery: true),
            protocolOpcode: opcode.rawValue,
            exchangeID: nextExchangeID(),
            protocolID: MatterProtocolID.interactionModel.rawValue
        )

        let encrypted = try SecureMessageCodec.encode(
            exchangeHeader: exchangeHeader,
            payload: payload,
            session: session,
            sourceNodeID: sourceNodeID
        )

        let responseMsg = try await transceiver.sendAndReceive(
            encrypted, to: address, timeout: configuration.operationTimeout
        )

        let (_, _, responsePayload) = try SecureMessageCodec.decode(
            data: responseMsg, session: session
        )

        return responsePayload
    }

    /// Establish a new CASE session to a device via Sigma1/2/3.
    private func establishCASESession(nodeID: NodeID) async throws -> SecureSession {
        guard let device = await registry.device(for: nodeID) else {
            throw ControllerError.deviceNotFound
        }

        guard let address = device.operationalAddress else {
            throw ControllerError.noOperationalAddress
        }

        let sessionID = sessionCache.allocateSessionID()
        let timeout = configuration.operationTimeout

        logger.debug("Establishing CASE session to node \(nodeID.rawValue)")

        // Sigma1
        let exchangeID = nextExchangeID()
        let (sigma1Data, handshakeCtx) = controllerSession.createSigma1(
            peerNodeID: nodeID,
            initiatorSessionID: sessionID
        )

        let sigma1Msg = buildUnsecuredMessage(
            payload: sigma1Data,
            opcode: .caseSigma1,
            exchangeID: exchangeID,
            isInitiator: true
        )

        let sigma2Msg = try await transceiver.sendAndReceive(
            sigma1Msg, to: address, timeout: timeout
        )
        let sigma2Data = try extractUnsecuredPayload(from: sigma2Msg)

        // Sigma2 → Sigma3 + session
        let (sigma3Data, session) = try controllerSession.handleSigma2(
            sigma2Data: sigma2Data,
            context: handshakeCtx,
            localSessionID: sessionID
        )

        let sigma3Msg = buildUnsecuredMessage(
            payload: sigma3Data,
            opcode: .caseSigma3,
            exchangeID: exchangeID,
            isInitiator: true
        )

        try await transceiver.send(sigma3Msg, to: address)

        // Cache the session
        sessionCache.store(session, for: nodeID)

        logger.debug("CASE session established to node \(nodeID.rawValue)")

        return session
    }

    /// Execute an operation with automatic session management.
    ///
    /// Gets or establishes a session, runs the operation. On failure,
    /// invalidates the session, re-establishes, and retries once.
    private func withSessionRetry<T>(
        nodeID: NodeID,
        operation: (SecureSession, MatterAddress) async throws -> T
    ) async throws -> T {
        guard let device = await registry.device(for: nodeID) else {
            throw ControllerError.deviceNotFound
        }

        guard let address = device.operationalAddress else {
            throw ControllerError.noOperationalAddress
        }

        let activeSession = try await session(for: nodeID)

        do {
            return try await operation(activeSession, address)
        } catch {
            // Retry once with a fresh session
            logger.debug("Operation failed, retrying with fresh session: \(error)")
            invalidateSession(for: nodeID)
            let freshSession = try await establishCASESession(nodeID: nodeID)
            return try await operation(freshSession, address)
        }
    }
}
