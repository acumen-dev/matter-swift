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
/// (`CommissioningController`, `ControllerSession`) with a
/// ``ControllerMessenger`` over the injected transport, and the injected
/// discovery, to provide a practical async/await API.
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

        /// MRP behaviour of the message layer (default: spec values, 4
        /// retransmissions). `mrp.peer` applies to devices with no recorded
        /// parameters of their own.
        public var mrp: MRPConfig

        public init(
            fabricID: FabricID,
            controllerNodeID: NodeID = NodeID(rawValue: 1),
            vendorID: VendorID = .test,
            rootKey: P256.Signing.PrivateKey = P256.Signing.PrivateKey(),
            operationTimeout: Duration = .seconds(30),
            commissioningTimeout: Duration = .seconds(120),
            mrp: MRPConfig = .default
        ) {
            self.fabricID = fabricID
            self.controllerNodeID = controllerNodeID
            self.vendorID = vendorID
            self.rootKey = rootKey
            self.operationTimeout = operationTimeout
            self.commissioningTimeout = commissioningTimeout
            self.mrp = mrp
        }
    }

    // MARK: - Properties

    private let fabricManager: FabricManager
    private let commissioning: CommissioningController
    private let controllerSession: ControllerSession
    private let registry: DeviceRegistry
    private let subscriptionClient: SubscriptionClient
    private let discovery: any MatterDiscovery
    private let configuration: Configuration
    private let logger: Logger
    private let store: (any MatterControllerStore)?

    /// The message layer: the transport's single reader, exchanges and MRP.
    /// Exposed for the Interaction Model client (subscription reports are
    /// routed through it).
    public let messenger: ControllerMessenger

    private var sessionCache = SessionCache()

    /// CASE establishments in flight, one per node: concurrent callers of
    /// ``session(for:)`` await the same handshake.
    private var establishing: [NodeID: Task<SecureSession, any Error>] = [:]

    // MARK: - Init

    /// Create a controller with injected transport and discovery.
    ///
    /// - Parameters:
    ///   - transport: UDP transport for message exchange.
    ///   - discovery: mDNS/DNS-SD discovery service.
    ///   - configuration: Controller configuration.
    ///   - store: Optional controller store for persistence across restarts.
    ///   - logger: Logger instance (default: "matter.controller").
    public init(
        transport: any MatterUDPTransport,
        discovery: any MatterDiscovery,
        configuration: Configuration,
        store: (any MatterControllerStore)? = nil,
        logger: Logger = Logger(label: "matter.controller")
    ) throws {
        let fabricManager = try FabricManager(
            rootKey: configuration.rootKey,
            fabricID: configuration.fabricID,
            controllerNodeID: configuration.controllerNodeID,
            vendorID: configuration.vendorID
        )
        self.fabricManager = fabricManager
        self.commissioning = CommissioningController(fabricManager: fabricManager)
        self.controllerSession = ControllerSession(fabricManager: fabricManager)
        self.registry = DeviceRegistry()
        self.subscriptionClient = SubscriptionClient()
        self.messenger = Self.makeMessenger(
            transport: transport,
            localNodeID: fabricManager.controllerFabricInfo.nodeID,
            configuration: configuration
        )
        self.discovery = discovery
        self.configuration = configuration
        self.store = store
        self.logger = logger
    }

    /// Restore a controller from persisted state.
    ///
    /// Reconstructs the `FabricManager` and `DeviceRegistry` from stored state
    /// rather than creating fresh certificates and an empty registry.
    ///
    /// Use the static `loadOrCreate()` factory for the common pattern of
    /// loading from a store if state exists, or creating fresh otherwise.
    ///
    /// - Parameters:
    ///   - transport: UDP transport for message exchange.
    ///   - discovery: mDNS/DNS-SD discovery service.
    ///   - configuration: Controller configuration (timeouts and MRP).
    ///   - stored: Previously persisted controller state.
    ///   - store: Controller store for ongoing persistence.
    ///   - logger: Logger instance (default: "matter.controller").
    public init(
        transport: any MatterUDPTransport,
        discovery: any MatterDiscovery,
        configuration: Configuration,
        stored: StoredControllerState,
        store: (any MatterControllerStore)? = nil,
        logger: Logger = Logger(label: "matter.controller")
    ) throws {
        let fabricManager = try FabricManager(
            stored: stored.identity,
            nextNodeID: stored.nextNodeID
        )
        self.fabricManager = fabricManager
        self.commissioning = CommissioningController(fabricManager: fabricManager)
        self.controllerSession = ControllerSession(fabricManager: fabricManager)
        self.registry = DeviceRegistry(storedDevices: stored.devices)
        self.subscriptionClient = SubscriptionClient()
        self.messenger = Self.makeMessenger(
            transport: transport,
            localNodeID: fabricManager.controllerFabricInfo.nodeID,
            configuration: configuration
        )
        self.discovery = discovery
        self.configuration = configuration
        self.store = store
        self.logger = logger

        logger.info("Restored controller from persisted state: \(stored.devices.count) device(s)")
    }

    /// Load a controller from persisted state or create a fresh one.
    ///
    /// Tries to load from the store. If stored state exists, reconstructs the
    /// controller from it. Otherwise creates a fresh controller with new certificates.
    ///
    /// ```swift
    /// let controller = try await MatterController.loadOrCreate(
    ///     transport: udp,
    ///     discovery: mdns,
    ///     configuration: config,
    ///     store: JSONFileControllerStore(directory: configDir)
    /// )
    /// ```
    public static func loadOrCreate(
        transport: any MatterUDPTransport,
        discovery: any MatterDiscovery,
        configuration: Configuration,
        store: any MatterControllerStore,
        logger: Logger = Logger(label: "matter.controller")
    ) async throws -> MatterController {
        if let stored = try await store.load() {
            return try MatterController(
                transport: transport,
                discovery: discovery,
                configuration: configuration,
                stored: stored,
                store: store,
                logger: logger
            )
        } else {
            return try MatterController(
                transport: transport,
                discovery: discovery,
                configuration: configuration,
                store: store,
                logger: logger
            )
        }
    }

    // MARK: - Discovery

    /// Browse for commissionable devices on the local network.
    public func discoverCommissionable() -> AsyncStream<MatterServiceRecord> {
        discovery.browse(type: .commissionable)
    }

    /// Browse for operational devices on the local network.
    ///
    /// Returns all operational `_matter._tcp` advertisements, regardless of fabric.
    /// Use `OperationalInstanceName.parse()` to extract fabric and node IDs from
    /// the service record name.
    public func discoverOperational() -> AsyncStream<MatterServiceRecord> {
        discovery.browse(type: .operational)
    }

    /// Discover a specific operational device by node ID on this controller's fabric.
    ///
    /// Constructs the expected operational instance name from the controller's
    /// compressed fabric ID and the target node ID, then resolves it via mDNS.
    ///
    /// - Parameter nodeID: The target device's operational node ID.
    /// - Returns: The resolved network address of the device.
    public func discoverDevice(nodeID: NodeID) async throws -> MatterAddress {
        let cfid = fabricManager.compressedFabricID()
        let opName = OperationalInstanceName(
            compressedFabricID: cfid,
            nodeID: nodeID.rawValue
        )

        let record = MatterServiceRecord(
            name: opName.instanceName,
            serviceType: .operational,
            host: "",
            port: 0
        )

        return try await discovery.resolve(record)
    }

    /// Resolve a discovered service record to a network address.
    public func resolve(_ record: MatterServiceRecord) async throws -> MatterAddress {
        try await discovery.resolve(record)
    }

    // MARK: - Commissioning

    /// Commission a device at the given address using the setup passcode.
    ///
    /// Drives the full commissioning flow:
    /// 1. PASE session establishment (PBKDFParamRequest → Pake3) on one unsecured exchange
    /// 2. ArmFailSafe
    /// 3. SetRegulatoryConfig
    /// 4. CSRRequest → generate NOC
    /// 5. AddTrustedRootCert + AddNOC
    /// 6. ACL write
    /// 7. CommissioningComplete
    ///
    /// Steps 2-7 run over the PASE session, registered with the message layer
    /// for their duration and unregistered on every exit path.
    ///
    /// - Parameters:
    ///   - address: The device's network address.
    ///   - setupCode: The device's setup passcode (e.g., 20202021).
    ///   - mrp: The device's advertised MRP parameters (SII/SAI/SAT from its
    ///     commissionable TXT record), if known. Recorded with the device and
    ///     used for its CASE sessions.
    /// - Returns: The commissioned device record.
    public func commission(
        address: MatterAddress,
        setupCode: UInt32,
        mrp: MRPParameters? = nil
    ) async throws -> CommissionedDevice {
        let timeout = configuration.operationTimeout

        logger.info("Beginning commissioning to \(address.host):\(address.port)")

        // Step 1: PASE on one unsecured exchange. The local session ID stays
        // reserved until commissioning ends (the PASE session is unregistered
        // by then on every path).
        guard let sessionID = await reserveSessionID() else {
            throw ControllerError.paseHandshakeFailed("No free local session ID")
        }
        defer { sessionCache.releaseSessionID(sessionID) }
        let (pbkdfReq, ctx1) = commissioning.beginPASE(
            passcode: setupCode,
            initiatorSessionID: sessionID
        )

        let handshake = await messenger.openExchange(peer: address, mrp: mrp)
        let paseContext: CommissioningController.CommissioningContext
        do {
            let pbkdfResp = try await handshake.request(
                protocolID: .secureChannel,
                opcode: SecureChannelOpcode.pbkdfParamRequest.rawValue,
                payload: pbkdfReq,
                timeout: timeout
            )
            try Self.expect(pbkdfResp, .pbkdfParamResponse, failure: ControllerError.paseHandshakeFailed)
            let (pake1, ctx2) = try commissioning.handlePBKDFParamResponse(
                response: pbkdfResp.payload, context: ctx1
            )

            let pake2 = try await handshake.request(
                protocolID: .secureChannel,
                opcode: SecureChannelOpcode.pasePake1.rawValue,
                payload: pake1,
                timeout: timeout
            )
            try Self.expect(pake2, .pasePake2, failure: ControllerError.paseHandshakeFailed)
            let (pake3, ctx3) = try commissioning.handlePake2(
                response: pake2.payload, context: ctx2
            )

            let status = try await handshake.request(
                protocolID: .secureChannel,
                opcode: SecureChannelOpcode.pasePake3.rawValue,
                payload: pake3,
                timeout: timeout
            )
            try Self.expect(status, .statusReport, failure: ControllerError.paseHandshakeFailed)
            let statusReport = try StatusReportMessage.decode(from: status.payload)
            guard statusReport.generalStatus == .success else {
                throw ControllerError.paseHandshakeFailed(
                    "PASE StatusReport: \(statusReport.generalStatus)"
                )
            }
            paseContext = ctx3
        } catch {
            await handshake.close()
            throw Self.commissioningError(error)
        }
        await handshake.close()

        guard let paseSession = paseContext.paseSession else {
            throw ControllerError.paseHandshakeFailed("No PASE session after Pake3")
        }

        logger.info("PASE session established (localSession=\(paseSession.localSessionID))")

        // Steps 2-7 over the encrypted PASE session. Register it before the
        // first encrypted request so the reply can be decrypted and routed.
        do {
            try await messenger.registerSession(paseSession, peerAddress: address, mrp: mrp)
        } catch {
            throw Self.commissioningError(error)
        }
        var device: CommissionedDevice
        do {
            device = try await commissionOverPASE(session: paseSession, context: paseContext)
        } catch {
            await messenger.unregisterSession(localSessionID: paseSession.localSessionID)
            throw Self.commissioningError(error)
        }
        await messenger.unregisterSession(localSessionID: paseSession.localSessionID)

        // Store the operational address and the device's MRP parameters
        device.setOperationalAddress(address)
        device.mrpParameters = mrp

        // Register in device registry
        await registry.register(device)

        // Persist controller state
        await saveState()

        logger.info("Commissioning complete: nodeID=\(device.nodeID.rawValue)")

        return device
    }

    /// Commissioning steps 2-7 over the established PASE session.
    private func commissionOverPASE(
        session: SecureSession,
        context ctx3: CommissioningController.CommissioningContext
    ) async throws -> CommissionedDevice {
        let paseSessionID = session.localSessionID

        // Step 2: ArmFailSafe
        let (armMsg, ctx4) = try commissioning.buildArmFailSafe(context: ctx3)
        let armResp = try await imRequest(sessionID: paseSessionID, opcode: .invokeRequest, payload: armMsg)
        let ctx5 = try commissioning.handleArmFailSafeResponse(
            response: armResp.payload, context: ctx4
        )

        // Step 3: SetRegulatoryConfig
        let regMsg = commissioning.buildSetRegulatoryConfig(context: ctx5)
        let regResp = try await imRequest(sessionID: paseSessionID, opcode: .invokeRequest, payload: regMsg)
        try commissioning.handleSetRegulatoryConfigResponse(response: regResp.payload)

        // Step 4: CSRRequest
        let csrMsg = commissioning.buildCSRRequest()
        let csrResp = try await imRequest(sessionID: paseSessionID, opcode: .invokeRequest, payload: csrMsg)
        let (addRootMsg, addNOCMsg, deviceNodeID, ctx6) = try await commissioning.handleCSRResponse(
            response: csrResp.payload, context: ctx5
        )
        logger.debug("Device will be node \(deviceNodeID.rawValue)")

        // Step 5: AddTrustedRootCert — its status is checked by the commissioning plan
        _ = try await imRequest(sessionID: paseSessionID, opcode: .invokeRequest, payload: addRootMsg)

        // Step 5b: AddNOC
        let addNOCResp = try await imRequest(sessionID: paseSessionID, opcode: .invokeRequest, payload: addNOCMsg)
        let (aclMsg, ctx7) = try commissioning.handleNOCResponse(
            response: addNOCResp.payload, context: ctx6
        )

        // Step 6: ACL write — its status is checked by the commissioning plan
        _ = try await imRequest(sessionID: paseSessionID, opcode: .writeRequest, payload: aclMsg)

        // Step 7: CommissioningComplete
        let completeMsg = commissioning.buildCommissioningComplete()
        let completeResp = try await imRequest(sessionID: paseSessionID, opcode: .invokeRequest, payload: completeMsg)
        return try commissioning.handleCommissioningComplete(
            response: completeResp.payload, context: ctx7
        )
    }


    // MARK: - Session Management

    /// Get or establish a CASE session to a commissioned device.
    ///
    /// Returns the cached session if there is one; otherwise establishes a
    /// new CASE session via Sigma1/2/3. Concurrent callers for the same node
    /// share one handshake. A cached session stays until it is invalidated
    /// (the device stopped acknowledging, or ``invalidateSession(for:)``).
    public func session(for nodeID: NodeID) async throws -> SecureSession {
        if let cached = sessionCache.session(for: nodeID) {
            return cached
        }
        if let inFlight = establishing[nodeID] {
            return try await inFlight.value
        }
        // Isolated to this actor: it cannot start before the entry is stored.
        let task = Task {
            defer { self.establishing[nodeID] = nil }
            return try await self.establishCASESession(nodeID: nodeID)
        }
        establishing[nodeID] = task
        return try await task.value
    }

    /// Invalidate the cached session for a node (e.g., after a communication
    /// error) and unregister it from the message layer.
    public func invalidateSession(for nodeID: NodeID) async {
        guard let session = sessionCache.session(for: nodeID) else { return }
        // Out of the cache before suspending, so a session established
        // meanwhile is never the one removed.
        sessionCache.remove(for: nodeID)
        await messenger.unregisterSession(localSessionID: session.localSessionID)
    }

    /// Set (or clear) a device's advertised MRP parameters (SII/SAI/SAT).
    /// Persisted with the device and applied to new exchanges at once,
    /// including on its cached session.
    public func setMRPParameters(_ parameters: MRPParameters?, for nodeID: NodeID) async {
        await registry.updateMRPParameters(for: nodeID, parameters: parameters)
        await saveState()
        // A CASE handshake in flight may have read the old parameters; let it
        // finish, then update the session it produced.
        if let inFlight = establishing[nodeID] {
            _ = try? await inFlight.value
        }
        if let session = sessionCache.session(for: nodeID) {
            // The registry's current value, not this call's argument, re-read
            // until stable: a concurrent call may interleave between the read
            // and the update, and the last registry write must win. Never
            // re-registers: a session unregistered meanwhile stays gone.
            var applied = await registry.device(for: nodeID)?.mrpParameters
            while true {
                await messenger.updateSession(localSessionID: session.localSessionID, mrp: applied)
                let latest = await registry.device(for: nodeID)?.mrpParameters
                if latest == applied { break }
                applied = latest
            }
        }
    }

    /// Stop the message layer: pending requests fail with
    /// `MessagingError.stopped`. Terminal for this controller instance.
    public func stop() async {
        await messenger.stop()
    }

    // MARK: - Operational API

    /// Read a single attribute from a commissioned device.
    ///
    /// Gets or establishes a CASE session and sends the request once. MRP
    /// retransmits it; a device that never acknowledges surfaces as
    /// `ControllerError.peerUnreachable` — the request is not re-issued.
    public func readAttribute(
        nodeID: NodeID,
        endpointID: EndpointID,
        clusterID: ClusterID,
        attributeID: AttributeID
    ) async throws -> TLVElement {
        try await withSession(nodeID: nodeID) { session in
            let response = try await self.imRequest(
                sessionID: session.localSessionID,
                opcode: .readRequest,
                payload: IMClient.readAttributeRequest(
                    endpointID: endpointID,
                    clusterID: clusterID,
                    attributeID: attributeID
                )
            )
            return try IMClient.parseReadResponse(response.payload)
        }
    }

    /// Write a single attribute on a commissioned device.
    ///
    /// Sent once on the node's CASE session (see ``readAttribute(nodeID:endpointID:clusterID:attributeID:)``).
    public func writeAttribute(
        nodeID: NodeID,
        endpointID: EndpointID,
        clusterID: ClusterID,
        attributeID: AttributeID,
        value: TLVElement
    ) async throws -> Bool {
        try await withSession(nodeID: nodeID) { session in
            let response = try await self.imRequest(
                sessionID: session.localSessionID,
                opcode: .writeRequest,
                payload: IMClient.writeAttributeRequest(
                    endpointID: endpointID,
                    clusterID: clusterID,
                    attributeID: attributeID,
                    value: value
                )
            )
            return try IMClient.parseWriteResponse(response.payload)
        }
    }

    /// Invoke a command on a commissioned device.
    ///
    /// Sent once on the node's CASE session. An invoke is never re-issued:
    /// if the device stops acknowledging, the call fails with
    /// `ControllerError.peerUnreachable` and the command may or may not have
    /// executed — exactly once at most, never twice.
    public func invokeCommand(
        nodeID: NodeID,
        endpointID: EndpointID,
        clusterID: ClusterID,
        commandID: CommandID,
        commandFields: TLVElement? = nil
    ) async throws -> TLVElement? {
        try await withSession(nodeID: nodeID) { session in
            let response = try await self.imRequest(
                sessionID: session.localSessionID,
                opcode: .invokeRequest,
                payload: IMClient.invokeCommandRequest(
                    endpointID: endpointID,
                    clusterID: clusterID,
                    commandID: commandID,
                    commandFields: commandFields
                )
            )
            return try IMClient.parseInvokeResponse(response.payload)
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
        await invalidateSession(for: nodeID)
        await saveState()
    }

    // MARK: - Persistence

    /// Save the current controller state (identity + devices + next node ID).
    ///
    /// No-op if no store was configured.
    private func saveState() async {
        guard let store else { return }
        let state = StoredControllerState(
            identity: fabricManager.toStoredIdentity(),
            devices: await registry.toStoredDevices(),
            nextNodeID: await fabricManager.nextNodeID
        )
        do {
            try await store.save(state)
        } catch {
            logger.warning("Failed to persist controller state: \(error)")
        }
    }

    // MARK: - Private Helpers

    private static func makeMessenger(
        transport: any MatterUDPTransport,
        localNodeID: NodeID,
        configuration: Configuration
    ) -> ControllerMessenger {
        var messaging = ControllerMessenger.Configuration()
        messaging.mrp = configuration.mrp
        return ControllerMessenger(transport: transport, localNodeID: localNodeID, configuration: messaging)
    }

    /// Send one Interaction Model request on a fresh exchange of `sessionID`
    /// and return the reply. The exchange is closed (owed ack flushed) on
    /// every path.
    func imRequest(
        sessionID: UInt16,
        opcode: InteractionModelOpcode,
        payload: Data
    ) async throws -> InboundMessage {
        let exchange = try await messenger.openExchange(sessionID: sessionID)
        do {
            let response = try await exchange.request(
                protocolID: .interactionModel,
                opcode: opcode.rawValue,
                payload: payload,
                timeout: configuration.operationTimeout
            )
            await exchange.close()
            guard response.protocolID == MatterProtocolID.interactionModel.rawValue else {
                throw MessagingError.unexpectedProtocol(protocolID: response.protocolID, opcode: response.opcode)
            }
            // A StatusResponse in place of the reply is the device refusing
            // the request (UnsupportedAccess, Busy, NeedsTimedInteraction, ...).
            if response.opcode == InteractionModelOpcode.statusResponse.rawValue {
                let status = try IMStatusResponse.fromTLV(response.payload)
                throw ControllerError.imStatus(status.status)
            }
            return response
        } catch {
            await exchange.close()
            throw error
        }
    }

    /// Establish a new CASE session to a device via Sigma1/2/3 on one
    /// unsecured exchange, and register it before caching it.
    private func establishCASESession(nodeID: NodeID) async throws -> SecureSession {
        guard let device = await registry.device(for: nodeID) else {
            throw ControllerError.deviceNotFound
        }

        guard let address = device.operationalAddress else {
            throw ControllerError.noOperationalAddress
        }

        // Reserved until this establishment ends; once cached, the session
        // itself keeps the ID in use.
        guard let sessionID = await reserveSessionID() else {
            throw ControllerError.caseSessionFailed("No free local session ID")
        }
        defer { sessionCache.releaseSessionID(sessionID) }
        let timeout = configuration.operationTimeout

        logger.debug("Establishing CASE session to node \(nodeID.rawValue)")

        let (sigma1Data, handshakeCtx) = controllerSession.createSigma1(
            peerNodeID: nodeID,
            initiatorSessionID: sessionID
        )

        let handshake = await messenger.openExchange(peer: address, mrp: device.mrpParameters)
        let session: SecureSession
        do {
            let sigma2 = try await handshake.request(
                protocolID: .secureChannel,
                opcode: SecureChannelOpcode.caseSigma1.rawValue,
                payload: sigma1Data,
                timeout: timeout
            )
            try Self.expect(sigma2, .caseSigma2, failure: ControllerError.caseSessionFailed)

            // Sigma2 → Sigma3 + session
            let (sigma3Data, established) = try controllerSession.handleSigma2(
                sigma2Data: sigma2.payload,
                context: handshakeCtx,
                localSessionID: sessionID
            )

            // Wait for StatusReport confirming CASE session
            let status = try await handshake.request(
                protocolID: .secureChannel,
                opcode: SecureChannelOpcode.caseSigma3.rawValue,
                payload: sigma3Data,
                timeout: timeout
            )
            try Self.expect(status, .statusReport, failure: ControllerError.caseSessionFailed)
            let statusReport = try StatusReportMessage.decode(from: status.payload)
            guard statusReport.generalStatus == .success else {
                throw ControllerError.caseSessionFailed(
                    "CASE StatusReport: \(statusReport.generalStatus)"
                )
            }
            session = established
        } catch {
            await handshake.close()
            throw Self.operationalError(error, nodeID: nodeID)
        }
        await handshake.close()

        // Register before caching so the first request's reply is routable.
        // Parameters re-read now: setMRPParameters may have run during the
        // handshake (it then waits for this establishment to finish).
        // A device removed during the handshake gets no session.
        guard let current = await registry.device(for: nodeID) else {
            throw ControllerError.deviceNotFound
        }
        do {
            try await messenger.registerSession(session, peerAddress: address, mrp: current.mrpParameters)
        } catch {
            throw Self.operationalError(error, nodeID: nodeID)
        }
        sessionCache.store(session, for: nodeID)

        logger.debug("CASE session established to node \(nodeID.rawValue)")

        return session
    }

    /// Reserve a local session ID that no registered, cached or in-flight
    /// session holds (see ``SessionCache/reserveSessionID(excluding:)``).
    /// The only suspension is the snapshot, before the synchronous reserve.
    private func reserveSessionID() async -> UInt16? {
        let registered = await messenger.registeredSessionIDs
        return sessionCache.reserveSessionID(excluding: registered)
    }

    /// Run `operation` **once** on the node's CASE session (established if
    /// needed).
    ///
    /// A transmitted request is only ever retransmitted by MRP under its
    /// original counter; it is never re-encoded on a new exchange or session.
    /// If the peer stops acknowledging, or the session closes or is no longer
    /// registered with the message layer, the session is invalidated and the
    /// error surfaces as `ControllerError.peerUnreachable`; the next call
    /// establishes a fresh session.
    private func withSession<T: Sendable>(
        nodeID: NodeID,
        operation: (SecureSession) async throws -> T
    ) async throws -> T {
        guard let device = await registry.device(for: nodeID) else {
            throw ControllerError.deviceNotFound
        }

        guard device.operationalAddress != nil else {
            throw ControllerError.noOperationalAddress
        }

        let activeSession = try await session(for: nodeID)
        // The wait may have been on a handshake shared with other callers; a
        // caller cancelled meanwhile must not send its request late.
        try Task.checkCancellation()

        do {
            return try await operation(activeSession)
        } catch {
            let mapped = Self.operationalError(error, nodeID: nodeID)
            if let controllerError = mapped as? ControllerError, controllerError == .peerUnreachable(nodeID) {
                logger.info("Node \(nodeID.rawValue) unreachable; invalidating its session (the request is not re-sent)")
                // Only the session this operation used: a concurrent failure
                // must not invalidate a session established since.
                if sessionCache.session(for: nodeID) === activeSession {
                    await invalidateSession(for: nodeID)
                }
            }
            throw mapped
        }
    }

    /// Check a handshake reply's protocol and opcode. A StatusReport in its
    /// place is the peer refusing the step.
    private static func expect(
        _ message: InboundMessage,
        _ opcode: SecureChannelOpcode,
        failure: (String) -> ControllerError
    ) throws {
        guard message.protocolID == MatterProtocolID.secureChannel.rawValue else {
            throw MessagingError.unexpectedProtocol(protocolID: message.protocolID, opcode: message.opcode)
        }
        if message.opcode == opcode.rawValue {
            return
        }
        if message.opcode == SecureChannelOpcode.statusReport.rawValue,
           let report = try? StatusReportMessage.decode(from: message.payload) {
            throw failure("StatusReport \(report.generalStatus) instead of \(opcode)")
        }
        throw ControllerError.unexpectedResponse("Expected \(opcode), got opcode \(message.opcode)")
    }

    /// Messaging failures during commissioning become `commissioningFailed`;
    /// anything else passes through.
    private static func commissioningError(_ error: any Error) -> any Error {
        guard let messaging = error as? MessagingError else { return error }
        return ControllerError.commissioningFailed("Messaging failure: \(messaging)")
    }

    /// Messaging failures on an operational exchange, as `ControllerError`.
    private static func operationalError(_ error: any Error, nodeID: NodeID) -> any Error {
        guard let messaging = error as? MessagingError else { return error }
        switch messaging {
        case .peerUnreachable, .sessionClosed, .unknownSession:
            // The session is gone from the message layer (unacknowledged,
            // closed, or unregistered): invalidate it, as for a silent peer.
            return ControllerError.peerUnreachable(nodeID)
        case .responseTimeout:
            return ControllerError.timeout("No response from node \(nodeID.rawValue)")
        case .unexpectedProtocol(let protocolID, let opcode):
            return ControllerError.unexpectedResponse("Protocol \(protocolID) opcode \(opcode) from node \(nodeID.rawValue)")
        case .exchangeClosed, .receiveAlreadyPending, .sendAlreadyPending, .stopped, .sessionIDInUse:
            return ControllerError.transportError("\(messaging)")
        }
    }
}
