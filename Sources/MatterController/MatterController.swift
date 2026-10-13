// MatterController.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import Logging
import Synchronization
import MatterTypes
import MatterModel
import MatterCrypto
import MatterProtocol
import MatterTransport

/// A point in commissioning at which a test can inject a failure.
enum CommissioningStep: Sendable {
    case afterArmFailSafe, afterCSR, afterAddNOC, afterACLWrite, afterCASE
}

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

        /// How long `findCommissionable` searches before giving up (default: 30s).
        public var discoveryTimeout: Duration

        /// How long a CASE attempt that got no answer waits to re-resolve the
        /// node's operational address before giving up with its original
        /// error (default: 5s). Kept short: an unadvertised name may never
        /// resolve, and every CASE attempt to a powered-off device (each
        /// subscription re-subscribe, for one) would otherwise pay it in full.
        public var addressRefreshTimeout: Duration

        public init(
            fabricID: FabricID,
            controllerNodeID: NodeID = NodeID(rawValue: 1),
            vendorID: VendorID = .test,
            rootKey: P256.Signing.PrivateKey = P256.Signing.PrivateKey(),
            operationTimeout: Duration = .seconds(30),
            commissioningTimeout: Duration = .seconds(120),
            mrp: MRPConfig = .default,
            discoveryTimeout: Duration = .seconds(30),
            addressRefreshTimeout: Duration = .seconds(5)
        ) {
            self.fabricID = fabricID
            self.controllerNodeID = controllerNodeID
            self.vendorID = vendorID
            self.rootKey = rootKey
            self.operationTimeout = operationTimeout
            self.commissioningTimeout = commissioningTimeout
            self.mrp = mrp
            self.discoveryTimeout = discoveryTimeout
            self.addressRefreshTimeout = addressRefreshTimeout
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

    /// Subscriptions created by ``subscribe(nodeID:_:)``. A subscription keeps
    /// itself alive until cancelled, so ``stop()`` cancels each one.
    private var subscriptions: [ControllerSubscription] = []
    private var stopped = false

    /// Test seam: called at each ``CommissioningStep`` point of
    /// ``commission(address:setupCode:mrp:)``; a thrown error fails
    /// commissioning there. Always nil in production.
    var commissioningFailureInjection: (@Sendable (CommissioningStep) throws -> Void)?

    /// The next node ID that would be allocated (for tests).
    var nextNodeID: UInt64 { get async { await fabricManager.nextNodeID } }

    /// Install (or clear) the commissioning failure-injection seam.
    func setCommissioningFailureInjection(_ injection: (@Sendable (CommissioningStep) throws -> Void)?) {
        commissioningFailureInjection = injection
    }

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

    /// Find the commissionable device a setup code refers to.
    ///
    /// Browses `_matterc._udp` and takes the **first** record whose TXT
    /// matches: `D` is a 12-bit value the code's discriminator matches, and
    /// `CM` is non-zero. Vendor and product are checked only when the code
    /// carries them, and, as chip-tool's `SetUpCodePairer` does, only
    /// against what the record advertises: a missing `VP`, or a `VP` without
    /// the `+pid` part, leaves that ID unknown and passes; only an
    /// advertised ID that differs (or does not parse) rejects. A record
    /// browsed without TXT is resolved and filtered on the resolved TXT. The
    /// match is resolved for its address and final TXT, from which `mrp` is
    /// built. A record whose resolve fails is logged (instance name only)
    /// and skipped.
    ///
    /// A short (manual-code) discriminator has 16 values, so two devices can
    /// both match; the first one wins. Callers must **not** try PASE against
    /// several candidates: a wrong passcode counts against the other device's
    /// commissioning window.
    ///
    /// The deadline cancels the search, including a resolve in flight.
    ///
    /// - Parameters:
    ///   - code: The parsed onboarding payload.
    ///   - timeout: How long to search (default: `configuration.discoveryTimeout`).
    /// - Throws: `ControllerError.commissionableNotFound` when nothing matches
    ///   in time; `ControllerError.discoveryFailed` if the browse stream ends
    ///   before a match (nothing more can arrive); `CancellationError` if the
    ///   calling task is cancelled.
    public func findCommissionable(_ code: SetupCode, timeout: Duration? = nil) async throws -> CommissionableDevice {
        let limit = timeout ?? configuration.discoveryTimeout
        let discovery = self.discovery
        let logger = self.logger
        let notFound = ControllerError.commissionableNotFound(Self.describe(code.discriminator))

        return try await withThrowingTaskGroup(of: CommissionableDevice.self) { group in
            group.addTask {
                for await record in discovery.browse(type: .commissionable) {
                    // A cancelled stream still delivers what it buffered: stop here.
                    try Task.checkCancellation()
                    if let device = try await Self.commissionable(
                        record, matching: code, discovery: discovery, logger: logger
                    ) {
                        return device
                    }
                }
                // The stream ended: cancelled, or the browser finished.
                try Task.checkCancellation()
                throw ControllerError.discoveryFailed("browse ended before a match")
            }
            group.addTask {
                try await Task.sleep(for: limit)
                throw notFound
            }
            defer { group.cancelAll() }
            guard let first = try await group.next() else { throw notFound }
            return first
        }
    }

    /// Filter one browsed record against `code`, resolving it as needed.
    private static func commissionable(
        _ record: MatterServiceRecord,
        matching code: SetupCode,
        discovery: any MatterDiscovery,
        logger: Logger
    ) async throws -> CommissionableDevice? {
        var resolved: ResolvedService?
        var txt = record.txtRecords
        if txt.isEmpty {
            guard let service = try await resolve(record, discovery: discovery, logger: logger) else { return nil }
            resolved = service
            txt = service.txtRecords
        }
        guard CommissionableDevice.Advertisement(txt: txt, matching: code) != nil else { return nil }

        if resolved == nil {
            guard let service = try await resolve(record, discovery: discovery, logger: logger) else { return nil }
            resolved = service
        }
        guard let resolved else { return nil }
        // Resolution may return no TXT (by contract); keep what was matched on.
        let finalTXT = resolved.txtRecords.isEmpty ? txt : resolved.txtRecords
        guard let advertisement = CommissionableDevice.Advertisement(txt: finalTXT, matching: code) else {
            return nil
        }
        return CommissionableDevice(
            instanceName: record.name,
            address: resolved.address,
            advertisement: advertisement,
            txtRecords: finalTXT
        )
    }

    /// Resolve `record`; nil (logged) when resolution fails. Cancellation propagates.
    private static func resolve(
        _ record: MatterServiceRecord,
        discovery: any MatterDiscovery,
        logger: Logger
    ) async throws -> ResolvedService? {
        do {
            return try await discovery.resolveService(record)
        } catch let cancellation as CancellationError {
            throw cancellation
        } catch {
            try Task.checkCancellation()
            logger.notice("Skipping commissionable instance \(record.name): resolve failed: \(error)")
            return nil
        }
    }

    /// Names the discriminator sought, for `commissionableNotFound`.
    private static func describe(_ discriminator: SetupCode.Discriminator) -> String {
        switch discriminator {
        case .long(let value): return "no commissionable device with discriminator \(value)"
        case .short(let value): return "no commissionable device with short discriminator \(value)"
        }
    }

    /// Browse for operational devices on the local network.
    ///
    /// Returns all operational `_matter._tcp` advertisements, regardless of fabric.
    /// Use `OperationalInstanceName.parse()` to extract fabric and node IDs from
    /// the service record name.
    public func discoverOperational() -> AsyncStream<MatterServiceRecord> {
        discovery.browse(type: .operational)
    }

    /// Resolves a commissioned node's current operational address and TXT via _matter._tcp.
    ///
    /// Resolves the node's operational instance name on this controller's
    /// fabric (compressed fabric ID and node ID). `mrp` is built from the
    /// resolved TXT; it is nil when the resolution returns no TXT (allowed by
    /// the discovery contract), so a caller can keep the timing it has
    /// rather than take the defaults.
    ///
    /// - Parameters:
    ///   - nodeID: The target device's operational node ID.
    ///   - timeout: How long to wait for the resolution (default:
    ///     `configuration.discoveryTimeout`).
    /// - Throws: `ControllerError.discoveryFailed` when nothing resolves in
    ///   time; the discovery's error if resolution fails; `CancellationError`
    ///   if the calling task is cancelled.
    public func discoverDevice(nodeID: NodeID, timeout: Duration? = nil) async throws -> (address: MatterAddress, mrp: MRPParameters?) {
        let resolved = try await resolveOperational(nodeID: nodeID, timeout: timeout)
        return (resolved.address, Self.mrpParameters(fromOperationalTXT: resolved.txtRecords))
    }

    /// MRP parameters from an operational TXT; nil when it is empty.
    private static func mrpParameters(fromOperationalTXT txt: [String: String]) -> MRPParameters? {
        txt.isEmpty ? nil : MRPParameters(txtRecords: txt)
    }

    /// Resolve `nodeID`'s operational instance, bounded by `timeout`
    /// (default: `configuration.discoveryTimeout`). The TXT is returned as
    /// resolved, so a caller can tell an empty one from one with defaults.
    private func resolveOperational(nodeID: NodeID, timeout: Duration? = nil) async throws -> ResolvedService {
        let limit = timeout ?? configuration.discoveryTimeout
        let name = OperationalInstanceName(
            compressedFabricID: fabricManager.compressedFabricID(),
            nodeID: nodeID.rawValue
        ).instanceName
        let record = MatterServiceRecord(name: name, serviceType: .operational, host: "", port: 0)
        let discovery = self.discovery
        let expired = ControllerError.discoveryFailed("node \(nodeID.rawValue) did not resolve within \(limit)")

        return try await withThrowingTaskGroup(of: ResolvedService.self) { group in
            group.addTask { try await discovery.resolveService(record) }
            group.addTask {
                try await Task.sleep(for: limit)
                throw expired
            }
            defer { group.cancelAll() }
            guard let first = try await group.next() else { throw expired }
            return first
        }
    }

    /// Record a node's new operational address and persist it. `mrp`
    /// replaces its MRP parameters; `nil` leaves them as they are. A cached
    /// session is untouched: it keeps the address it was registered with.
    /// Nothing is saved once the controller has stopped.
    func updateOperationalAddress(_ address: MatterAddress, mrp: MRPParameters?, for nodeID: NodeID) async {
        await registry.updateAddress(for: nodeID, address: address)
        if let mrp {
            await registry.updateMRPParameters(for: nodeID, parameters: mrp)
        }
        guard !stopped else { return }
        await saveState()
    }

    /// Resolve a discovered service record to a network address.
    public func resolve(_ record: MatterServiceRecord) async throws -> MatterAddress {
        try await discovery.resolve(record)
    }

    // MARK: - Commissioning

    /// Commission a device from its setup code (manual or QR): find it by
    /// discriminator, then commission it at the address it advertises.
    ///
    /// The device's advertised MRP timing (SII/SAI/SAT) is used for
    /// commissioning and persisted with the device, unless `mrp` overrides it.
    /// An override lasts until the node's address is refreshed: when a CASE
    /// attempt gets no answer and re-resolving finds the node at a new
    /// address, the timing from its operational TXT replaces the stored one
    /// (an empty operational TXT keeps it).
    /// The same rules as ``findCommissionable(_:timeout:)`` apply: a short
    /// discriminator may match more than one device, and the first wins.
    ///
    /// - Parameters:
    ///   - setupCode: The manual pairing code or `MT:` QR payload.
    ///   - discoveryTimeout: How long to search (default: `configuration.discoveryTimeout`).
    ///   - mrp: Overrides the advertised MRP parameters (until an address
    ///     refresh; see above).
    /// - Throws: `ControllerError.invalidSetupCode` (naming the problem, never
    ///   the code); the errors of `findCommissionable` and of
    ///   ``commission(address:setupCode:mrp:)``.
    public func commission(
        setupCode: String,
        discoveryTimeout: Duration? = nil,
        mrp: MRPParameters? = nil
    ) async throws -> CommissionedDevice {
        let code: SetupCode
        do {
            code = try SetupCode(parsing: setupCode)
        } catch {
            throw ControllerError.invalidSetupCode(Self.describe(error))
        }
        let found = try await findCommissionable(code, timeout: discoveryTimeout)
        return try await commission(address: found.address, setupCode: code.passcode, mrp: mrp ?? found.mrp)
    }

    /// The case name only: a payload (`malformedQRCode`) may carry the code text.
    private static func describe(_ error: SetupCodeError) -> String {
        switch error {
        case .empty: "empty setup code"
        case .invalidCharacters: "setup code has invalid characters"
        case .invalidLength: "setup code has an invalid length"
        case .checkDigitMismatch: "setup code check digit mismatch"
        case .unsupportedVersion: "unsupported setup code version"
        case .invalidPasscode: "setup code passcode is not allowed"
        case .malformedQRCode: "malformed QR setup code"
        }
    }

    /// Commission a device at the given address using the setup passcode.
    ///
    /// Drives the full commissioning flow:
    /// 1. PASE session establishment (PBKDFParamRequest → Pake3) on one unsecured exchange
    /// 2. ArmFailSafe
    /// 3. LocationCapability read → SetRegulatoryConfig with a location the device supports
    /// 4. CSRRequest → generate NOC
    /// 5. AddTrustedRootCert + AddNOC
    /// 6. ACL write
    /// 7. CASE session to the device on the new fabric
    /// 8. CommissioningComplete over that CASE session
    ///
    /// Steps 2-6 run over the PASE session, registered with the message layer
    /// for their duration and unregistered on every exit path. The CASE
    /// session is kept: on success it is cached as the node's operational
    /// session; on failure it is unregistered.
    ///
    /// A failure after ArmFailSafe disarms the fail-safe on the device (best
    /// effort). If the caller's task is cancelled, that disarm is sent once,
    /// but its retransmission stops when the PASE session is torn down, so on
    /// a lossy link the device may stay armed until its fail-safe expires.
    ///
    /// - Parameters:
    ///   - address: The device's network address.
    ///   - setupCode: The device's setup passcode (e.g., 20202021).
    ///   - mrp: The device's advertised MRP parameters (SII/SAI/SAT from its
    ///     commissionable TXT record), if known. Recorded with the device and
    ///     used for its CASE sessions until an address refresh finds the
    ///     node at a new address, when the timing from its operational TXT
    ///     replaces it (an empty operational TXT keeps it).
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

        // Steps 2-6 over the encrypted PASE session, then CASE and
        // CommissioningComplete. Register the PASE session before the first
        // encrypted request so the reply can be decrypted and routed.
        do {
            try await messenger.registerSession(paseSession, peerAddress: address, mrp: mrp)
        } catch {
            throw Self.commissioningError(error)
        }
        var device: CommissionedDevice
        let caseSession: SecureSession
        do {
            (device, caseSession) = try await commissionOverPASE(
                session: paseSession, context: paseContext, address: address, mrp: mrp
            )
        } catch {
            await messenger.unregisterSession(localSessionID: paseSession.localSessionID)
            throw Self.commissioningError(error)
        }
        await messenger.unregisterSession(localSessionID: paseSession.localSessionID)

        // Store the operational address and the device's MRP parameters
        device.setOperationalAddress(address)
        device.mrpParameters = mrp

        // The CASE session CommissioningComplete went over is the node's
        // operational session; then register the device. Its ID stayed
        // reserved until now; once cached, the session keeps it in use.
        sessionCache.store(caseSession, for: device.nodeID)
        sessionCache.releaseSessionID(caseSession.localSessionID)
        await registry.register(device)

        // Persist controller state
        await saveState()

        logger.info("Commissioning complete: nodeID=\(device.nodeID.rawValue)")

        return device
    }

    /// Commissioning steps 2-6 over the established PASE session, then
    /// CommissioningComplete over CASE on the new fabric.
    ///
    /// Once ArmFailSafe has been sent, the fail-safe counts as armed unless
    /// the device explicitly refused it (a lost response may still have armed
    /// it), and any later failure disarms it on the device (best effort, over
    /// the still-open PASE session), so the device reverts at once rather than
    /// after the fail-safe expires. The allocated node ID is released only if
    /// CommissioningComplete was never sent; once sent, the device may have
    /// committed with it, so it stays consumed (and is persisted). A CASE
    /// session already registered is torn down. The original error is rethrown.
    ///
    /// - Returns: the device and its registered (not yet cached) CASE session,
    ///   whose local session ID is still reserved: the caller releases it
    ///   once the session is cached. On failure the reservation is released
    ///   here, after the CASE session is unregistered.
    private func commissionOverPASE(
        session: SecureSession,
        context ctx3: CommissioningController.CommissioningContext,
        address: MatterAddress,
        mrp: MRPParameters?
    ) async throws -> (CommissionedDevice, SecureSession) {
        var failSafeArmed = false
        var allocatedNodeID: NodeID?
        var completeSent = false
        var caseReservation: UInt16?
        var caseSession: SecureSession?
        do {
            return try await runCommissioningSteps(
                session: session, context: ctx3, address: address, mrp: mrp,
                failSafeArmed: &failSafeArmed, allocatedNodeID: &allocatedNodeID,
                completeSent: &completeSent, caseReservation: &caseReservation,
                caseSession: &caseSession
            )
        } catch {
            // Once CommissioningComplete has gone out the device may have
            // committed with this node ID; reusing it would give two devices
            // one identity, so it stays consumed, and persisted so a restart
            // does not hand it out again.
            if let allocatedNodeID {
                if completeSent {
                    await saveState()
                } else {
                    await fabricManager.releaseNodeID(allocatedNodeID)
                }
            }
            if failSafeArmed {
                await disarmFailSafe(sessionID: session.localSessionID)
            }
            if let caseSession {
                await messenger.unregisterSession(localSessionID: caseSession.localSessionID)
            }
            if let caseReservation {
                sessionCache.releaseSessionID(caseReservation)
            }
            throw error
        }
    }

    /// Send ArmFailSafe(0) over the PASE session. Bounded by the per-exchange
    /// timeout; a failure here is logged and swallowed.
    private func disarmFailSafe(sessionID: UInt16) async {
        do {
            _ = try await imRequest(
                sessionID: sessionID, opcode: .invokeRequest, payload: commissioning.buildDisarmFailSafe()
            )
            logger.info("Commissioning failed; fail-safe disarmed on the device")
        } catch {
            logger.warning("Commissioning failed and the fail-safe could not be disarmed: \(error)")
        }
    }

    private func runCommissioningSteps(
        session: SecureSession,
        context ctx3: CommissioningController.CommissioningContext,
        address: MatterAddress,
        mrp: MRPParameters?,
        failSafeArmed: inout Bool,
        allocatedNodeID: inout NodeID?,
        completeSent: inout Bool,
        caseReservation: inout UInt16?,
        caseSession: inout SecureSession?
    ) async throws -> (CommissionedDevice, SecureSession) {
        let paseSessionID = session.localSessionID

        // Step 2: ArmFailSafe
        let (armMsg, ctx4) = try commissioning.buildArmFailSafe(context: ctx3)
        // Armed from the moment it is sent: a lost response may still have
        // armed the device. Only an explicit refusal clears it.
        failSafeArmed = true
        let ctx5: CommissioningController.CommissioningContext
        do {
            let armResp = try await imRequest(sessionID: paseSessionID, opcode: .invokeRequest, payload: armMsg)
            ctx5 = try commissioning.handleArmFailSafeResponse(
                response: armResp.payload, context: ctx4
            )
        } catch {
            if case ControllerError.imStatus = error { failSafeArmed = false }
            if case ControllerError.commissioningFailed = error { failSafeArmed = false }
            throw error
        }
        try commissioningFailureInjection?(.afterArmFailSafe)

        // Step 3: SetRegulatoryConfig, with a location the device supports
        let capabilityResp = try await imRequest(
            sessionID: paseSessionID, opcode: .readRequest, payload: commissioning.buildReadLocationCapability()
        )
        let location = try commissioning.handleLocationCapabilityResponse(capabilityResp.payload)
        let regMsg = commissioning.buildSetRegulatoryConfig(context: ctx5, locationType: location)
        let regResp = try await imRequest(sessionID: paseSessionID, opcode: .invokeRequest, payload: regMsg)
        try commissioning.handleSetRegulatoryConfigResponse(response: regResp.payload)

        // Step 4: CSRRequest
        let (csrMsg, csrNonce) = commissioning.buildCSRRequest()
        let csrResp = try await imRequest(sessionID: paseSessionID, opcode: .invokeRequest, payload: csrMsg)
        let deviceNodeID = await fabricManager.allocateNodeID()
        allocatedNodeID = deviceNodeID
        let (addRootMsg, addNOCMsg, ctx6) = try await commissioning.handleCSRResponse(
            response: csrResp.payload, expectedNonce: csrNonce, deviceNodeID: deviceNodeID, context: ctx5
        )
        logger.debug("Device will be node \(deviceNodeID.rawValue)")
        try commissioningFailureInjection?(.afterCSR)

        // Step 5: AddTrustedRootCert
        let addRootResp = try await imRequest(sessionID: paseSessionID, opcode: .invokeRequest, payload: addRootMsg)
        try commissioning.handleAddTrustedRootCertResponse(addRootResp.payload)

        // Step 5b: AddNOC — records the fabric index the device assigned
        let addNOCResp = try await imRequest(sessionID: paseSessionID, opcode: .invokeRequest, payload: addNOCMsg)
        var ctx7 = ctx6
        ctx7.deviceFabricIndex = try commissioning.handleNOCResponse(addNOCResp.payload)
        try commissioningFailureInjection?(.afterAddNOC)

        // Step 6: ACL write
        let aclResp = try await imRequest(
            sessionID: paseSessionID, opcode: .writeRequest, payload: commissioning.buildACLWrite()
        )
        try commissioning.handleACLWriteResponse(aclResp.payload)
        try commissioningFailureInjection?(.afterACLWrite)

        // Step 7: CASE to the device on the new fabric. A real device
        // (connectedhomeip) refuses CommissioningComplete over PASE with
        // InvalidAuthentication ("invalid security context").
        // Reserved until the session is cached (by the caller) or
        // unregistered (on failure): see commissionOverPASE.
        guard let caseSessionID = await reserveSessionID() else {
            throw ControllerError.caseSessionFailed("No free local session ID")
        }
        caseReservation = caseSessionID
        let established = try await caseHandshake(
            nodeID: deviceNodeID, address: address, mrp: mrp, localSessionID: caseSessionID
        )
        try await messenger.registerSession(established, peerAddress: address, mrp: mrp)
        caseSession = established
        try commissioningFailureInjection?(.afterCASE)

        // Step 8: CommissioningComplete over that CASE session
        let completeMsg = commissioning.buildCommissioningComplete()
        completeSent = true
        let completeResp = try await imRequest(
            sessionID: established.localSessionID, opcode: .invokeRequest, payload: completeMsg
        )
        let device = try commissioning.handleCommissioningComplete(
            response: completeResp.payload, context: ctx7
        )
        return (device, established)
    }


    // MARK: - Session Management

    /// Get or establish a CASE session to a commissioned device.
    ///
    /// Returns the cached session if there is one; otherwise establishes a
    /// new CASE session via Sigma1/2/3. Concurrent callers for the same node
    /// share one handshake. A caller cancelled while waiting for it throws
    /// `CancellationError` at once; the handshake carries on for the others.
    /// A cached session stays until it is invalidated (the device stopped
    /// acknowledging, or ``invalidateSession(for:)``).
    public func session(for nodeID: NodeID) async throws -> SecureSession {
        if let cached = sessionCache.session(for: nodeID) {
            return cached
        }
        if let inFlight = establishing[nodeID] {
            return try await Self.value(of: inFlight)
        }
        // Isolated to this actor: it cannot start before the entry is stored.
        let task = Task {
            defer { self.establishing[nodeID] = nil }
            return try await self.establishCASESession(nodeID: nodeID)
        }
        establishing[nodeID] = task
        return try await Self.value(of: task)
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
    ///
    /// Explicit parameters last until the node's address is refreshed: when
    /// a CASE attempt gets no answer and re-resolving finds the node at a new
    /// address, the timing from its operational TXT replaces them (an empty
    /// operational TXT keeps them). The last registry write wins.
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
    /// `MessagingError.stopped`. Cancels every live subscription (finishing
    /// its event stream) first. Terminal for this controller instance.
    public func stop() async {
        stopped = true
        let tracked = subscriptions
        subscriptions = []
        for subscription in tracked { await subscription.cancel() }
        await messenger.stop()
    }

    // MARK: - Operational API

    /// Read a single attribute from a commissioned device.
    ///
    /// Gets or establishes a CASE session and sends the request once. MRP
    /// retransmits it; a device that never acknowledges surfaces as
    /// `ControllerError.peerUnreachable` — the request is not re-issued.
    ///
    /// Reads are fabric-filtered by default: a fabric-scoped list (ACL,
    /// Fabrics, ...) then holds only this controller's own entries. Pass
    /// `isFabricFiltered: false` to see every fabric's entries; the device
    /// omits other fabrics' fields only where the cluster marks them
    /// fabric-sensitive.
    public func readAttribute(
        nodeID: NodeID,
        endpointID: EndpointID,
        clusterID: ClusterID,
        attributeID: AttributeID,
        isFabricFiltered: Bool = true
    ) async throws -> TLVElement {
        try await withSession(nodeID: nodeID) { session in
            let response = try await self.imRequest(
                sessionID: session.localSessionID,
                opcode: .readRequest,
                payload: IMClient.readAttributeRequest(
                    endpointID: endpointID,
                    clusterID: clusterID,
                    attributeID: attributeID,
                    isFabricFiltered: isFabricFiltered
                )
            )
            return try IMClient.parseReadResponse(response.payload)
        }
    }

    /// Write a single attribute on a commissioned device.
    ///
    /// Sent once on the node's CASE session (see ``readAttribute(nodeID:endpointID:clusterID:attributeID:isFabricFiltered:)``).
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
    ///
    /// Pass `timedTimeout` for commands that require a timed interaction
    /// (DoorLock Lock/Unlock, AdministratorCommissioning window commands); the
    /// controller then sends `TimedRequest` first, on the same exchange.
    public func invokeCommand(
        nodeID: NodeID,
        endpointID: EndpointID,
        clusterID: ClusterID,
        commandID: CommandID,
        commandFields: TLVElement? = nil,
        timedTimeout: Duration? = nil
    ) async throws -> TLVElement? {
        try await withSession(nodeID: nodeID) { session in
            let payload = IMClient.invokeCommandRequest(
                endpointID: endpointID,
                clusterID: clusterID,
                commandID: commandID,
                commandFields: commandFields,
                timedRequest: timedTimeout != nil
            )
            let response: InboundMessage
            if let timedTimeout {
                response = try await self.timedInvoke(sessionID: session.localSessionID, timeout: timedTimeout, payload: payload)
            } else {
                response = try await self.imRequest(sessionID: session.localSessionID, opcode: .invokeRequest, payload: payload)
            }
            return try IMClient.parseInvokeResponse(response.payload)
        }
    }

    /// Subscribe to attributes and events on a commissioned device.
    ///
    /// Returns once the first subscription is established (its priming report
    /// is already on ``ControllerSubscription/events``). Liveness is judged on
    /// the max interval the device granted plus the MRP exhaustion horizon for
    /// the peer; a dead subscription is re-established with backoff, asking only
    /// for events not yet delivered. Cancel it with ``ControllerSubscription/cancel()``;
    /// ``stop()`` cancels any still running.
    public func subscribe(nodeID: NodeID, _ request: SubscriptionRequest) async throws -> ControllerSubscription {
        guard !stopped else { throw MessagingError.stopped }
        guard let device = await registry.device(for: nodeID) else {
            throw ControllerError.deviceNotFound
        }
        guard !stopped else { throw MessagingError.stopped }
        let margin = MRPConfig(
            peer: device.mrpParameters ?? .default,
            maxRetransmissions: configuration.mrp.maxRetransmissions
        ).exhaustionHorizon(peerActive: false)
        let subscription = ControllerSubscription(
            nodeID: nodeID,
            request: request,
            messenger: messenger,
            client: subscriptionClient,
            sessionProvider: { [weak self] in
                guard let self else { throw MessagingError.stopped }
                return try await self.session(for: nodeID).localSessionID
            },
            livenessMargin: margin,
            operationTimeout: configuration.operationTimeout,
            onEstablishFailure: { [weak self] sessionID, error in
                await self?.invalidateStaleSession(for: nodeID, sessionID: sessionID, error: error)
            }
        )
        // Tracked before start() suspends, so a concurrent stop() cancels it.
        // Prune cancelled entries by removal only: the array is re-read after
        // every suspension, never rebuilt from a snapshot.
        var cancelledIDs: Set<ObjectIdentifier> = []
        for existing in subscriptions where await existing.isCancelled {
            cancelledIDs.insert(ObjectIdentifier(existing))
        }
        subscriptions.removeAll { cancelledIDs.contains(ObjectIdentifier($0)) }
        guard !stopped else { throw MessagingError.stopped }
        track(subscription)   // no suspension since the guard
        do {
            try await subscription.start()
        } catch {
            subscriptions.removeAll { $0 === subscription }
            if stopped { throw MessagingError.stopped }
            throw Self.operationalError(error, nodeID: nodeID)
        }
        if stopped {
            await subscription.cancel()
            subscriptions.removeAll { $0 === subscription }
            throw MessagingError.stopped
        }
        return subscription
    }

    /// Track a subscription so ``stop()`` and ``removeDevice(nodeID:)`` cancel it.
    func track(_ subscription: ControllerSubscription) {
        subscriptions.append(subscription)
    }

    /// Number of subscriptions currently tracked (for tests).
    var trackedSubscriptionCount: Int { subscriptions.count }

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
        let doomed = subscriptions.filter { $0.nodeID == nodeID }
        subscriptions.removeAll { $0.nodeID == nodeID }
        for subscription in doomed { await subscription.cancel() }
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

    /// Run a timed invoke: `TimedRequest`, then the `InvokeRequest`, on **one**
    /// exchange (the device keys its timed-interaction window by exchange).
    /// A refused `TimedRequest` fails the call and the invoke is never sent.
    func timedInvoke(sessionID: UInt16, timeout: Duration, payload: Data) async throws -> InboundMessage {
        let exchange = try await messenger.openExchange(sessionID: sessionID)
        do {
            let timedStatus = try await exchange.request(
                protocolID: .interactionModel,
                opcode: InteractionModelOpcode.timedRequest.rawValue,
                payload: IMClient.timedRequest(timeout: timeout),
                timeout: configuration.operationTimeout
            )
            guard timedStatus.protocolID == MatterProtocolID.interactionModel.rawValue,
                  timedStatus.opcode == InteractionModelOpcode.statusResponse.rawValue else {
                throw MessagingError.unexpectedProtocol(protocolID: timedStatus.protocolID, opcode: timedStatus.opcode)
            }
            let status = try IMStatusResponse.fromTLV(timedStatus.payload)
            guard status.status == IMStatusResponse.success.status else {
                throw ControllerError.imStatus(status.status)
            }
            let response = try await exchange.request(
                protocolID: .interactionModel,
                opcode: InteractionModelOpcode.invokeRequest.rawValue,
                payload: payload,
                timeout: configuration.operationTimeout
            )
            await exchange.close()
            if response.opcode == InteractionModelOpcode.statusResponse.rawValue {
                throw ControllerError.imStatus(try IMStatusResponse.fromTLV(response.payload).status)
            }
            return response
        } catch {
            await exchange.close()
            throw error
        }
    }

    /// Establish a new CASE session to a device via Sigma1/2/3 on one
    /// unsecured exchange, and register it before caching it.
    ///
    /// If the handshake fails with `peerUnreachable` or `timeout` (taken to
    /// mean nothing answered; a `timeout` can also follow a Sigma2), the
    /// node's operational address is re-resolved once, within
    /// `configuration.addressRefreshTimeout` (see
    /// ``refreshedAddress(nodeID:tried:)``). At a different address the
    /// handshake is retried once there, under the same reserved session ID,
    /// and the session is registered with that address. Otherwise the
    /// original error is thrown unchanged: retrying an unchanged address
    /// would only double a dead peer's failure latency. Any other failure,
    /// such as a refusal (`caseSessionFailed`), never triggers a re-resolve.
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

        logger.debug("Establishing CASE session to node \(nodeID.rawValue)")

        var usedAddress = address
        let session: SecureSession
        do {
            session = try await caseHandshake(
                nodeID: nodeID, address: address, mrp: device.mrpParameters, localSessionID: sessionID
            )
        } catch {
            let original = Self.operationalError(error, nodeID: nodeID)
            guard Self.nothingAnswered(original, nodeID: nodeID),
                  let refreshed = try await refreshedAddress(nodeID: nodeID, tried: address) else {
                throw original
            }
            logger.info("Node \(nodeID.rawValue) did not answer CASE; retrying at its re-resolved address")
            usedAddress = refreshed.address
            do {
                session = try await caseHandshake(
                    nodeID: nodeID, address: refreshed.address, mrp: refreshed.mrp, localSessionID: sessionID
                )
            } catch {
                throw Self.operationalError(error, nodeID: nodeID)
            }
        }

        // Register before caching so the first request's reply is routable.
        // Parameters re-read now: setMRPParameters may have run during the
        // handshake (it then waits for this establishment to finish).
        // A device removed during the handshake gets no session.
        guard let current = await registry.device(for: nodeID) else {
            throw ControllerError.deviceNotFound
        }
        do {
            try await messenger.registerSession(session, peerAddress: usedAddress, mrp: current.mrpParameters)
        } catch {
            throw Self.operationalError(error, nodeID: nodeID)
        }
        sessionCache.store(session, for: nodeID)

        logger.debug("CASE session established to node \(nodeID.rawValue)")

        return session
    }

    /// Re-resolve `nodeID`'s operational address after a handshake at
    /// `tried` got no answer. When it differs, the new address is recorded
    /// and persisted, with the MRP parameters from the operational TXT; an
    /// empty TXT (allowed by the discovery contract) keeps the stored
    /// parameters rather than overwriting them with defaults. Returns the
    /// new address and the parameters to retry with, or nil when resolution
    /// fails (logged) or names the address already tried, or when the
    /// device was removed or the controller stopped meanwhile. Resolution is
    /// bounded by `configuration.addressRefreshTimeout`; cancellation
    /// propagates.
    private func refreshedAddress(
        nodeID: NodeID,
        tried: MatterAddress
    ) async throws -> (address: MatterAddress, mrp: MRPParameters?)? {
        let resolved: ResolvedService
        do {
            resolved = try await resolveOperational(nodeID: nodeID, timeout: configuration.addressRefreshTimeout)
        } catch let cancellation as CancellationError {
            throw cancellation
        } catch {
            try Task.checkCancellation()
            logger.notice("Node \(nodeID.rawValue): operational re-resolve failed: \(error)")
            return nil
        }
        guard !stopped, await registry.device(for: nodeID) != nil else { return nil }
        guard resolved.address != tried else { return nil }
        // A device removed from here on is a no-op in the registry; a stop
        // from here on skips the save (see updateOperationalAddress).
        await updateOperationalAddress(
            resolved.address, mrp: Self.mrpParameters(fromOperationalTXT: resolved.txtRecords), for: nodeID
        )
        // The registry's value: an empty TXT kept what was stored.
        return (resolved.address, await registry.device(for: nodeID)?.mrpParameters)
    }

    /// Whether `error` (already mapped by ``operationalError(_:nodeID:)``)
    /// means nothing answered, rather than a device that answered badly.
    private static func nothingAnswered(_ error: any Error, nodeID: NodeID) -> Bool {
        switch error as? ControllerError {
        case .peerUnreachable(let node)?: return node == nodeID
        case .timeout?: return true
        default: return false
        }
    }

    /// Sigma1/2/3 with `nodeID` at `address` on one unsecured exchange,
    /// closed on every path. Returns the established session, not yet
    /// registered with the message layer.
    private func caseHandshake(
        nodeID: NodeID,
        address: MatterAddress,
        mrp: MRPParameters?,
        localSessionID sessionID: UInt16
    ) async throws -> SecureSession {
        let timeout = configuration.operationTimeout
        let (sigma1Data, handshakeCtx) = controllerSession.createSigma1(
            peerNodeID: nodeID,
            initiatorSessionID: sessionID
        )

        let handshake = await messenger.openExchange(peer: address, mrp: mrp)
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
            throw error
        }
        await handshake.close()
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

    /// Await a shared task's value, but stop waiting — throwing
    /// `CancellationError` — as soon as the calling task is cancelled. The
    /// shared task itself is never cancelled: other callers may be waiting
    /// on it.
    private static func value<T: Sendable>(of task: Task<T, any Error>) async throws -> T {
        let waiter = CancellableWaiter<T>()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                if waiter.install(continuation) {
                    Task { waiter.resume(with: await task.result) }
                }
            }
        } onCancel: {
            waiter.resume(with: .failure(CancellationError()))
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

    /// Drop the cached session if `error` says it is gone and it is still the
    /// session the failed attempt used (a newer one is left alone).
    func invalidateStaleSession(for nodeID: NodeID, sessionID: UInt16, error: any Error) async {
        guard let mapped = Self.operationalError(error, nodeID: nodeID) as? ControllerError,
              mapped == .peerUnreachable(nodeID),
              let cached = sessionCache.session(for: nodeID),
              cached.localSessionID == sessionID else { return }
        logger.info("Node \(nodeID.rawValue) subscription failed on a dead session; invalidating it")
        await invalidateSession(for: nodeID)
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

// MARK: - Cancellable wait

/// One waiter's continuation, resumed exactly once: by the shared task's
/// result or by the waiter's cancellation, whichever comes first.
private final class CancellableWaiter<T: Sendable>: Sendable {
    private enum State {
        case idle
        case waiting(CheckedContinuation<T, any Error>)
        /// Resumed (by cancellation) before the continuation was installed.
        case early(Result<T, any Error>)
        case done
    }

    private let state = Mutex<State>(.idle)

    /// Install the continuation. Returns `false` if the waiter was already
    /// cancelled (the continuation is resumed at once); then nothing needs
    /// to forward the task's result.
    func install(_ continuation: CheckedContinuation<T, any Error>) -> Bool {
        let early = state.withLock { state -> Result<T, any Error>? in
            switch state {
            case .idle:
                state = .waiting(continuation)
                return nil
            case .early(let result):
                state = .done
                return result
            case .waiting, .done:
                preconditionFailure("CancellableWaiter continuation installed twice")
            }
        }
        guard let early else { return true }
        continuation.resume(with: early)
        return false
    }

    /// Resume with `result` unless already resumed.
    func resume(with result: Result<T, any Error>) {
        let continuation = state.withLock { state -> CheckedContinuation<T, any Error>? in
            switch state {
            case .idle:
                state = .early(result)
                return nil
            case .waiting(let continuation):
                state = .done
                return continuation
            case .early, .done:
                return nil
            }
        }
        continuation?.resume(with: result)
    }
}
