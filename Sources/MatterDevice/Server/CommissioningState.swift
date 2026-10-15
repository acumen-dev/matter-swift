// CommissioningState.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import Logging
import MatterTypes
import MatterModel
import MatterCrypto

/// Shared mutable state for the device-side commissioning flow.
///
/// Tracks fail-safe timer, commissioning window state, staged credentials
/// (RCAC, NOC, operational key), and committed fabrics. Shared between
/// `GeneralCommissioningHandler`, `OperationalCredentialsHandler`,
/// `AdminCommissioningHandler`, and `MatterDeviceServer`.
///
/// All mutations happen synchronously on the device server actor (before the server
/// starts: on the context that creates the bridge) — no locking of that state.
/// Marked `@unchecked Sendable` because it is owned by the `MatterDeviceServer`
/// actor and only mutated within that actor's context.
///
/// Persistence rule: nothing outside that context reads the fabric state. Each
/// mutation of persisted state (fabrics, ACLs, next fabric index, PBKDF parameters)
/// calls `fabricStateChanged()` on the owning context, which copies it into
/// `fabricSnapshot` under `persistLock`. Writes to the fabric store compose that
/// snapshot with the bridged endpoint allocation — both lock-protected — so
/// `MatterBridge.add*`, which runs on the host's context, can request a save
/// without touching actor-owned state.
public final class CommissioningState: @unchecked Sendable {

    // MARK: - Commissioning Window Status

    /// Commissioning window status values per Matter spec §11.18.5.1.
    public enum WindowStatus: UInt8, Sendable {
        case notOpen = 0
        case enhancedWindowOpen = 1
        case basicWindowOpen = 2
    }

    /// Current commissioning window status.
    public private(set) var windowStatus: WindowStatus = .notOpen

    /// When the commissioning window expires (nil if not open).
    public private(set) var windowExpiry: Date?

    /// Fabric that opened the current window (nil if not open or first commissioning).
    public private(set) var windowAdminFabricIndex: FabricIndex?

    /// Vendor ID of the admin that opened the current window.
    public private(set) var windowAdminVendorId: UInt16?

    /// Injected PAKE verifier for an enhanced commissioning window (§11.18.8.1).
    ///
    /// When an `OpenCommissioningWindow` command includes a PAKE verifier, it is stored here
    /// so that the PASE handler can use it instead of the device's default passcode-derived verifier.
    /// Cleared when the window closes (via `closeWindow()`).
    public private(set) var injectedPAKEVerifier: InjectedPAKEVerifier?

    // MARK: - Fail-Safe

    /// Whether the fail-safe timer is currently armed.
    public private(set) var isFailSafeArmed: Bool = false

    /// When the fail-safe expires (nil if not armed).
    public private(set) var failSafeExpiry: Date?

    // MARK: - Staged Credentials

    /// Staged RCAC (trusted root certificate) — pending CommissioningComplete.
    public var stagedRCAC: Data?

    /// Staged NOC (Node Operational Certificate) — pending CommissioningComplete.
    public var stagedNOC: Data?

    /// Staged ICAC (optional Intermediate CA Certificate).
    public var stagedICAC: Data?

    /// Staged IPK epoch key value.
    public var stagedIPK: Data?

    /// Staged CASE admin subject (controller node ID).
    public var stagedCaseAdminSubject: UInt64?

    /// Staged admin vendor ID.
    public var stagedAdminVendorId: UInt16?

    /// Device's operational key pair — generated during CSRRequest.
    public private(set) var operationalKey: P256.Signing.PrivateKey?

    /// CSR nonce from the most recent CSRRequest.
    public private(set) var csrNonce: Data?

    /// Device Attestation Credentials — set during server initialisation.
    public var attestationCredentials: DeviceAttestationCredentials?

    /// Attestation challenge derived from the active PASE session keys.
    /// Set after PASE session establishment, used to sign attestation responses.
    public var attestationChallenge: Data?

    // MARK: - Invoking Context

    /// Fabric index of the current command invocation (set by the server before dispatch).
    /// Used by commands like UpdateFabricLabel that operate on the accessing fabric.
    public var invokingFabricIndex: FabricIndex?

    // MARK: - PBKDF Parameters

    /// PBKDF2 salt for PASE commissioning.
    ///
    /// Set once on first startup and persisted across restarts. Controllers (e.g. Apple Home)
    /// cache PBKDF params after a successful PASE and send `hasPBKDFParameters = true` on
    /// subsequent attempts — the server must respond with the same salt, or SPAKE2+ fails.
    public private(set) var pbkdfSalt: Data?

    /// PBKDF2 iteration count paired with `pbkdfSalt`.
    public private(set) var pbkdfIterations: Int = 1000

    /// Set the PBKDF2 parameters and persist them.
    public func setPBKDFParameters(salt: Data, iterations: Int) {
        pbkdfSalt = salt
        pbkdfIterations = iterations
        fabricStateChanged()
    }

    // MARK: - Committed Fabrics

    /// Committed fabrics on this device.
    public private(set) var fabrics: [FabricIndex: CommittedFabric] = [:]

    /// Set a committed fabric's label (UpdateFabricLabel).
    ///
    /// - Returns: `false` if no such fabric is committed.
    @discardableResult
    public func setFabricLabel(_ label: String, for fabricIndex: FabricIndex) -> Bool {
        guard fabrics[fabricIndex] != nil else { return false }
        // Not part of StoredFabric, so there is nothing to persist.
        fabrics[fabricIndex]?.label = label
        return true
    }

    /// Next fabric index to assign.
    private var nextFabricIndex: UInt8 = 1

    // MARK: - ACLs

    /// Staged ACL entries — pending CommissioningComplete.
    public var stagedACLs: [AccessControlCluster.AccessControlEntry] = []

    /// Committed ACL entries per fabric.
    public private(set) var committedACLs: [FabricIndex: [AccessControlCluster.AccessControlEntry]] = [:]

    /// Update committed ACLs for a specific fabric and persist.
    ///
    /// Called by `AccessControlHandler` for post-commissioning ACL writes.
    /// During commissioning, ACL writes are staged and committed by `commitCommissioning()`.
    /// After commissioning, this method updates the committed ACLs directly.
    public func updateCommittedACLs(fabricIndex: FabricIndex, entries: [AccessControlCluster.AccessControlEntry]) {
        committedACLs[fabricIndex] = entries
        fabricStateChanged()
    }

    // MARK: - Persistence

    /// Optional fabric store for persisting committed state across restarts.
    private let fabricStore: (any MatterFabricStore)?

    /// Whether committed state is persisted through a fabric store.
    var hasFabricStore: Bool { fabricStore != nil }

    /// Bridged endpoint IDs issued per device `uniqueID`, persisted with the fabrics.
    let bridgedEndpointAllocator = BridgedEndpointAllocator()

    /// Whether `loadFromStore()` has applied the stored state. It runs once, so a later
    /// call never reads disk over in-memory state.
    private var loaded = false

    /// Guards `fabricSnapshot`, `savePending` and `saveWriter`.
    private let persistLock = NSLock()
    /// The persisted fabric state as of its last change, with empty allocation fields.
    private var fabricSnapshot = StoredDeviceState()
    /// Whether a change has not been written yet.
    private var savePending = false
    /// The single task writing to the fabric store. It writes the latest state until
    /// nothing is pending, so a burst of changes costs one or two writes, not one each.
    private var saveWriter: Task<Void, Never>?

    /// Attempts per write before it is given up. A later change requests a new write.
    static let maxSaveAttempts = 3
    private let saveRetryDelay: @Sendable (Int) async -> Void
    private let logger = Logger(label: "matter.commissioning-state")

    // MARK: - Callbacks

    /// Called when commissioning completes with fabric info for CASE session setup.
    public var onCommissioningComplete: ((CommittedFabric) -> Void)?

    /// Called when a fabric is removed (for server cleanup — CASE sessions, mDNS, etc.).
    public var onFabricRemoved: ((FabricIndex) -> Void)?

    /// Called when the commissioning window is opened (for mDNS update).
    public var onWindowOpened: (() -> Void)?

    /// Called when the commissioning window is closed (for mDNS update, PASE cleanup).
    public var onWindowClosed: (() -> Void)?

    /// Called immediately after AddNOC stages the NOC + RCAC + IPK.
    ///
    /// Per Matter spec §4.3.5, the device SHALL begin operational mDNS advertisement
    /// as soon as the NOC is installed (staged), not waiting for CommissioningComplete.
    /// The server uses this callback to advertise the operational instance name so that
    /// Apple Home (and other commissioners) can discover the device before CommissioningComplete.
    public var onNOCStaged: (() -> Void)?

    /// Called when staged credentials are reverted (fail-safe expiry or ArmFailSafe(0)).
    ///
    /// The server uses this to withdraw the pre-committed operational mDNS advertisement.
    public var onNOCReverted: (() -> Void)?

    // MARK: - Init

    /// Create commissioning state that is not persisted.
    public init() {
        self.fabricStore = nil
        self.saveRetryDelay = Self.defaultSaveRetryDelay
    }

    /// Create commissioning state persisted through `fabricStore`.
    ///
    /// Internal: a persisted state must be loaded before bridged endpoints are added,
    /// and only `MatterBridge.init(config:fabricStore:attributeStore:)` guarantees that.
    ///
    /// - Parameter saveRetryDelay: Waits before retry `attempt` (1-based) of a failed
    ///   write. Injectable so tests need no wall clock.
    init(
        fabricStore: (any MatterFabricStore)?,
        saveRetryDelay: @escaping @Sendable (Int) async -> Void = CommissioningState.defaultSaveRetryDelay
    ) {
        self.fabricStore = fabricStore
        self.saveRetryDelay = saveRetryDelay
    }

    /// 200 ms, then 400 ms.
    static let defaultSaveRetryDelay: @Sendable (Int) async -> Void = { attempt in
        try? await Task.sleep(for: .milliseconds(100 << attempt))
    }

    // MARK: - Fail-Safe Operations

    public func armFailSafe(expiresAt: Date) {
        isFailSafeArmed = true
        failSafeExpiry = expiresAt
    }

    public func disarmFailSafe() {
        isFailSafeArmed = false
        failSafeExpiry = nil
        let hadStagedNOC = stagedNOC != nil
        clearStagedState()
        // Notify server to withdraw the staged operational mDNS advertisement.
        if hadStagedNOC {
            onNOCReverted?()
        }
    }

    /// Check if the fail-safe has expired.
    public func checkFailSafeExpiry(now: Date = Date()) -> Bool {
        guard let expiry = failSafeExpiry else { return false }
        if now >= expiry {
            disarmFailSafe()
            return true
        }
        return false
    }

    // MARK: - Commissioning Window Operations

    /// Open a basic commissioning window with a timeout.
    ///
    /// - Parameters:
    ///   - timeout: Window duration in seconds (Matter spec: 180–900).
    ///   - fabricIndex: Fabric of the admin opening the window (nil for first commissioning).
    ///   - vendorId: Vendor ID of the admin opening the window.
    ///   - now: Current time (injectable for testing).
    public func openBasicWindow(
        timeout: UInt16,
        fabricIndex: FabricIndex? = nil,
        vendorId: UInt16? = nil,
        now: Date = Date()
    ) {
        windowStatus = .basicWindowOpen
        windowExpiry = now.addingTimeInterval(TimeInterval(timeout))
        windowAdminFabricIndex = fabricIndex
        windowAdminVendorId = vendorId
        onWindowOpened?()
    }

    /// Open an enhanced commissioning window with an injected PAKE verifier (§11.18.8.1).
    ///
    /// The injected verifier replaces the device's default passcode-derived verifier for any
    /// PASE session that begins while this window is open. The window status is set to
    /// `enhancedWindowOpen`.
    ///
    /// - Parameters:
    ///   - timeout: Window duration in seconds (Matter spec: 180–900).
    ///   - verifier: The injected PAKE verifier containing W0, L, discriminator, iterations, and salt.
    ///   - fabricIndex: Fabric of the admin opening the window.
    ///   - vendorId: Vendor ID of the admin opening the window.
    ///   - now: Current time (injectable for testing).
    public func openEnhancedWindow(
        timeout: UInt16,
        verifier: InjectedPAKEVerifier,
        fabricIndex: FabricIndex? = nil,
        vendorId: UInt16? = nil,
        now: Date = Date()
    ) {
        windowStatus = .enhancedWindowOpen
        windowExpiry = now.addingTimeInterval(TimeInterval(timeout))
        windowAdminFabricIndex = fabricIndex
        windowAdminVendorId = vendorId
        injectedPAKEVerifier = verifier
        onWindowOpened?()
    }

    /// Close the commissioning window.
    public func closeWindow() {
        windowStatus = .notOpen
        windowExpiry = nil
        windowAdminFabricIndex = nil
        windowAdminVendorId = nil
        injectedPAKEVerifier = nil
        onWindowClosed?()
    }

    /// Check if the commissioning window has expired.
    ///
    /// Returns `true` if the window was open and has expired (and was closed).
    public func checkWindowExpiry(now: Date = Date()) -> Bool {
        guard let expiry = windowExpiry else { return false }
        if now >= expiry {
            closeWindow()
            return true
        }
        return false
    }

    /// Whether the commissioning window is currently open (basic or enhanced).
    public var isWindowOpen: Bool {
        windowStatus != .notOpen
    }

    // MARK: - Fabric Removal

    /// Remove a committed fabric and its ACLs.
    ///
    /// Returns `true` if the fabric was found and removed.
    public func removeFabric(_ fabricIndex: FabricIndex) -> Bool {
        guard fabrics.removeValue(forKey: fabricIndex) != nil else { return false }
        committedACLs.removeValue(forKey: fabricIndex)
        fabricStateChanged()
        onFabricRemoved?(fabricIndex)
        return true
    }

    // MARK: - CSR

    /// Generate a new operational key pair and store the CSR nonce.
    public func generateOperationalKey(csrNonce: Data) -> P256.Signing.PrivateKey {
        let key = P256.Signing.PrivateKey()
        self.operationalKey = key
        self.csrNonce = csrNonce
        return key
    }

    // MARK: - Commit

    /// Commit staged credentials as a new fabric.
    /// The fabric index the next `commitCommissioning()` will assign.
    ///
    /// Indices are allocated monotonically and not reused, so after a fabric is
    /// removed this is not `fabrics.count + 1`. AddNOC's response and the staged
    /// CASE identity must use this value, or CASE runs under a different index
    /// than the committed fabric and every ACL check after commit fails.
    public var pendingFabricIndex: FabricIndex {
        FabricIndex(rawValue: nextFabricIndex)
    }

    public func commitCommissioning() {
        guard let noc = stagedNOC,
              let rcac = stagedRCAC,
              let opKey = operationalKey,
              let ipk = stagedIPK else {
            // Nothing to commit — this is a no-op commissioning complete
            isFailSafeArmed = false
            failSafeExpiry = nil
            return
        }

        let fabricIndex = pendingFabricIndex
        nextFabricIndex += 1

        let fabric = CommittedFabric(
            fabricIndex: fabricIndex,
            nocTLV: noc,
            icacTLV: stagedICAC,
            rcacTLV: rcac,
            operationalKey: opKey,
            ipkEpochKey: ipk,
            caseAdminSubject: stagedCaseAdminSubject ?? 0,
            adminVendorId: stagedAdminVendorId ?? 0
        )

        fabrics[fabricIndex] = fabric

        // Commit staged ACLs — stamp the real fabricIndex onto each entry.
        // Commissioners may omit fabricIndex in ACL write requests (per spec); the device
        // assigns it. Entries written during commissioning carry a placeholder (0); we fix
        // them up here so that fabric-scoped attribute filtering works correctly post-commit.
        if !stagedACLs.isEmpty {
            let fixedACLs = stagedACLs.map { entry in
                AccessControlCluster.AccessControlEntry(
                    privilege: entry.privilege,
                    authMode: entry.authMode,
                    subjects: entry.subjects,
                    targets: entry.targets,
                    fabricIndex: fabricIndex
                )
            }
            committedACLs[fabricIndex] = fixedACLs
        }
        fabricStateChanged()

        onCommissioningComplete?(fabric)

        isFailSafeArmed = false
        failSafeExpiry = nil
        clearStagedState()
    }

    // MARK: - Persistence

    /// Load committed state from the fabric store.
    ///
    /// Restores fabrics, ACLs, the next fabric index counter and the bridged endpoint
    /// allocation from persisted state. Only the first successful call has any effect.
    public func loadFromStore() async throws {
        guard let store = fabricStore, !loaded else { return }
        let stored = try await store.load() ?? StoredDeviceState()

        nextFabricIndex = stored.nextFabricIndex
        pbkdfSalt = stored.pbkdfSalt
        if let iterations = stored.pbkdfIterations {
            pbkdfIterations = iterations
        }

        for sf in stored.fabrics {
            let fabricIndex = FabricIndex(rawValue: sf.fabricIndex)
            let opKey = try P256.Signing.PrivateKey(rawRepresentation: sf.operationalKeyRaw)
            let fabric = CommittedFabric(
                fabricIndex: fabricIndex,
                nocTLV: sf.nocTLV,
                icacTLV: sf.icacTLV,
                rcacTLV: sf.rcacTLV,
                operationalKey: opKey,
                ipkEpochKey: sf.ipkEpochKey,
                caseAdminSubject: sf.caseAdminSubject,
                adminVendorId: sf.adminVendorId
            )
            fabrics[fabricIndex] = fabric
        }

        for sa in stored.acls {
            let fabricIndex = FabricIndex(rawValue: sa.fabricIndex)
            committedACLs[fabricIndex] = sa.entries.map { entry in
                AccessControlCluster.AccessControlEntry(
                    privilege: AccessControlCluster.Privilege(rawValue: entry.privilege) ?? .view,
                    authMode: AccessControlCluster.AuthMode(rawValue: entry.authMode) ?? .case,
                    subjects: entry.subjects,
                    targets: entry.targets?.map { t in
                        AccessControlCluster.Target(
                            cluster: t.cluster.map { ClusterID(rawValue: $0) },
                            endpoint: t.endpoint.map { EndpointID(rawValue: $0) },
                            deviceType: t.deviceType.map { DeviceTypeID(rawValue: $0) }
                        )
                    },
                    fabricIndex: fabricIndex
                )
            }
        }

        loaded = true
        refreshFabricSnapshot()

        // Last, once the fabric state is in memory: only now may an allocation save
        // replace the stored state.
        if bridgedEndpointAllocator.load(
            assigned: stored.bridgedEndpointIDs,
            highest: stored.highestBridgedEndpointID
        ) {
            scheduleSave()
            await flush()
        }
    }

    /// Save committed state to the fabric store and wait for the write.
    ///
    /// Persists all fabrics, ACLs, the next fabric index counter, the PBKDF parameters
    /// and the bridged endpoint allocation. Every mutator saves on its own; this is for
    /// callers that need the write to have happened. Call it on the owning context.
    func saveToStore() async {
        fabricStateChanged()
        await flush()
    }

    /// Wait until every requested save has been written.
    public func flush() async {
        while let writer = persistLock.withLock({ saveWriter }) {
            await writer.value
        }
    }

    /// Record a change to persisted fabric state and request a save.
    ///
    /// Call on the owning context: this is the only place the fabric state is read
    /// for persistence.
    func fabricStateChanged() {
        refreshFabricSnapshot()
        scheduleSave()
    }

    /// Request a write of the current snapshot and allocation. Safe from any context.
    func scheduleSave() {
        guard let store = fabricStore else { return }
        persistLock.withLock {
            savePending = true
            guard saveWriter == nil else { return }
            saveWriter = Task {
                var failures = 0
                while let state = self.takePendingState() {
                    do {
                        try await store.save(state)
                        failures = 0
                    } catch {
                        failures += 1
                        guard failures < Self.maxSaveAttempts else {
                            self.logger.error("Giving up saving fabric state after \(failures) failed attempts: \(error)")
                            failures = 0
                            continue
                        }
                        self.logger.error("Saving fabric state failed (attempt \(failures) of \(Self.maxSaveAttempts)), retrying: \(error)")
                        // Retry with the latest state, which includes this one.
                        self.persistLock.withLock { self.savePending = true }
                        await self.saveRetryDelay(failures)
                    }
                }
            }
        }
    }

    /// The state to write next, or `nil` (and the writer retires) if nothing is pending.
    private func takePendingState() -> StoredDeviceState? {
        persistLock.withLock {
            guard savePending else {
                saveWriter = nil
                return nil
            }
            savePending = false
            var state = fabricSnapshot
            let allocation = bridgedEndpointAllocator.snapshot()
            state.bridgedEndpointIDs = allocation.assigned
            state.highestBridgedEndpointID = allocation.highest
            return state
        }
    }

    private func refreshFabricSnapshot() {
        let snapshot = fabricState()
        persistLock.withLock { fabricSnapshot = snapshot }
    }

    /// The persisted fabric state, read on the owning context. Allocation fields empty.
    private func fabricState() -> StoredDeviceState {
        let storedFabrics = fabrics.values.map { f in
            StoredFabric(
                fabricIndex: f.fabricIndex.rawValue,
                nocTLV: f.nocTLV,
                icacTLV: f.icacTLV,
                rcacTLV: f.rcacTLV,
                operationalKeyRaw: f.operationalKey.rawRepresentation,
                ipkEpochKey: f.ipkEpochKey,
                caseAdminSubject: f.caseAdminSubject,
                adminVendorId: f.adminVendorId
            )
        }

        let storedACLs = committedACLs.map { (fabricIndex, entries) in
            StoredFabricACLs(
                fabricIndex: fabricIndex.rawValue,
                entries: entries.map { e in
                    StoredACLEntry(
                        privilege: e.privilege.rawValue,
                        authMode: e.authMode.rawValue,
                        subjects: e.subjects,
                        targets: e.targets?.map { t in
                            StoredACLTarget(
                                cluster: t.cluster?.rawValue,
                                endpoint: t.endpoint?.rawValue,
                                deviceType: t.deviceType?.rawValue
                            )
                        },
                        fabricIndex: e.fabricIndex.rawValue
                    )
                }
            )
        }

        return StoredDeviceState(
            fabrics: storedFabrics,
            acls: storedACLs,
            nextFabricIndex: nextFabricIndex,
            pbkdfSalt: pbkdfSalt,
            pbkdfIterations: pbkdfSalt != nil ? pbkdfIterations : nil
        )
    }

    // MARK: - Private

    private func clearStagedState() {
        stagedRCAC = nil
        stagedNOC = nil
        stagedICAC = nil
        stagedIPK = nil
        stagedCaseAdminSubject = nil
        stagedAdminVendorId = nil
        stagedACLs = []
        // Keep operationalKey and csrNonce — they persist until next CSRRequest
    }
}

// MARK: - Injected PAKE Verifier

/// An injected PAKE verifier provided via the `OpenCommissioningWindow` command (§11.18.8.1).
///
/// Allows a commissioner to open an enhanced commissioning window by injecting a freshly-derived
/// SPAKE2+ verifier (W0 || L), a discriminator, and PBKDF parameters. Any PASE session that
/// begins while the enhanced window is open must use this verifier instead of the device's
/// default passcode-derived verifier.
public struct InjectedPAKEVerifier: Sendable {

    /// W0 scalar — first 32 bytes of the 97-byte PAKEPasscodeVerifier field.
    public let w0: Data

    /// L point (uncompressed SEC1, 65 bytes) — remaining bytes of PAKEPasscodeVerifier.
    public let L: Data

    /// 12-bit discriminator for mDNS advertisement during the window (advisory).
    public let discriminator: UInt16

    /// PBKDF2 iteration count used to derive this verifier.
    public let iterations: UInt32

    /// PBKDF2 salt used to derive this verifier (16–32 bytes).
    public let salt: Data

    public init(w0: Data, L: Data, discriminator: UInt16, iterations: UInt32, salt: Data) {
        self.w0 = w0
        self.L = L
        self.discriminator = discriminator
        self.iterations = iterations
        self.salt = salt
    }

    /// Build a `Spake2pVerifier` from the injected W0 and L values.
    public func spake2pVerifier() -> Spake2pVerifier {
        Spake2pVerifier(w0: w0, L: L)
    }
}

// MARK: - Committed Fabric

/// A fully committed fabric on the device.
public struct CommittedFabric: Sendable {

    public let fabricIndex: FabricIndex
    public let nocTLV: Data
    public let icacTLV: Data?
    public let rcacTLV: Data
    public let operationalKey: P256.Signing.PrivateKey
    public let ipkEpochKey: Data
    public let caseAdminSubject: UInt64
    public let adminVendorId: UInt16

    /// Optional user-assigned label for this fabric.
    public var label: String?

    /// Build a `FabricInfo` from this committed fabric.
    ///
    /// Parses the TLV-encoded certificates and constructs the full fabric info
    /// needed for CASE session establishment.
    public func fabricInfo() throws -> FabricInfo {
        let rcac = try MatterCertificate.fromTLV(rcacTLV)
        let noc = try MatterCertificate.fromTLV(nocTLV)
        let icac = try icacTLV.map { try MatterCertificate.fromTLV($0) }

        // Extract fabric ID and node ID from NOC subject
        let fabricID = noc.subject.fabricID ?? FabricID(rawValue: 0)
        let nodeID = noc.subject.nodeID ?? NodeID(rawValue: 0)

        return FabricInfo(
            fabricIndex: fabricIndex,
            fabricID: fabricID,
            nodeID: nodeID,
            rcac: rcac,
            icac: icac,
            rawICAC: icacTLV,
            noc: noc,
            rawNOC: nocTLV,
            operationalKey: operationalKey,
            ipkEpochKey: ipkEpochKey
        )
    }
}
