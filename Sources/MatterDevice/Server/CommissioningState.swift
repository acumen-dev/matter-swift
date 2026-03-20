// CommissioningState.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
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
/// All mutations happen synchronously on the device server actor — no internal
/// locking needed. Marked `@unchecked Sendable` because it is owned by the
/// `MatterDeviceServer` actor and only mutated within that actor's context.
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
    public var pbkdfSalt: Data?

    /// PBKDF2 iteration count paired with `pbkdfSalt`.
    public var pbkdfIterations: Int = 1000

    // MARK: - Committed Fabrics

    /// Committed fabrics on this device.
    public var fabrics: [FabricIndex: CommittedFabric] = [:]

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
        // Persist asynchronously — the save is best-effort
        Task { await saveToStore() }
    }

    // MARK: - Persistence

    /// Optional fabric store for persisting committed state across restarts.
    private let fabricStore: (any MatterFabricStore)?

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

    public init(fabricStore: (any MatterFabricStore)? = nil) {
        self.fabricStore = fabricStore
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

        let fabricIndex = FabricIndex(rawValue: nextFabricIndex)
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

        onCommissioningComplete?(fabric)

        isFailSafeArmed = false
        failSafeExpiry = nil
        clearStagedState()
    }

    // MARK: - Persistence

    /// Load committed state from the fabric store.
    ///
    /// Restores fabrics, ACLs, and the next fabric index counter from persisted
    /// state. Called during server startup before accepting connections.
    public func loadFromStore() async throws {
        guard let store = fabricStore else { return }
        guard let stored = try await store.load() else { return }

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
    }

    /// Save committed state to the fabric store.
    ///
    /// Persists all fabrics, ACLs, and the next fabric index counter.
    /// Called after commissioning completes and after ACL modifications.
    public func saveToStore() async {
        guard let store = fabricStore else { return }

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

        let state = StoredDeviceState(
            fabrics: storedFabrics,
            acls: storedACLs,
            nextFabricIndex: nextFabricIndex,
            pbkdfSalt: pbkdfSalt,
            pbkdfIterations: pbkdfSalt != nil ? pbkdfIterations : nil
        )

        try? await store.save(state)
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
