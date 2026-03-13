// CommissioningState.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import MatterTypes
import MatterModel
import MatterCrypto

/// Shared mutable state for the device-side commissioning flow.
///
/// Tracks fail-safe timer, staged credentials (RCAC, NOC, operational key),
/// and committed fabrics. Shared between `GeneralCommissioningHandler`,
/// `OperationalCredentialsHandler`, and `MatterDeviceServer`.
///
/// All mutations happen synchronously on the device server actor — no internal
/// locking needed. Marked `@unchecked Sendable` because it is owned by the
/// `MatterDeviceServer` actor and only mutated within that actor's context.
public final class CommissioningState: @unchecked Sendable {

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

    // MARK: - Committed Fabrics

    /// Committed fabrics on this device.
    public private(set) var fabrics: [FabricIndex: CommittedFabric] = [:]

    /// Next fabric index to assign.
    private var nextFabricIndex: UInt8 = 1

    // MARK: - ACLs

    /// Staged ACL entries — pending CommissioningComplete.
    public var stagedACLs: [AccessControlCluster.AccessControlEntry] = []

    /// Committed ACL entries per fabric.
    public private(set) var committedACLs: [FabricIndex: [AccessControlCluster.AccessControlEntry]] = [:]

    // MARK: - Persistence

    /// Optional fabric store for persisting committed state across restarts.
    private let fabricStore: (any MatterFabricStore)?

    // MARK: - Callbacks

    /// Called when commissioning completes with fabric info for CASE session setup.
    public var onCommissioningComplete: ((CommittedFabric) -> Void)?

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
        clearStagedState()
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

        // Commit staged ACLs
        if !stagedACLs.isEmpty {
            committedACLs[fabricIndex] = stagedACLs
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
            nextFabricIndex: nextFabricIndex
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
            noc: noc,
            operationalKey: operationalKey
        )
    }
}
