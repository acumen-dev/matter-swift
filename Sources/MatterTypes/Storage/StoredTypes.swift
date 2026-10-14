// StoredTypes.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

// MARK: - Device-Side State

/// Complete device-side persisted state.
///
/// Contains all committed fabrics, ACLs, and the next fabric index counter.
/// Staged credentials (pending CommissioningComplete) are NOT persisted — they
/// are transient and cleared on restart.
public struct StoredDeviceState: Codable, Sendable, Equatable {

    /// Committed fabrics on this device.
    public var fabrics: [StoredFabric]

    /// Access control entries per fabric.
    public var acls: [StoredFabricACLs]

    /// Next fabric index to assign (incremented on each commissioning).
    public var nextFabricIndex: UInt8

    /// PBKDF2 salt for PASE commissioning.
    ///
    /// Persisted so the same salt is used across restarts. Controllers (e.g. Apple Home)
    /// that cache PBKDF parameters send `hasPBKDFParameters = true` on retry — the server
    /// must use the same salt, or SPAKE2+ will fail.
    public var pbkdfSalt: Data?

    /// PBKDF2 iteration count used together with `pbkdfSalt`.
    public var pbkdfIterations: Int?

    public init(
        fabrics: [StoredFabric] = [],
        acls: [StoredFabricACLs] = [],
        nextFabricIndex: UInt8 = 1,
        pbkdfSalt: Data? = nil,
        pbkdfIterations: Int? = nil
    ) {
        self.fabrics = fabrics
        self.acls = acls
        self.nextFabricIndex = nextFabricIndex
        self.pbkdfSalt = pbkdfSalt
        self.pbkdfIterations = pbkdfIterations
    }
}

/// A committed fabric serialized for persistence.
///
/// Certificates are stored as TLV-encoded `Data` (using the existing
/// `MatterCertificate.tlvEncode()` / `.fromTLV()` roundtrip). The operational
/// private key is stored as its 32-byte raw representation.
public struct StoredFabric: Codable, Sendable, Equatable {

    /// Local fabric index.
    public let fabricIndex: UInt8

    /// TLV-encoded Node Operational Certificate.
    public let nocTLV: Data

    /// TLV-encoded Intermediate CA Certificate (optional).
    public let icacTLV: Data?

    /// TLV-encoded Root CA Certificate.
    public let rcacTLV: Data

    /// P-256 operational private key raw representation (32 bytes).
    public let operationalKeyRaw: Data

    /// IPK epoch key value.
    public let ipkEpochKey: Data

    /// CASE admin subject (controller node ID).
    public let caseAdminSubject: UInt64

    /// Admin vendor ID.
    public let adminVendorId: UInt16

    public init(
        fabricIndex: UInt8,
        nocTLV: Data,
        icacTLV: Data?,
        rcacTLV: Data,
        operationalKeyRaw: Data,
        ipkEpochKey: Data,
        caseAdminSubject: UInt64,
        adminVendorId: UInt16
    ) {
        self.fabricIndex = fabricIndex
        self.nocTLV = nocTLV
        self.icacTLV = icacTLV
        self.rcacTLV = rcacTLV
        self.operationalKeyRaw = operationalKeyRaw
        self.ipkEpochKey = ipkEpochKey
        self.caseAdminSubject = caseAdminSubject
        self.adminVendorId = adminVendorId
    }
}

/// ACL entries for a single fabric, serialized for persistence.
public struct StoredFabricACLs: Codable, Sendable, Equatable {

    /// Fabric index these ACLs belong to.
    public let fabricIndex: UInt8

    /// The ACL entries for this fabric.
    public let entries: [StoredACLEntry]

    public init(fabricIndex: UInt8, entries: [StoredACLEntry]) {
        self.fabricIndex = fabricIndex
        self.entries = entries
    }
}

/// A single access control entry serialized for persistence.
///
/// Uses raw integer values for privilege and auth mode to avoid depending
/// on MatterModel types from MatterTypes.
public struct StoredACLEntry: Codable, Sendable, Equatable {

    /// Privilege level (raw value of `AccessControlCluster.Privilege`).
    public let privilege: UInt8

    /// Authentication mode (raw value of `AccessControlCluster.AuthMode`).
    public let authMode: UInt8

    /// Authorized subjects (node IDs, group IDs).
    public let subjects: [UInt64]

    /// Optional access targets.
    public let targets: [StoredACLTarget]?

    /// Fabric index this entry belongs to.
    public let fabricIndex: UInt8

    public init(
        privilege: UInt8,
        authMode: UInt8,
        subjects: [UInt64],
        targets: [StoredACLTarget]?,
        fabricIndex: UInt8
    ) {
        self.privilege = privilege
        self.authMode = authMode
        self.subjects = subjects
        self.targets = targets
        self.fabricIndex = fabricIndex
    }
}

/// An ACL target (cluster/endpoint/device type triple) serialized for persistence.
public struct StoredACLTarget: Codable, Sendable, Equatable {

    /// Cluster ID (optional).
    public let cluster: UInt32?

    /// Endpoint ID (optional).
    public let endpoint: UInt16?

    /// Device type ID (optional).
    public let deviceType: UInt32?

    public init(cluster: UInt32?, endpoint: UInt16?, deviceType: UInt32?) {
        self.cluster = cluster
        self.endpoint = endpoint
        self.deviceType = deviceType
    }
}

// MARK: - Controller-Side State

/// Complete controller-side persisted state.
///
/// Contains the controller's fabric identity (root CA key, certificates),
/// the commissioned device registry, and the node ID allocation counter.
public struct StoredControllerState: Codable, Sendable, Equatable {

    /// The schema version this library writes.
    ///
    /// Version 1 is the layout before device attestation records; it has no
    /// `schemaVersion` key. Version 2 adds `StoredCommissionedDevice.attestation`.
    /// Bump it whenever a change would make an older library drop or misread data:
    /// a new field, and also a new case of any enumeration whose raw value is stored here
    /// (for example `AttestationFailureReason`, stored as an override's `reason`).
    ///
    /// Releases up to and including 1.0.0-beta.5 have no version check: they load a
    /// version 2 file and silently drop `schemaVersion` and the attestation records on
    /// their next save. Do not run an older library against state a newer one wrote.
    public static let currentSchemaVersion = 2

    /// The schema version this state was decoded with (a blob with no `schemaVersion` key is
    /// version 1). Encoding always writes ``currentSchemaVersion``.
    public private(set) var schemaVersion: Int

    /// Controller's fabric identity and root CA key.
    public var identity: StoredControllerIdentity

    /// Commissioned devices known to this controller.
    public var devices: [StoredCommissionedDevice]

    /// Next node ID to allocate for new devices.
    public var nextNodeID: UInt64

    public init(
        identity: StoredControllerIdentity,
        devices: [StoredCommissionedDevice] = [],
        nextNodeID: UInt64
    ) {
        self.schemaVersion = Self.currentSchemaVersion
        self.identity = identity
        self.devices = devices
        self.nextNodeID = nextNodeID
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion, identity, devices, nextNodeID
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(Self.currentSchemaVersion, forKey: .schemaVersion)
        try container.encode(identity, forKey: .identity)
        try container.encode(devices, forKey: .devices)
        try container.encode(nextNodeID, forKey: .nextNodeID)
    }

    /// Decodes a state, treating a missing `schemaVersion` as 1.
    ///
    /// - Throws: `DecodingError.dataCorrupted` if `schemaVersion` is greater than
    ///   ``currentSchemaVersion``. An older library must not load newer state and
    ///   then save it back with the fields it does not know missing.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let version = try container.decodeIfPresent(Int.self, forKey: .schemaVersion) ?? 1
        guard version <= Self.currentSchemaVersion else {
            throw DecodingError.dataCorruptedError(
                forKey: .schemaVersion, in: container,
                debugDescription: "controller state has schemaVersion \(version); this library "
                    + "understands up to \(Self.currentSchemaVersion). Update the library "
                    + "rather than load and re-save state it would truncate.")
        }
        guard version >= 1 else {
            throw DecodingError.dataCorruptedError(
                forKey: .schemaVersion, in: container,
                debugDescription: "controller state has invalid schemaVersion \(version)")
        }
        self.schemaVersion = version
        self.identity = try container.decode(StoredControllerIdentity.self, forKey: .identity)
        self.devices = try container.decode([StoredCommissionedDevice].self, forKey: .devices)
        self.nextNodeID = try container.decode(UInt64.self, forKey: .nextNodeID)
    }
}

/// Controller fabric identity serialized for persistence.
///
/// Contains the root CA key, controller certificates, and fabric metadata.
/// Private keys are stored as 32-byte raw representations.
public struct StoredControllerIdentity: Codable, Sendable, Equatable {

    /// Root CA private key raw representation (32 bytes).
    public let rootKeyRaw: Data

    /// Local fabric index.
    public let fabricIndex: UInt8

    /// Fabric identifier.
    public let fabricID: UInt64

    /// Controller's operational node ID.
    public let controllerNodeID: UInt64

    /// TLV-encoded Root CA Certificate.
    public let rcacTLV: Data

    /// TLV-encoded Node Operational Certificate.
    public let nocTLV: Data

    /// Controller's operational private key raw representation (32 bytes).
    public let operationalKeyRaw: Data

    /// Vendor ID for NOC issuance.
    public let vendorID: UInt16

    /// IPK epoch key value.
    public let ipkEpochKey: Data

    public init(
        rootKeyRaw: Data,
        fabricIndex: UInt8,
        fabricID: UInt64,
        controllerNodeID: UInt64,
        rcacTLV: Data,
        nocTLV: Data,
        operationalKeyRaw: Data,
        vendorID: UInt16,
        ipkEpochKey: Data
    ) {
        self.rootKeyRaw = rootKeyRaw
        self.fabricIndex = fabricIndex
        self.fabricID = fabricID
        self.controllerNodeID = controllerNodeID
        self.rcacTLV = rcacTLV
        self.nocTLV = nocTLV
        self.operationalKeyRaw = operationalKeyRaw
        self.vendorID = vendorID
        self.ipkEpochKey = ipkEpochKey
    }
}

/// A commissioned device serialized for persistence.
///
/// Mirrors `CommissionedDevice` using raw values to avoid a dependency
/// from MatterTypes on MatterController.
public struct StoredCommissionedDevice: Codable, Sendable, Equatable {

    /// Device's operational node ID.
    public let nodeID: UInt64

    /// Fabric index the device belongs to.
    public let fabricIndex: UInt8

    /// Vendor ID (optional).
    public let vendorID: UInt16?

    /// Product ID (optional).
    public let productID: UInt16?

    /// Operational host address (optional).
    public var operationalHost: String?

    /// Operational port (optional).
    public var operationalPort: UInt16?

    /// Human-readable label (optional).
    public var label: String?

    /// When this device was commissioned.
    public let commissionedAt: Date

    /// Advertised MRP session idle interval (SII) in milliseconds, if known.
    public var mrpIdleIntervalMs: UInt32?

    /// Advertised MRP session active interval (SAI) in milliseconds, if known.
    public var mrpActiveIntervalMs: UInt32?

    /// Advertised MRP session active threshold (SAT) in milliseconds, if known.
    public var mrpActiveThresholdMs: UInt32?

    /// How the device passed (or was approved past) attestation at commissioning.
    /// `nil` for devices commissioned before attestation was recorded.
    public var attestation: StoredAttestationRecord?

    public init(
        nodeID: UInt64,
        fabricIndex: UInt8,
        vendorID: UInt16?,
        productID: UInt16?,
        operationalHost: String?,
        operationalPort: UInt16?,
        label: String?,
        commissionedAt: Date,
        mrpIdleIntervalMs: UInt32? = nil,
        mrpActiveIntervalMs: UInt32? = nil,
        mrpActiveThresholdMs: UInt32? = nil,
        attestation: StoredAttestationRecord? = nil
    ) {
        self.nodeID = nodeID
        self.fabricIndex = fabricIndex
        self.vendorID = vendorID
        self.productID = productID
        self.operationalHost = operationalHost
        self.operationalPort = operationalPort
        self.label = label
        self.commissionedAt = commissionedAt
        self.mrpIdleIntervalMs = mrpIdleIntervalMs
        self.mrpActiveIntervalMs = mrpActiveIntervalMs
        self.mrpActiveThresholdMs = mrpActiveThresholdMs
        self.attestation = attestation
    }
}

// MARK: - Attribute State

/// Complete attribute data for persistence.
///
/// Keyed by endpoint/cluster pair, containing TLV-encoded attribute values
/// and cluster data versions.
public struct StoredAttributeData: Codable, Sendable, Equatable {

    /// Attribute data per cluster, keyed by endpoint+cluster pair.
    public var clusters: [StoredClusterKey: StoredClusterData]

    public init(clusters: [StoredClusterKey: StoredClusterData] = [:]) {
        self.clusters = clusters
    }
}

/// Key for a cluster instance (endpoint + cluster ID pair).
public struct StoredClusterKey: Codable, Sendable, Equatable, Hashable {

    /// Endpoint ID.
    public let endpointID: UInt16

    /// Cluster ID.
    public let clusterID: UInt32

    public init(endpointID: UInt16, clusterID: UInt32) {
        self.endpointID = endpointID
        self.clusterID = clusterID
    }
}

/// Persisted data for a single cluster instance.
///
/// Attribute values are stored as TLV-encoded byte blobs (via `TLVEncoder.encode()`).
/// The data version is preserved so subscription clients can detect changes after restart.
public struct StoredClusterData: Codable, Sendable, Equatable {

    /// Cluster data version.
    public let dataVersion: UInt32

    /// Attribute values keyed by attribute ID, TLV-encoded.
    public var attributes: [UInt32: Data]

    public init(dataVersion: UInt32, attributes: [UInt32: Data] = [:]) {
        self.dataVersion = dataVersion
        self.attributes = attributes
    }
}
