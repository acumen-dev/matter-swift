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

    public init(
        fabrics: [StoredFabric] = [],
        acls: [StoredFabricACLs] = [],
        nextFabricIndex: UInt8 = 1
    ) {
        self.fabrics = fabrics
        self.acls = acls
        self.nextFabricIndex = nextFabricIndex
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
        self.identity = identity
        self.devices = devices
        self.nextNodeID = nextNodeID
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

    public init(
        nodeID: UInt64,
        fabricIndex: UInt8,
        vendorID: UInt16?,
        productID: UInt16?,
        operationalHost: String?,
        operationalPort: UInt16?,
        label: String?,
        commissionedAt: Date
    ) {
        self.nodeID = nodeID
        self.fabricIndex = fabricIndex
        self.vendorID = vendorID
        self.productID = productID
        self.operationalHost = operationalHost
        self.operationalPort = operationalPort
        self.label = label
        self.commissionedAt = commissionedAt
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
