// BasicInformation.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes

/// Basic Information cluster (0x0028).
///
/// Provides core identity and versioning attributes for the node.
/// Required on endpoint 0 for all Matter devices.
public enum BasicInformationCluster {

    // MARK: - Cluster ID

    public static let id = ClusterID(rawValue: 0x0028)

    // MARK: - Attribute IDs

    public enum Attribute {
        /// Data model revision. UInt16 (read-only).
        public static let dataModelRevision     = AttributeID(rawValue: 0x0000)
        /// Vendor name. String (read-only, max 32 chars).
        public static let vendorName            = AttributeID(rawValue: 0x0001)
        /// Vendor ID. UInt16 (read-only).
        public static let vendorID              = AttributeID(rawValue: 0x0002)
        /// Product name. String (read-only, max 32 chars).
        public static let productName           = AttributeID(rawValue: 0x0003)
        /// Product ID. UInt16 (read-only).
        public static let productID             = AttributeID(rawValue: 0x0004)
        /// Node label. String (writable, max 32 chars).
        public static let nodeLabel             = AttributeID(rawValue: 0x0005)
        /// Location. String (writable, 2-char ISO 3166-1 code).
        public static let location              = AttributeID(rawValue: 0x0006)
        /// Hardware version. UInt16 (read-only).
        public static let hardwareVersion       = AttributeID(rawValue: 0x0007)
        /// Hardware version string. String (read-only, max 64 chars).
        public static let hardwareVersionString = AttributeID(rawValue: 0x0008)
        /// Software version. UInt32 (read-only).
        public static let softwareVersion       = AttributeID(rawValue: 0x0009)
        /// Software version string. String (read-only, max 64 chars).
        public static let softwareVersionString = AttributeID(rawValue: 0x000A)
        /// Serial number. String (read-only, max 32 chars).
        public static let serialNumber          = AttributeID(rawValue: 0x000F)
        /// Unique ID. String (read-only, max 32 chars).
        public static let uniqueID              = AttributeID(rawValue: 0x0012)
        /// Capability minima. Structure (read-only).
        public static let capabilityMinima      = AttributeID(rawValue: 0x0013)
    }

    // MARK: - Capability Minima

    /// CapabilityMinimaStruct — minimum supported capabilities.
    ///
    /// ```
    /// Structure {
    ///   0: caseSessionsPerFabric (unsigned int)
    ///   1: subscriptionsPerFabric (unsigned int)
    /// }
    /// ```
    public struct CapabilityMinima: Sendable, Equatable {

        public let caseSessionsPerFabric: UInt16
        public let subscriptionsPerFabric: UInt16

        public init(caseSessionsPerFabric: UInt16 = 3, subscriptionsPerFabric: UInt16 = 3) {
            self.caseSessionsPerFabric = caseSessionsPerFabric
            self.subscriptionsPerFabric = subscriptionsPerFabric
        }

        public func toTLVElement() -> TLVElement {
            .structure([
                .init(tag: .contextSpecific(0), value: .unsignedInt(UInt64(caseSessionsPerFabric))),
                .init(tag: .contextSpecific(1), value: .unsignedInt(UInt64(subscriptionsPerFabric)))
            ])
        }
    }
}
