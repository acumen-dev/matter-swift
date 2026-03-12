// Descriptor.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes

/// Descriptor cluster (0x001D).
///
/// Every endpoint has a Descriptor cluster that lists its device types,
/// server clusters, client clusters, and parts (children). This is mandatory
/// on all Matter endpoints and is always read-only.
public enum DescriptorCluster {

    // MARK: - Attribute IDs

    public enum Attribute {
        /// List of device types on this endpoint. Array of DeviceTypeStruct.
        public static let deviceTypeList = AttributeID(rawValue: 0x0000)
        /// List of server-side cluster IDs. Array of cluster-id.
        public static let serverList     = AttributeID(rawValue: 0x0001)
        /// List of client-side cluster IDs. Array of cluster-id.
        public static let clientList     = AttributeID(rawValue: 0x0002)
        /// List of child endpoint IDs. Array of endpoint-no.
        public static let partsList      = AttributeID(rawValue: 0x0003)
    }

    // MARK: - DeviceTypeStruct

    /// DeviceTypeStruct — describes a device type on an endpoint.
    ///
    /// ```
    /// Structure {
    ///   0: deviceType (uint32)
    ///   1: revision (uint16)
    /// }
    /// ```
    public struct DeviceTypeStruct: Sendable, Equatable {

        private enum Tag {
            static let deviceType: UInt8 = 0
            static let revision: UInt8 = 1
        }

        public let deviceType: DeviceTypeID
        public let revision: UInt16

        public init(deviceType: DeviceTypeID, revision: UInt16) {
            self.deviceType = deviceType
            self.revision = revision
        }

        public func toTLVElement() -> TLVElement {
            .structure([
                .init(tag: .contextSpecific(Tag.deviceType), value: .unsignedInt(UInt64(deviceType.rawValue))),
                .init(tag: .contextSpecific(Tag.revision), value: .unsignedInt(UInt64(revision)))
            ])
        }

        public static func fromTLVElement(_ element: TLVElement) throws -> DeviceTypeStruct {
            guard case .structure(let fields) = element else {
                throw DescriptorError.invalidStructure
            }
            guard let dt = fields.first(where: { $0.tag == .contextSpecific(Tag.deviceType) })?.value.uintValue,
                  let rev = fields.first(where: { $0.tag == .contextSpecific(Tag.revision) })?.value.uintValue else {
                throw DescriptorError.missingField
            }
            return DeviceTypeStruct(
                deviceType: DeviceTypeID(rawValue: UInt32(dt)),
                revision: UInt16(rev)
            )
        }
    }

    // MARK: - Errors

    public enum DescriptorError: Error, Sendable {
        case invalidStructure
        case missingField
    }
}
