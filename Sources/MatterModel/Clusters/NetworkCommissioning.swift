// NetworkCommissioning.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

/// Network Commissioning cluster (0x0031).
///
/// Manages network interface configuration. Required on root endpoint (endpoint 0)
/// for all Matter devices. For a bridge running on Ethernet, advertise the Ethernet
/// feature flag and expose the interface list.
public enum NetworkCommissioningCluster {

    // MARK: - Cluster ID

    public static let id = ClusterID(rawValue: 0x0031)

    // MARK: - Attribute IDs

    public enum Attribute {
        public static let maxNetworks             = AttributeID(rawValue: 0x0000)
        public static let networks                = AttributeID(rawValue: 0x0001)
        public static let interfaceEnabled        = AttributeID(rawValue: 0x0004)
        public static let lastNetworkingStatus    = AttributeID(rawValue: 0x0005)
        public static let lastNetworkID           = AttributeID(rawValue: 0x0006)
        public static let lastConnectErrorValue   = AttributeID(rawValue: 0x0007)
        public static let featureMap              = AttributeID(rawValue: 0xFFFC)
        public static let clusterRevision         = AttributeID(rawValue: 0xFFFD)
    }

    // MARK: - Feature Flags

    public enum Feature {
        public static let wifi: UInt32     = 0x01
        public static let thread: UInt32   = 0x02
        public static let ethernet: UInt32 = 0x04
    }

    // MARK: - NetworkInfoStruct

    /// A network entry in the `networks` attribute.
    ///
    /// ```
    /// Structure {
    ///   0: networkID (octet string)
    ///   1: connected (bool)
    /// }
    /// ```
    public struct NetworkInfoStruct: Sendable, Equatable {
        public let networkID: Data
        public let connected: Bool

        public init(networkID: Data, connected: Bool) {
            self.networkID = networkID
            self.connected = connected
        }

        public func toTLVElement() -> TLVElement {
            .structure([
                .init(tag: .contextSpecific(0), value: .octetString(networkID)),
                .init(tag: .contextSpecific(1), value: .bool(connected))
            ])
        }

        public static func fromTLVElement(_ element: TLVElement) throws -> NetworkInfoStruct {
            guard case .structure(let fields) = element else {
                throw NetworkCommissioningError.invalidStructure
            }
            guard let idData = fields.first(where: { $0.tag == .contextSpecific(0) })?.value.dataValue else {
                throw NetworkCommissioningError.missingField
            }
            let connected = fields.first(where: { $0.tag == .contextSpecific(1) })?.value.boolValue ?? false
            return NetworkInfoStruct(networkID: idData, connected: connected)
        }
    }

    // MARK: - Errors

    public enum NetworkCommissioningError: Error, Sendable {
        case invalidStructure
        case missingField
    }
}
