// Discovery.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
@_exported import MDNSCore

// MARK: - Type Aliases

/// Platform-agnostic mDNS/DNS-SD discovery protocol.
///
/// Matter-specific alias for `ServiceDiscovery` from MDNSCore.
/// Platform implementations (`MatterApple`, `MatterLinux`) are provided via
/// `AppleServiceDiscovery` and `LinuxServiceDiscovery` from the shared
/// `mdns-swift` package, re-exported as `AppleDiscovery` and `LinuxDiscovery`.
public typealias MatterDiscovery = ServiceDiscovery

/// A discovered or advertised Matter service record.
///
/// Matter-specific alias for `ServiceRecord` from MDNSCore.
public typealias MatterServiceRecord = ServiceRecord

// MARK: - Matter Service Types

/// Matter service types for mDNS/DNS-SD discovery.
public enum MatterServiceType: String, Sendable {
    /// Commissionable devices (not yet commissioned).
    case commissionable = "_matterc._udp"
    /// Operational devices (commissioned, ready for CASE).
    case operational = "_matter._tcp"
    /// Commissioner discovery.
    case commissioner = "_matterd._udp"
}

// MARK: - ServiceType Extensions

extension ServiceType {
    /// Matter commissionable discovery: `_matterc._udp`
    public static let commissionable: ServiceType = "_matterc._udp"
    /// Matter operational discovery: `_matter._tcp`
    public static let operational: ServiceType = "_matter._tcp"
    /// Matter commissioner discovery: `_matterd._udp`
    public static let commissioner: ServiceType = "_matterd._udp"
}

// MARK: - MatterDiscovery Convenience Extension

extension ServiceDiscovery {
    /// Browse by `MatterServiceType` — convenience wrapper over `browse(serviceType:)`.
    public func browse(type: MatterServiceType) -> AsyncStream<ServiceRecord> {
        browse(serviceType: ServiceType(rawValue: type.rawValue))
    }
}

// MARK: - OperationalInstanceName

/// Operational instance name for DNS-SD advertisement.
///
/// Per Matter Core Spec §4.3.1, operational devices are advertised as:
/// - Service type: `_matter._tcp`
/// - Instance name: `<CompressedFabricID>-<NodeID>` (16 hex chars each, uppercase)
/// - Fabric subtype: `_I<CompressedFabricID>._sub._matter._tcp`
///
/// ```swift
/// let name = OperationalInstanceName(compressedFabricID: cfid, nodeID: 42)
/// print(name.instanceName)    // "0000000000001234-000000000000002A"
/// print(name.fabricSubtype)   // "_I0000000000001234._sub._matter._tcp"
/// ```
public struct OperationalInstanceName: Sendable, Equatable {

    /// The compressed fabric identifier (8-byte HMAC-derived).
    public let compressedFabricID: UInt64

    /// The node's operational ID within the fabric.
    public let nodeID: UInt64

    public init(compressedFabricID: UInt64, nodeID: UInt64) {
        self.compressedFabricID = compressedFabricID
        self.nodeID = nodeID
    }

    /// The DNS-SD instance name: `<CompressedFabricID>-<NodeID>` (16 uppercase hex chars each).
    public var instanceName: String {
        String(format: "%016llX-%016llX", compressedFabricID, nodeID)
    }

    /// The fabric subtype for scoped browsing: `_I<CompressedFabricID>._sub._matter._tcp`.
    public var fabricSubtype: String {
        String(format: "_I%016llX._sub._matter._tcp", compressedFabricID)
    }

    /// Parse an instance name back into components.
    ///
    /// - Parameter name: A string in the format `<16 hex>-<16 hex>`.
    /// - Returns: An `OperationalInstanceName` if parsing succeeds, nil otherwise.
    public static func parse(_ name: String) -> OperationalInstanceName? {
        let parts = name.split(separator: "-")
        guard parts.count == 2,
              parts[0].count == 16,
              parts[1].count == 16,
              let cfid = UInt64(parts[0], radix: 16),
              let nid = UInt64(parts[1], radix: 16) else {
            return nil
        }
        return OperationalInstanceName(compressedFabricID: cfid, nodeID: nid)
    }
}
