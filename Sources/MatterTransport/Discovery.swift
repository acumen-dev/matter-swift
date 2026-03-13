// Discovery.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

/// Matter service types for mDNS/DNS-SD discovery.
public enum MatterServiceType: String, Sendable {
    /// Commissionable devices (not yet commissioned).
    case commissionable = "_matterc._udp"
    /// Operational devices (commissioned, ready for CASE).
    case operational = "_matter._tcp"
    /// Commissioner discovery.
    case commissioner = "_matterd._udp"
}

/// A discovered or advertised Matter service record.
public struct MatterServiceRecord: Sendable {
    public let name: String
    public let serviceType: MatterServiceType
    public let host: String
    public let port: UInt16
    public let txtRecords: [String: String]

    public init(
        name: String,
        serviceType: MatterServiceType,
        host: String,
        port: UInt16,
        txtRecords: [String: String] = [:]
    ) {
        self.name = name
        self.serviceType = serviceType
        self.host = host
        self.port = port
        self.txtRecords = txtRecords
    }
}

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

/// Platform-agnostic mDNS/DNS-SD discovery protocol.
///
/// Implementations provide platform-specific service discovery:
/// - `MatterApple`: `NWBrowser` / `NWListener`
/// - `MatterLinux`: avahi or built-in mDNS
public protocol MatterDiscovery: Sendable {
    /// Advertise a service on the local network.
    ///
    /// Multiple services can be advertised simultaneously (e.g., commissionable + operational).
    /// Each service is identified by its `name` — advertising a service with the same name
    /// replaces the previous advertisement.
    func advertise(service: MatterServiceRecord) async throws

    /// Browse for services of a given type.
    func browse(type: MatterServiceType) -> AsyncStream<MatterServiceRecord>

    /// Resolve a discovered service to a network address.
    func resolve(_ record: MatterServiceRecord) async throws -> MatterAddress

    /// Stop all advertisements.
    func stopAdvertising() async

    /// Stop advertising a specific service by name.
    func stopAdvertising(name: String) async
}

extension MatterDiscovery {
    /// Default implementation: stop all advertisements.
    public func stopAdvertising(name: String) async {
        await stopAdvertising()
    }
}
