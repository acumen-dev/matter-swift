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

/// Platform-agnostic mDNS/DNS-SD discovery protocol.
///
/// Implementations provide platform-specific service discovery:
/// - `MatterApple`: `NWBrowser` / `NWListener`
/// - `MatterLinux`: avahi or built-in mDNS
public protocol MatterDiscovery: Sendable {
    /// Advertise a service on the local network.
    func advertise(service: MatterServiceRecord) async throws

    /// Browse for services of a given type.
    func browse(type: MatterServiceType) -> AsyncStream<MatterServiceRecord>

    /// Resolve a discovered service to a network address.
    func resolve(_ record: MatterServiceRecord) async throws -> MatterAddress

    /// Stop advertising.
    func stopAdvertising() async
}
