// NWEndpoint+MatterAddress.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(Network)
import Foundation
import Network
import MatterTransport

// MARK: - MatterAddress ↔ NWEndpoint Conversion

extension MatterAddress {

    /// Create a `MatterAddress` from an `NWEndpoint`.
    ///
    /// Only `.hostPort` endpoints are supported — returns `nil` for
    /// `.service`, `.unix`, `.url`, or other endpoint types.
    public init?(endpoint: NWEndpoint) {
        guard case .hostPort(let host, let port) = endpoint else {
            return nil
        }
        let hostString: String
        switch host {
        case .ipv4(let addr):
            hostString = "\(addr)"
        case .ipv6(let addr):
            hostString = "\(addr)"
        case .name(let name, _):
            hostString = name
        @unknown default:
            return nil
        }
        self.init(host: hostString, port: port.rawValue)
    }
}

extension NWEndpoint {

    /// Create an `NWEndpoint.hostPort` from a `MatterAddress`.
    public static func hostPort(from address: MatterAddress) -> NWEndpoint {
        .hostPort(host: NWEndpoint.Host(address.host), port: NWEndpoint.Port(rawValue: address.port)!)
    }
}
#endif
