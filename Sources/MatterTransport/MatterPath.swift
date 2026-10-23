// MatterPath.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MDNSCore

/// A local network path: the interface and source address a datagram leaves from
/// or arrived on.
public struct MatterPath: Sendable, Hashable, CustomStringConvertible {
    public var interfaceIndex: UInt32
    public var interfaceName: String
    /// Canonical literal, no zone.
    public var localAddress: String

    public init(interfaceIndex: UInt32, interfaceName: String, localAddress: String) {
        self.interfaceIndex = interfaceIndex
        self.interfaceName = interfaceName
        self.localAddress = localAddress
    }

    public var description: String { "\(interfaceName)/\(localAddress)" }
}

/// A received datagram with the path it arrived on.
public struct MatterDatagram: Sendable {
    public var data: Data
    public var sender: MatterAddress
    /// nil when the transport cannot tell.
    public var path: MatterPath?

    public init(data: Data, sender: MatterAddress, path: MatterPath?) {
        self.data = data
        self.sender = sender
        self.path = path
    }
}

/// How a send chose its path.
public enum PathSelectionOutcome: String, Sendable {
    case preferred, `fallthrough`, routeTable = "route_table"
}

/// The path a send used.
public struct MatterSendResult: Sendable, Equatable {
    public var path: MatterPath
    /// Set when this send selected the path (no `via`); nil when it used a pinned one.
    public var selection: PathSelectionOutcome?

    public init(path: MatterPath, selection: PathSelectionOutcome?) {
        self.path = path
        self.selection = selection
    }
}

public enum TransportPathError: Error, Sendable, Equatable {
    /// A pinned path can no longer reach the peer (EHOSTUNREACH, ENETUNREACH, EADDRNOTAVAIL).
    case pathUnavailable(MatterPath, errno: Int32)
    /// No allowed interface has a route to the peer.
    case noAllowedRoute(peer: MatterAddress)
}
