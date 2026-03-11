// UDPTransport.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes

/// Network address for Matter communication.
public struct MatterAddress: Sendable, Hashable {
    public let host: String
    public let port: UInt16

    public init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }
}

/// Platform-agnostic UDP transport protocol.
///
/// Implementations provide platform-specific networking:
/// - `MatterApple`: `NWConnection` / `NWListener`
/// - `MatterLinux`: SwiftNIO `DatagramBootstrap`
public protocol MatterUDPTransport: Sendable {
    /// Send data to a specific address.
    func send(_ data: Data, to address: MatterAddress) async throws

    /// Receive incoming datagrams.
    func receive() -> AsyncStream<(Data, MatterAddress)>

    /// Bind to a local port for receiving.
    func bind(port: UInt16) async throws

    /// Close the transport.
    func close() async
}

import Foundation
