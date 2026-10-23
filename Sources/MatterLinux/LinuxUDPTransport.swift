// LinuxUDPTransport.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTransport
import Logging

// MARK: - LinuxUDPTransport

/// Linux platform UDP transport over ``POSIXUDPSocketCore``: an `AF_INET6`
/// (`IPV6_V6ONLY`) and an `AF_INET` socket bound to the same port, with
/// `PKTINFO` on every send naming the interface and source address (the
/// pinned path, or the one the interface policy selects).
///
/// Not SwiftNIO: NIO reports packet info on receive but cannot set
/// `IPV6_PKTINFO` on a write.
///
/// ```swift
/// let transport = LinuxUDPTransport()
/// try await transport.bind(port: 5540)
///
/// for await (data, sender) in transport.receive() {
///     print("Received \(data.count) bytes from \(sender)")
/// }
/// ```
public actor LinuxUDPTransport: MatterUDPTransport {

    private let core: POSIXUDPSocketCore

    // MARK: - Init

    public init(logger: Logger = Logger(label: "matter.linux.udp")) {
        self.core = POSIXUDPSocketCore(logger: logger)
    }

    // MARK: - MatterUDPTransport

    public func bind(port: UInt16) async throws {
        try core.bind(port: port)
    }

    public func send(_ data: Data, to address: MatterAddress) async throws {
        _ = try core.send(data, to: address, via: nil)
    }

    public func send(_ data: Data, to address: MatterAddress, via path: MatterPath?) async throws -> MatterSendResult? {
        try core.send(data, to: address, via: path)
    }

    public func setInterfacePolicy(_ policy: InterfacePolicy) async {
        core.setPolicy(policy)
    }

    /// Returns the port the transport is currently bound to, or `nil` if not yet bound.
    public func boundPort() -> UInt16? {
        core.boundPort
    }

    public nonisolated func receive() -> AsyncStream<(Data, MatterAddress)> {
        core.datagrams.senderAndData()
    }

    public nonisolated func receiveDatagrams() -> AsyncStream<MatterDatagram> {
        core.datagrams
    }

    public func close() async {
        core.close()
    }
}
