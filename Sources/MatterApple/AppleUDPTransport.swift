// AppleUDPTransport.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(Network)
import Foundation
import MatterTransport
import Logging

/// Apple platform UDP transport using two POSIX sockets (one IPv6, one IPv4)
/// for both receive and send, through ``POSIXUDPSocketCore``.
///
/// ## Why two sockets?
///
/// During PASE (commissioning password exchange) Apple Home connects via
/// IPv6 link-local (fe80::). During CASE (operational session) Apple resolves
/// the device's SRV hostname, which resolves to an IPv4 address on most home
/// networks. A single `IPV6_V6ONLY=1` socket cannot receive IPv4 UDP, so
/// CASE Sigma1 is silently dropped and commissioning never completes.
///
/// Two sockets on the same port sidestep this: `AF_INET6 / IPV6_V6ONLY=1`
/// handles all IPv6 traffic, `AF_INET` handles all IPv4 traffic. Both receive
/// loops feed the same `AsyncStream` so callers see a unified packet stream.
///
/// ## Why POSIX instead of Network.framework?
///
/// Network.framework has two fatal issues for this use-case on macOS:
///
/// - **NWListener-derived sends**: `contentProcessed` fires with no error but
///   the kernel silently drops the datagram (confirmed macOS bug).
/// - **Fresh outbound `NWConnection`**: requires Local Network Access (TCC)
///   permission. CLI tools never trigger the OS prompt — the connection is
///   cancelled immediately without any user-visible dialog.
///
/// POSIX `recvmsg` / `sendmsg` bypass TCC entirely.
///
/// ## Ports and paths
///
/// One socket per address family, both bound to the requested port (the IPv4
/// one to the port the IPv6 one got, when it is 0). Every send carries
/// `PKTINFO` naming the interface and source address — the pinned path, or
/// the one the interface policy selects — and link-local destinations take
/// their interface the same way. Measured on macOS 27: `PKTINFO` on a bound
/// socket keeps the bound source port, which the commissioning controller
/// (iPhone) requires, since it drops any response whose source port differs.
public actor AppleUDPTransport: MatterUDPTransport {

    private let core: POSIXUDPSocketCore

    // MARK: - Init

    public init(logger: Logger = Logger(label: "matter.apple.udp")) {
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

    public nonisolated func receive() -> AsyncStream<(Data, MatterAddress)> {
        core.datagrams.senderAndData()
    }

    public nonisolated func receiveDatagrams() -> AsyncStream<MatterDatagram> {
        core.datagrams
    }

    public func boundPort() -> UInt16? {
        core.boundPort
    }

    public func close() async {
        core.close()
    }
}
#endif
