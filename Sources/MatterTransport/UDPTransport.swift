// UDPTransport.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes
import MDNSCore

/// Network address for Matter communication.
///
/// Matter-specific alias for `NetworkAddress` from MDNSCore.
public typealias MatterAddress = NetworkAddress

/// Platform-agnostic UDP transport protocol.
///
/// Implementations provide platform-specific networking:
/// - `MatterApple` and `MatterLinux`: ``POSIXUDPSocketCore`` (one socket per
///   address family, `PKTINFO` on every send)
///
/// The path-aware requirements (``receiveDatagrams()``,
/// ``send(_:to:via:)``, ``setInterfacePolicy(_:)``) have defaults, so a
/// transport that cannot tell or choose its path need not implement them.
public protocol MatterUDPTransport: Sendable {
    /// Send data to a specific address.
    func send(_ data: Data, to address: MatterAddress) async throws

    /// Receive incoming datagrams.
    func receive() -> AsyncStream<(Data, MatterAddress)>

    /// Bind to a local port for receiving.
    func bind(port: UInt16) async throws

    /// Close the transport.
    func close() async

    /// Receive incoming datagrams with the path each arrived on.
    func receiveDatagrams() -> AsyncStream<MatterDatagram>

    /// Send data to `address` by `path`, or, when `path` is nil, by the path
    /// the interface policy selects. Returns the path used, or nil when the
    /// transport cannot tell.
    func send(_ data: Data, to address: MatterAddress, via path: MatterPath?) async throws -> MatterSendResult?

    /// Set the policy that path selection follows.
    func setInterfacePolicy(_ policy: InterfacePolicy) async
}

extension MatterUDPTransport {
    /// ``receive()`` with no path (nil).
    public func receiveDatagrams() -> AsyncStream<MatterDatagram> {
        let datagrams = receive()
        return AsyncStream { continuation in
            let pump = Task {
                for await (data, sender) in datagrams {
                    continuation.yield(MatterDatagram(data: data, sender: sender, path: nil))
                }
                continuation.finish()
            }
            continuation.onTermination = { _ in pump.cancel() }
        }
    }

    /// ``send(_:to:)``, ignoring `path`; returns nil.
    public func send(_ data: Data, to address: MatterAddress, via path: MatterPath?) async throws -> MatterSendResult? {
        try await send(data, to: address)
        return nil
    }

    /// No-op: the transport does not choose its path.
    public func setInterfacePolicy(_ policy: InterfacePolicy) async {}
}

/// Errors from the POSIX socket transports.
public enum TransportError: Error, Sendable, Equatable {
    case socketCreationFailed
    case bindFailed(Int32)
    case sendFailed(Int32)
    case notBound
    case invalidAddress(String)
}

import Foundation
