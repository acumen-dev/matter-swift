// LinuxUDPTransport.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import NIOCore
import NIOPosix
import MatterTransport
import Logging

// MARK: - LinuxUDPTransport

/// Linux platform UDP transport using SwiftNIO's `DatagramBootstrap`.
///
/// Binds a single dual-stack UDP channel on `"::"` (all interfaces, IPv4+IPv6),
/// accepting both native IPv6 and IPv4-mapped addresses.
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

    // MARK: - State

    private let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    private var channel: Channel?
    private var receiveContinuation: AsyncStream<(Data, MatterAddress)>.Continuation?
    private let _receiveStream: AsyncStream<(Data, MatterAddress)>
    private let logger: Logger

    // MARK: - Init

    public init(logger: Logger = Logger(label: "matter.linux.udp")) {
        self.logger = logger
        let (stream, continuation) = AsyncStream<(Data, MatterAddress)>.makeStream()
        self._receiveStream = stream
        self.receiveContinuation = continuation
    }

    // MARK: - MatterUDPTransport

    public func bind(port: UInt16) async throws {
        guard let cont = receiveContinuation else {
            throw LinuxTransportError.notBound
        }

        let handler = MatterDatagramHandler(continuation: cont)
        let ch = try await DatagramBootstrap(group: group)
            .channelOption(.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(handler)
                }
            }
            .bind(host: "::", port: Int(port))
            .get()

        self.channel = ch
        logger.info("UDP transport bound on port \(port) (dual-stack IPv4/IPv6)")
    }

    public func send(_ data: Data, to address: MatterAddress) async throws {
        guard let ch = channel else { throw LinuxTransportError.notBound }
        guard let socketAddress = try? SocketAddress(ipAddress: address.host, port: Int(address.port)) else {
            throw LinuxTransportError.invalidAddress(address.host)
        }
        var buffer = ch.allocator.buffer(capacity: data.count)
        buffer.writeBytes(data)
        let envelope = AddressedEnvelope(remoteAddress: socketAddress, data: buffer)
        try await ch.writeAndFlush(envelope).get()
    }

    /// Returns the pre-created receive stream. `nonisolated` because `receive()` is
    /// not `async` in `MatterUDPTransport`; `_receiveStream` is a `let` set in `init`.
    public nonisolated func receive() -> AsyncStream<(Data, MatterAddress)> {
        _receiveStream
    }

    public func close() async {
        receiveContinuation?.finish()
        receiveContinuation = nil
        try? await channel?.close().get()
        channel = nil
        try? await group.shutdownGracefully()
    }
}

// MARK: - MatterDatagramHandler

private final class MatterDatagramHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>

    private let continuation: AsyncStream<(Data, MatterAddress)>.Continuation

    init(continuation: AsyncStream<(Data, MatterAddress)>.Continuation) {
        self.continuation = continuation
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var envelope = Self.unwrapInboundIn(data)
        let bytes = envelope.data.readBytes(length: envelope.data.readableBytes) ?? []
        let payload = Data(bytes)

        let host: String
        switch envelope.remoteAddress {
        case .v4(let v4): host = v4.host
        case .v6(let v6): host = v6.host
        case .unixDomainSocket: return
        }
        let port = UInt16(envelope.remoteAddress.port ?? 0)
        continuation.yield((payload, MatterAddress(host: host, port: port)))
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}

// MARK: - Errors

enum LinuxTransportError: Error {
    case notBound
    case invalidAddress(String)
}
