// AppleUDPTransport.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTransport
import Logging

/// Apple platform UDP transport using a dual-stack POSIX socket.
///
/// Binds a single `AF_INET6` socket with `IPV6_V6ONLY = 0`, accepting both
/// IPv4 (presented as IPv4-mapped `::ffff:a.b.c.d`) and native IPv6
/// addresses including link-local `fe80::` addresses with scope IDs.
///
/// The receive loop runs on a dedicated `DispatchQueue` to avoid blocking
/// the Swift cooperative thread pool. The DispatchQueue closure captures only
/// value-type locals (socket fd, stream continuation) so it never re-enters
/// the actor — eliminating data races entirely.
///
/// ```swift
/// let transport = AppleUDPTransport()
/// try await transport.bind(port: 5540)
///
/// // Receive loop
/// for await (data, sender) in transport.receive() {
///     print("Received \(data.count) bytes from \(sender)")
/// }
/// ```
public actor AppleUDPTransport: MatterUDPTransport {

    // MARK: - State

    private let receiveQueue = DispatchQueue(label: "matter.udp.receive", qos: .userInitiated)
    private var fd: Int32 = -1
    private var receiveContinuation: AsyncStream<(Data, MatterAddress)>.Continuation?
    /// Pre-created stream returned by `receive()`. Stored as `let` so it can
    /// be accessed from `nonisolated` context without awaiting the actor.
    private let _receiveStream: AsyncStream<(Data, MatterAddress)>
    private let logger: Logger

    // MARK: - Init

    public init(logger: Logger = Logger(label: "matter.apple.udp")) {
        self.logger = logger
        let (stream, continuation) = AsyncStream<(Data, MatterAddress)>.makeStream()
        self._receiveStream = stream
        self.receiveContinuation = continuation
    }

    // MARK: - MatterUDPTransport

    public func bind(port: UInt16) async throws {
        let socketFD = socket(AF_INET6, SOCK_DGRAM, 0)
        guard socketFD >= 0 else {
            throw TransportError.socketCreationFailed
        }

        var one: Int32 = 1
        var zero: Int32 = 0
        setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(socketFD, SOL_SOCKET, SO_REUSEPORT, &one, socklen_t(MemoryLayout<Int32>.size))
        // Dual-stack: accept both IPv4-mapped and native IPv6 on one socket.
        setsockopt(socketFD, IPPROTO_IPV6, IPV6_V6ONLY, &zero, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in6()
        addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        addr.sin6_family = sa_family_t(AF_INET6)
        addr.sin6_port = port.bigEndian
        addr.sin6_addr = in6addr_any

        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.bind(socketFD, sockPtr, socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        }
        guard bindResult == 0 else {
            Darwin.close(socketFD)
            throw TransportError.bindFailed(errno)
        }

        self.fd = socketFD
        logger.info("UDP transport bound on port \(port) (dual-stack IPv4/IPv6)")
        startReceiveLoop()
    }

    public func send(_ data: Data, to address: MatterAddress) async throws {
        guard fd >= 0 else { throw TransportError.notBound }
        guard var destAddr = sockAddr6(host: address.host, port: address.port) else {
            throw TransportError.invalidAddress(address.host)
        }

        let socketFD = fd
        let sent = data.withUnsafeBytes { buffer in
            withUnsafePointer(to: &destAddr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    sendto(socketFD, buffer.baseAddress, buffer.count, 0,
                           sockPtr, socklen_t(MemoryLayout<sockaddr_in6>.size))
                }
            }
        }
        guard sent >= 0 else {
            throw TransportError.sendFailed(errno)
        }
    }

    /// Returns the pre-created receive stream. Non-isolated because `receive()`
    /// is not `async` in `MatterUDPTransport`; the stream is a `let` constant
    /// set in `init` so it is safe to access without actor isolation.
    public nonisolated func receive() -> AsyncStream<(Data, MatterAddress)> {
        _receiveStream
    }

    /// Returns the port the socket is currently bound to, or `nil` if not bound.
    ///
    /// Use after `bind(port: 0)` to discover the ephemeral port the OS assigned.
    public func boundPort() -> UInt16? {
        guard fd >= 0 else { return nil }
        var addr = sockaddr_in6()
        var addrLen = socklen_t(MemoryLayout<sockaddr_in6>.size)
        let result = withUnsafeMutablePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                getsockname(fd, sockPtr, &addrLen)
            }
        }
        guard result == 0 else { return nil }
        return UInt16(bigEndian: addr.sin6_port)
    }

    public func close() async {
        if fd >= 0 {
            Darwin.close(fd)
            fd = -1
        }
        receiveContinuation?.finish()
        receiveContinuation = nil
    }

    // MARK: - Socket Address Helpers

    /// Build a `sockaddr_in6` for the given host and port.
    ///
    /// Accepts:
    /// - Native IPv6 addresses: `"::1"`, `"fe80::1%en0"` (scope ID parsed
    ///   from `%ifname` suffix via `if_nametoindex`)
    /// - IPv4 addresses: converted to IPv4-mapped form `::ffff:a.b.c.d`
    ///
    /// Returns `nil` if `host` is neither a valid IPv4 nor IPv6 address string.
    private func sockAddr6(host: String, port: UInt16) -> sockaddr_in6? {
        var addr = sockaddr_in6()
        addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        addr.sin6_family = sa_family_t(AF_INET6)
        addr.sin6_port = port.bigEndian

        // Strip scope ID suffix for link-local addresses (e.g. "fe80::1%en0")
        let addrStr: String
        if let percentIdx = host.firstIndex(of: "%") {
            let ifname = String(host[host.index(after: percentIdx)...])
            addr.sin6_scope_id = if_nametoindex(ifname)
            addrStr = String(host[..<percentIdx])
        } else {
            addrStr = host
        }

        // Try native IPv6
        if inet_pton(AF_INET6, addrStr, &addr.sin6_addr) == 1 {
            return addr
        }

        // Try IPv4 → IPv4-mapped ::ffff:a.b.c.d
        var v4 = in_addr()
        guard inet_pton(AF_INET, addrStr, &v4) == 1 else { return nil }

        // inet_pton stores the address in network byte order in v4.s_addr.
        // withUnsafeBytes gives us those same network-order bytes.
        let v4Bytes = withUnsafeBytes(of: v4.s_addr) { Data($0) }
        withUnsafeMutableBytes(of: &addr.sin6_addr) { bytes in
            for i in 0..<10 { bytes[i] = 0 }
            bytes[10] = 0xFF
            bytes[11] = 0xFF
            bytes[12] = v4Bytes[0]
            bytes[13] = v4Bytes[1]
            bytes[14] = v4Bytes[2]
            bytes[15] = v4Bytes[3]
        }
        return addr
    }

    // MARK: - Receive Loop

    /// Start the blocking receive loop on a dedicated dispatch queue.
    ///
    /// The closure captures only `socketFD: Int32` (value copy) and
    /// `cont: AsyncStream.Continuation` (Sendable) — it never accesses
    /// actor-isolated state, eliminating re-entrancy risk. The loop exits
    /// naturally when `close()` closes the socket, causing `recvfrom` to
    /// return ≤ 0.
    private func startReceiveLoop() {
        let socketFD = self.fd
        guard let cont = self.receiveContinuation else { return }

        receiveQueue.async {
            var buffer = [UInt8](repeating: 0, count: 65536)

            while true {
                var senderAddr = sockaddr_in6()
                var addrLen = socklen_t(MemoryLayout<sockaddr_in6>.size)

                let received = withUnsafeMutablePointer(to: &senderAddr) { ptr in
                    ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                        recvfrom(socketFD, &buffer, buffer.count, 0, sockPtr, &addrLen)
                    }
                }

                guard received > 0 else { break }

                let data = Data(buffer[..<received])

                // Determine host string: IPv4-mapped or native IPv6
                var sin6addr = senderAddr.sin6_addr
                let addrBytes = withUnsafeBytes(of: &sin6addr) { Data($0) }

                let host: String
                if addrBytes[10] == 0xFF && addrBytes[11] == 0xFF {
                    // IPv4-mapped ::ffff:a.b.c.d — present as dotted-decimal
                    host = "\(addrBytes[12]).\(addrBytes[13]).\(addrBytes[14]).\(addrBytes[15])"
                } else {
                    var hostBuf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                    inet_ntop(AF_INET6, &sin6addr, &hostBuf, socklen_t(INET6_ADDRSTRLEN))
                    host = hostBuf.withUnsafeBufferPointer { buf in
                        String(utf8String: buf.baseAddress!) ?? ""
                    }
                }

                let port = UInt16(bigEndian: senderAddr.sin6_port)
                cont.yield((data, MatterAddress(host: host, port: port)))
            }

            cont.finish()
        }
    }
}

// MARK: - Errors

enum TransportError: Error {
    case socketCreationFailed
    case bindFailed(Int32)
    case sendFailed(Int32)
    case notBound
    case invalidAddress(String)
}
