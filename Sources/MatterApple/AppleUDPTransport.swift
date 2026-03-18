// AppleUDPTransport.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(Network)
import Foundation
import MatterTransport
import Logging

/// Apple platform UDP transport using two POSIX sockets (one IPv6, one IPv4)
/// for both receive and send.
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
/// POSIX `recvfrom` / `sendto` bypass TCC entirely.
///
/// ## Source-port correctness
///
/// Both sockets are bound to port 5540, so all outbound datagrams have source
/// port 5540. This is required: the commissioning controller (iPhone) uses a
/// connected UDP NWConnection to `(server, 5540)` and silently drops any
/// response whose source port differs.
///
/// ## Link-local routing
///
/// For link-local (`fe80::`) destinations, `IPV6_BOUND_IF` is set on the
/// IPv6 socket before `sendto()` and cleared immediately after. This is
/// necessary because macOS silently drops link-local datagrams unless the
/// outgoing interface is pinned. Using `sendmsg` + `IPV6_PKTINFO` instead
/// causes macOS to select an ephemeral source port, breaking the iPhone's
/// source-port filter. Since `AppleUDPTransport` is an actor, sends are
/// serialised and the brief global socket-option mutation is race-free.
///
/// Using `IPV6_V6ONLY=0` (dual-stack) breaks this workaround on macOS: the
/// kernel does not reliably pin the outgoing interface via `IPV6_BOUND_IF` on
/// dual-stack sockets, causing the response to arrive from the wrong source
/// address. Keeping the IPv6 socket in pure-IPv6 mode preserves the
/// workaround and we handle IPv4 with the separate `AF_INET` socket.
public actor AppleUDPTransport: MatterUDPTransport {

    // MARK: - State

    private var socketFd: Int32 = -1       // AF_INET6 / IPV6_V6ONLY=1
    private var ipv4SocketFd: Int32 = -1   // AF_INET
    private let _receiveStream: AsyncStream<(Data, MatterAddress)>
    private let receiveContinuation: AsyncStream<(Data, MatterAddress)>.Continuation?
    private let logger: Logger

    // MARK: - Init

    public init(logger: Logger = Logger(label: "matter.apple.udp")) {
        self.logger = logger
        let (stream, continuation) = AsyncStream<(Data, MatterAddress)>.makeStream(
            bufferingPolicy: .unbounded
        )
        self._receiveStream = stream
        self.receiveContinuation = continuation
    }

    // MARK: - MatterUDPTransport

    public func bind(port: UInt16) async throws {
        // ── IPv6 socket ──────────────────────────────────────────────────────
        let sock6 = Darwin.socket(AF_INET6, SOCK_DGRAM, 0)
        guard sock6 >= 0 else { throw TransportError.socketCreationFailed }

        var one: Int32 = 1
        // Pure IPv6 mode preserves the IPV6_BOUND_IF workaround for PASE
        // link-local sends (see class doc). Dual-stack breaks it on macOS.
        Darwin.setsockopt(sock6, IPPROTO_IPV6, IPV6_V6ONLY, &one,
                          socklen_t(MemoryLayout.size(ofValue: one)))
        // Allow fast restart without "Address already in use" errors.
        Darwin.setsockopt(sock6, SOL_SOCKET, SO_REUSEADDR, &one,
                          socklen_t(MemoryLayout.size(ofValue: one)))

        var addr6 = sockaddr_in6()
        addr6.sin6_len    = UInt8(MemoryLayout<sockaddr_in6>.size)
        addr6.sin6_family = sa_family_t(AF_INET6)
        addr6.sin6_port   = port.bigEndian
        // sin6_addr stays in6addr_any (all zeros)

        let bind6: Int32 = withUnsafePointer(to: &addr6) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(sock6, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        }
        guard bind6 == 0 else {
            let err = errno
            Darwin.close(sock6)
            throw TransportError.bindFailed(err)
        }

        // ── IPv4 socket ──────────────────────────────────────────────────────
        // Required for CASE sessions: Apple resolves the operational mDNS
        // hostname to an IPv4 address and sends Sigma1 there.
        let sock4 = Darwin.socket(AF_INET, SOCK_DGRAM, 0)
        guard sock4 >= 0 else {
            Darwin.close(sock6)
            throw TransportError.socketCreationFailed
        }

        Darwin.setsockopt(sock4, SOL_SOCKET, SO_REUSEADDR, &one,
                          socklen_t(MemoryLayout.size(ofValue: one)))

        var addr4 = sockaddr_in()
        addr4.sin_len    = UInt8(MemoryLayout<sockaddr_in>.size)
        addr4.sin_family = sa_family_t(AF_INET)
        addr4.sin_port   = port.bigEndian
        addr4.sin_addr   = in_addr(s_addr: INADDR_ANY)

        let bind4: Int32 = withUnsafePointer(to: &addr4) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(sock4, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bind4 == 0 else {
            let err = errno
            Darwin.close(sock6)
            Darwin.close(sock4)
            throw TransportError.bindFailed(err)
        }

        socketFd     = sock6
        ipv4SocketFd = sock4
        startReceiveThread(fd: sock6)
        startReceiveThreadIPv4(fd: sock4)
        logger.info("UDP transport bound on port \(port) (POSIX, IPv4+IPv6)")
    }

    public func send(_ data: Data, to address: MatterAddress) async throws {
        // Detect IPv4 vs IPv6 by presence of ':' (IPv6 always contains colons).
        if !address.host.contains(":") {
            try sendIPv4(data, to: address)
            return
        }

        // ── IPv6 send (existing logic) ────────────────────────────────────────
        let fd = socketFd
        guard fd >= 0 else { throw TransportError.notBound }

        // Split "fe80::1%en0" → hostStr="fe80::1", ifIndex=if_nametoindex("en0")
        var hostStr = address.host
        var ifIndex: UInt32 = 0
        if let pct = address.host.firstIndex(of: "%") {
            let ifName = String(address.host[address.host.index(after: pct)...])
            hostStr   = String(address.host[..<pct])
            ifIndex   = UInt32(if_nametoindex(ifName))
        }

        var dest = sockaddr_in6()
        dest.sin6_len      = UInt8(MemoryLayout<sockaddr_in6>.size)
        dest.sin6_family   = sa_family_t(AF_INET6)
        dest.sin6_port     = in_port_t(address.port).bigEndian
        dest.sin6_scope_id = ifIndex
        guard Darwin.inet_pton(AF_INET6, hostStr, &dest.sin6_addr) == 1 else {
            throw TransportError.invalidAddress(hostStr)
        }

        logger.debug("UDP send: host=\(address.host) port=\(address.port) dataLen=\(data.count) ifIndex=\(ifIndex)")

        // For link-local destinations the kernel needs an outgoing interface.
        // IPV6_PKTINFO (sendmsg) causes macOS to use an ephemeral source port,
        // breaking the iPhone's source-port filter on its NWConnection.
        // Instead, briefly set IPV6_BOUND_IF on the socket, call sendto(), then
        // clear it. The actor serialises all sends so the global socket state
        // change is race-free with respect to other sends. The receive thread's
        // recvfrom() is unaffected by IPV6_BOUND_IF in the kernel path used here.
        if ifIndex > 0 {
            var idx = Int32(ifIndex)
            Darwin.setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF,
                              &idx, socklen_t(MemoryLayout<Int32>.size))
        }

        let sent = posixSendto(fd: fd, data: data, dest: &dest)

        if ifIndex > 0 {
            var zero: Int32 = 0
            Darwin.setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF,
                              &zero, socklen_t(MemoryLayout<Int32>.size))
        }

        guard sent >= 0 else {
            let err = errno
            logger.error("UDP sendto errno=\(err) (\(String(cString: strerror(err)))) host=\(address.host) port=\(address.port)")
            throw TransportError.sendFailed(err)
        }

        logger.debug("UDP sent \(sent) bytes → \(address.host):\(address.port) ifIndex=\(ifIndex)")
    }

    public nonisolated func receive() -> AsyncStream<(Data, MatterAddress)> {
        _receiveStream
    }

    public func boundPort() -> UInt16? {
        guard socketFd >= 0 else { return nil }
        var addr = sockaddr_in6()
        var len  = socklen_t(MemoryLayout<sockaddr_in6>.size)
        let rc: Int32 = withUnsafeMutablePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.getsockname(socketFd, $0, &len)
            }
        }
        return rc == 0 ? UInt16(bigEndian: addr.sin6_port) : nil
    }

    public func close() async {
        if socketFd >= 0 {
            Darwin.close(socketFd)
            socketFd = -1
        }
        if ipv4SocketFd >= 0 {
            Darwin.close(ipv4SocketFd)
            ipv4SocketFd = -1
        }
        receiveContinuation?.finish()
    }

    // MARK: - IPv4 send

    private func sendIPv4(_ data: Data, to address: MatterAddress) throws {
        let fd = ipv4SocketFd
        guard fd >= 0 else { throw TransportError.notBound }

        var dest = sockaddr_in()
        dest.sin_len    = UInt8(MemoryLayout<sockaddr_in>.size)
        dest.sin_family = sa_family_t(AF_INET)
        dest.sin_port   = in_port_t(address.port).bigEndian
        guard Darwin.inet_pton(AF_INET, address.host, &dest.sin_addr) == 1 else {
            throw TransportError.invalidAddress(address.host)
        }

        logger.debug("UDP send (IPv4): host=\(address.host) port=\(address.port) dataLen=\(data.count)")

        let sent: Int = data.withUnsafeBytes { dataPtr in
            withUnsafeMutablePointer(to: &dest) { destPtr in
                destPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    Darwin.sendto(fd, dataPtr.baseAddress, data.count, 0,
                                  sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }

        guard sent >= 0 else {
            let err = errno
            logger.error("UDP sendto (IPv4) errno=\(err) (\(String(cString: strerror(err)))) host=\(address.host) port=\(address.port)")
            throw TransportError.sendFailed(err)
        }

        logger.debug("UDP sent \(sent) bytes → \(address.host):\(address.port) (IPv4)")
    }

    // MARK: - Receive threads

    private func startReceiveThread(fd: Int32) {
        let cont = receiveContinuation
        let log  = logger
        let thread = Thread { Self.receiveLoop(fd: fd, continuation: cont, logger: log) }
        thread.name = "matter.udp.recv6"
        thread.qualityOfService = .userInitiated
        thread.start()
    }

    private func startReceiveThreadIPv4(fd: Int32) {
        let cont = receiveContinuation
        let log  = logger
        let thread = Thread { Self.receiveLoopIPv4(fd: fd, continuation: cont, logger: log) }
        thread.name = "matter.udp.recv4"
        thread.qualityOfService = .userInitiated
        thread.start()
    }

    private static func receiveLoop(
        fd: Int32,
        continuation: AsyncStream<(Data, MatterAddress)>.Continuation?,
        logger: Logger
    ) {
        var buf = [UInt8](repeating: 0, count: 2048)

        while true {
            var src    = sockaddr_in6()
            var srcLen = socklen_t(MemoryLayout<sockaddr_in6>.size)

            let n: Int = buf.withUnsafeMutableBytes { bufPtr in
                withUnsafeMutablePointer(to: &src) { srcPtr in
                    srcPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        Darwin.recvfrom(fd, bufPtr.baseAddress, bufPtr.count, 0, $0, &srcLen)
                    }
                }
            }

            if n < 0 {
                let err = errno
                if err == EBADF || err == EINVAL || err == ENOTSOCK { break }
                logger.warning("UDP recvfrom errno=\(err)")
                continue
            }
            guard n > 0 else { continue }

            // Stringify the source address, appending %ifname for link-local scope.
            var hostBuf = [CChar](repeating: 0, count: 64)
            Darwin.inet_ntop(AF_INET6, &src.sin6_addr, &hostBuf, 64)
            var host = String(decoding: hostBuf.prefix(while: { $0 != 0 }).map(UInt8.init), as: UTF8.self)
            if src.sin6_scope_id > 0 {
                var ifname = [CChar](repeating: 0, count: 32)
                Darwin.if_indextoname(src.sin6_scope_id, &ifname)
                let name = String(decoding: ifname.prefix(while: { $0 != 0 }).map(UInt8.init), as: UTF8.self)
                if !name.isEmpty { host += "%" + name }
            }

            let port    = UInt16(bigEndian: src.sin6_port)
            let address = MatterAddress(host: host, port: port)
            let data    = Data(buf[..<n])

            logger.debug("UDP recv: host=\(host) port=\(port) dataLen=\(n)")
            continuation?.yield((data, address))
        }

        logger.info("UDP receive loop ended (fd closed)")
    }

    private static func receiveLoopIPv4(
        fd: Int32,
        continuation: AsyncStream<(Data, MatterAddress)>.Continuation?,
        logger: Logger
    ) {
        var buf = [UInt8](repeating: 0, count: 2048)

        while true {
            var src    = sockaddr_in()
            var srcLen = socklen_t(MemoryLayout<sockaddr_in>.size)

            let n: Int = buf.withUnsafeMutableBytes { bufPtr in
                withUnsafeMutablePointer(to: &src) { srcPtr in
                    srcPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        Darwin.recvfrom(fd, bufPtr.baseAddress, bufPtr.count, 0, $0, &srcLen)
                    }
                }
            }

            if n < 0 {
                let err = errno
                if err == EBADF || err == EINVAL || err == ENOTSOCK { break }
                logger.warning("UDP recvfrom (IPv4) errno=\(err)")
                continue
            }
            guard n > 0 else { continue }

            var addrCopy = src.sin_addr
            var hostBuf  = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            Darwin.inet_ntop(AF_INET, &addrCopy, &hostBuf, socklen_t(INET_ADDRSTRLEN))
            let host    = String(decoding: hostBuf.prefix(while: { $0 != 0 }).map(UInt8.init), as: UTF8.self)
            let port    = UInt16(bigEndian: src.sin_port)
            let address = MatterAddress(host: host, port: port)
            let data    = Data(buf[..<n])

            logger.debug("UDP recv (IPv4): host=\(host) port=\(port) dataLen=\(n)")
            continuation?.yield((data, address))
        }

        logger.info("UDP IPv4 receive loop ended (fd closed)")
    }

    private func posixSendto(fd: Int32, data: Data, dest: inout sockaddr_in6) -> Int {
        data.withUnsafeBytes { dataPtr in
            withUnsafeMutablePointer(to: &dest) { destPtr in
                destPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    Darwin.sendto(fd, dataPtr.baseAddress, data.count, 0,
                                  sockPtr, socklen_t(MemoryLayout<sockaddr_in6>.size))
                }
            }
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
#endif
