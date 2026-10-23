// POSIXUDPSocketCore.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(Darwin) || canImport(Glibc)
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import CMatterSockets
import Foundation
import Logging
import Synchronization

/// The UDP socket layer under the Apple and Linux transports: one `AF_INET6`
/// (`IPV6_V6ONLY`) and one `AF_INET` socket bound to the same port, a receive
/// thread per socket, and `PKTINFO` on every send.
///
/// A send either takes a pinned ``MatterPath`` (interface and source address)
/// or, without one, selects a path under the ``InterfacePolicy`` with
/// ``PathSelector`` over ``POSIXInterfaces``. Either way the datagram carries
/// a `PKTINFO` control message, which on a bound socket keeps the bound
/// source port (measured on macOS 27). Each received datagram reports the
/// interface it arrived on and the local address it was sent to.
///
/// Each receive thread owns its socket: ``close()`` only wakes the threads
/// (through a wake pipe), and each closes its own descriptor on the way out,
/// so a descriptor number is never released while a thread may still read it.
/// `shutdown(2)` cannot do the waking: on Darwin it fails with `ENOTCONN` on
/// an unconnected UDP socket and leaves a blocked `recvmsg` blocked.
public final class POSIXUDPSocketCore: Sendable {

    private struct State {
        var fd6: Int32 = -1
        var fd4: Int32 = -1
        /// Read end of the wake pipe, polled by both receive threads; the last
        /// thread out closes it.
        var wakeRead: Int32 = -1
        /// Write end of the wake pipe; ``close()`` closes it, which wakes the threads.
        var wakeWrite: Int32 = -1
        var receiveThreads = 0
        var closed = false
        var monitor = InterfacePolicyMonitor(policy: .automatic)
        var addressedData: AsyncStream<(Data, MatterAddress)>?
    }

    private let logger: Logger
    private let state = Mutex(State())
    private let continuation: AsyncStream<MatterDatagram>.Continuation

    /// Every datagram received on either socket. Finishes on ``close()``.
    ///
    /// One stream: consume it here or through ``addressedData``, not both.
    public let datagrams: AsyncStream<MatterDatagram>

    public init(logger: Logger) {
        self.logger = logger
        (datagrams, continuation) = AsyncStream<MatterDatagram>.makeStream(bufferingPolicy: .unbounded)
    }

    /// ``datagrams`` as `(data, sender)`, without the path. Created on first
    /// use; every call returns that same stream.
    public var addressedData: AsyncStream<(Data, MatterAddress)> {
        state.withLock { state in
            if let stream = state.addressedData { return stream }
            let datagrams = self.datagrams
            let stream = AsyncStream<(Data, MatterAddress)>(bufferingPolicy: .unbounded) { continuation in
                let pump = Task {
                    for await datagram in datagrams { continuation.yield((datagram.data, datagram.sender)) }
                    continuation.finish()
                }
                continuation.onTermination = { _ in pump.cancel() }
            }
            state.addressedData = stream
            return stream
        }
    }

    // MARK: - Bind

    /// Binds the IPv6 socket to `port`, then the IPv4 socket to the port the
    /// IPv6 one got (so both share one port when `port` is 0), and starts a
    /// receive thread on each.
    public func bind(port: UInt16) throws {
        try state.withLock { state in
            guard !state.closed, state.fd6 < 0 else { throw TransportError.bindFailed(EINVAL) }
            var wake: [Int32] = [-1, -1]
            guard pipe(&wake) == 0 else { throw TransportError.socketCreationFailed }

            // An ephemeral IPv6 port may be taken for IPv4: retry with a fresh one.
            let attempts = port == 0 ? 8 : 1
            var lastError: Int32 = 0
            for _ in 0..<attempts {
                var err: Int32 = 0
                let fd6 = cms_open_udp(AF_INET6, port, &err)
                guard fd6 >= 0 else { lastError = err; break }
                let shared = cms_bound_port(fd6)
                let fd4 = cms_open_udp(AF_INET, shared, &err)
                guard fd4 >= 0 else {
                    closeDescriptor(fd6)
                    lastError = err
                    if err == EADDRINUSE { continue }
                    break
                }
                state.fd6 = fd6
                state.fd4 = fd4
                state.wakeRead = wake[0]
                state.wakeWrite = wake[1]
                state.receiveThreads = 2
                startReceiveThread(fd: fd6, wake: wake[0], name: "matter.udp.recv6")
                startReceiveThread(fd: fd4, wake: wake[0], name: "matter.udp.recv4")
                logger.info("UDP transport bound on port \(shared) (POSIX, IPv4+IPv6)")
                return
            }
            closeDescriptor(wake[0])
            closeDescriptor(wake[1])
            throw TransportError.bindFailed(lastError)
        }
    }

    /// The port both sockets are bound to, or nil before ``bind(port:)``.
    public var boundPort: UInt16? {
        state.withLock { state in
            guard state.fd6 >= 0 else { return nil }
            let port = cms_bound_port(state.fd6)
            return port == 0 ? nil : port
        }
    }

    // MARK: - Policy

    /// Sets the policy later selections follow, and logs a warning for each
    /// interface it names that is missing or down.
    public func setPolicy(_ policy: InterfacePolicy) {
        let interfaces = POSIXInterfaces.snapshot()
        let changes = state.withLock { state in
            state.monitor = InterfacePolicyMonitor(policy: policy)
            return state.monitor.update(interfaces)
        }
        logger.debug("Matter interface policy: \(policy)")
        logInterfaceChanges(changes)
    }

    // MARK: - Send

    /// Sends `data` to `address` by `path`, or by the path the policy selects
    /// when `path` is nil, and returns the path used.
    ///
    /// - Throws: ``TransportError/invalidAddress(_:)`` for a host that is not
    ///   an IP literal; ``TransportPathError/noAllowedRoute(peer:)`` when no
    ///   allowed interface has a route (or the host's `%zone` interface is
    ///   gone); ``TransportPathError/pathUnavailable(_:errno:)`` when the
    ///   pinned path cannot reach the peer — `EHOSTUNREACH`, `ENETUNREACH`,
    ///   `EADDRNOTAVAIL`; `EINVAL` when the path's address or interface is no
    ///   longer on the host (Linux's answer); `EAFNOSUPPORT` for a path of the
    ///   other address family; `ENXIO` for a `%zone` interface that is gone —
    ///   and ``TransportError/sendFailed(_:)`` otherwise.
    public func send(_ data: Data, to address: MatterAddress, via path: MatterPath?) throws -> MatterSendResult {
        let host = MatterAddress.strippingBrackets(address.host)
        guard let destination = Destination(address.host) else { throw TransportError.invalidAddress(host) }
        guard state.withLock({ $0.fd6 >= 0 }) else { throw TransportError.notBound }

        let chosen: MatterPath
        let outcome: PathSelectionOutcome?
        if let path {
            if destination.zoneMissing {
                logger.debug("UDP send by \(path) to \(host): its zone names no interface")
                throw TransportPathError.pathUnavailable(path, errno: ENXIO)
            }
            if Self.family(of: path.localAddress) != destination.family {
                logger.debug("UDP send by \(path) to \(host): the path is of the other address family")
                throw TransportPathError.pathUnavailable(path, errno: EAFNOSUPPORT)
            }
            chosen = path
            outcome = nil
        } else {
            if destination.zoneMissing {
                logger.debug("No route to \(host): its zone names no interface")
                throw TransportPathError.noAllowedRoute(peer: address)
            }
            let interfaces = POSIXInterfaces.snapshot()
            let (policy, changes) = state.withLock { state in
                (state.monitor.policy, state.monitor.update(interfaces))
            }
            logInterfaceChanges(changes)
            let selection = PathSelector(policy: policy).select(interfaces: interfaces) {
                POSIXInterfaces.route(to: address, via: $0, interfaces: interfaces)
            }
            guard let selected = selection.path, let how = selection.outcome else {
                logger.debug("No allowed route to \(host) under \(policy)")
                throw TransportPathError.noAllowedRoute(peer: address)
            }
            if !selection.skipped.isEmpty {
                let skips = selection.skipped.map { "\($0.name) preferred, \(Self.reason($0.reason))" }
                logger.info("Path to \(host): \(skips.joined(separator: "; ")); using \(selected.interfaceName) (\(selected.localAddress))")
            }
            chosen = selected
            outcome = how
        }

        try sendPinned(data, to: destination, port: address.port, host: host, path: chosen)
        return MatterSendResult(path: chosen, selection: outcome)
    }

    private func sendPinned(_ data: Data, to destination: Destination, port: UInt16, host: String, path: MatterPath) throws {
        logger.trace("UDP send: host=\(host) port=\(port) dataLen=\(data.count) path=\(path)")

        // Held across sendmsg: close() hands the descriptor to its receive thread to
        // close, so only the lock keeps it open (not recycled) for the whole call.
        let (sent, err): (Int, Int32) = try state.withLock { state in
            let fd = destination.family == AF_INET6 ? state.fd6 : state.fd4
            guard fd >= 0 else { throw TransportError.notBound }
            let n = data.withUnsafeBytes { bytes in
                Self.withSockaddr(destination, port: port) { address, length in
                    cms_send(fd, bytes.baseAddress, bytes.count, address, length,
                             path.interfaceIndex, path.localAddress)
                }
            }
            return (n, n < 0 ? errno : 0)
        }

        guard sent < 0 else { return }
        if err == EHOSTUNREACH || err == ENETUNREACH || err == EADDRNOTAVAIL
            || (err == EINVAL && !Self.isOnHost(path)) {
            logger.debug("UDP send by \(path) to \(host):\(port) failed: errno=\(err) (\(Self.describe(err)))")
            throw TransportPathError.pathUnavailable(path, errno: err)
        }
        logger.error("UDP sendmsg errno=\(err) (\(Self.describe(err))) host=\(host) port=\(port) path=\(path)")
        throw TransportError.sendFailed(err)
    }

    /// Whether `path`'s interface is present and up and still holds its address.
    /// Linux answers a `PKTINFO` source that is not on the host with `EINVAL`.
    private static func isOnHost(_ path: MatterPath) -> Bool {
        guard let interface = POSIXInterfaces.snapshot().first(where: { $0.index == path.interfaceIndex }) else {
            return false
        }
        return interface.isUp && interface.addresses.contains(path.localAddress)
    }

    // MARK: - Close

    /// Wakes both receive threads, which close their sockets and exit, and
    /// finishes ``datagrams``. Sends after this throw ``TransportError/notBound``.
    public func close() {
        state.withLock { state in
            guard !state.closed else { return }
            state.closed = true
            state.fd6 = -1
            state.fd4 = -1
            if state.wakeWrite >= 0 {
                // The threads poll the read end: closing the write end wakes them (POLLHUP).
                closeDescriptor(state.wakeWrite)
                state.wakeWrite = -1
            }
        }
        continuation.finish()
    }

    // MARK: - Receive

    private func startReceiveThread(fd: Int32, wake: Int32, name: String) {
        let thread = Thread { [self] in receiveLoop(fd: fd, wake: wake, name: name) }
        thread.name = name
        thread.qualityOfService = .userInitiated
        thread.start()
    }

    /// Owns `fd`: reads it until ``close()``, then closes it. The last thread
    /// out closes the wake pipe's read end.
    private func receiveLoop(fd: Int32, wake: Int32, name: String) {
        var buffer = [UInt8](repeating: 0, count: 2048)
        var from = sockaddr_storage()
        var ifindex: UInt32 = 0
        var local = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let readable = Int16(POLLIN)

        while !state.withLock({ $0.closed }) {
            var fds = [pollfd(fd: fd, events: readable, revents: 0),
                       pollfd(fd: wake, events: readable, revents: 0)]
            let ready = poll(&fds, nfds_t(fds.count), -1)
            if ready < 0 {
                let err = errno
                if err == EINTR { continue }
                logger.warning("UDP poll errno=\(err) (\(Self.describe(err)))")
                break
            }
            if fds[1].revents != 0 { break }   // woken by close()
            guard fds[0].revents != 0 else { continue }

            let n = buffer.withUnsafeMutableBytes { bytes in
                cms_recv(fd, bytes.baseAddress, bytes.count, &from, &ifindex, &local, local.count)
            }
            if n < 0 {
                let err = errno
                if err == EBADF || err == EINVAL || err == ENOTSOCK { break }
                if err != EINTR && err != EAGAIN { logger.warning("UDP recvmsg errno=\(err) (\(Self.describe(err)))") }
                continue
            }

            guard let sender = Self.sender(from) else { continue }
            let path = Self.arrivalPath(ifindex: ifindex, local: local)
            logger.trace("UDP recv: host=\(sender.host) port=\(sender.port) dataLen=\(n) path=\(path.map(\.description) ?? "unknown")")
            continuation.yield(MatterDatagram(data: Data(buffer[..<n]), sender: sender, path: path))
        }

        closeDescriptor(fd)
        state.withLock { state in
            state.receiveThreads -= 1
            if state.receiveThreads == 0, state.wakeRead >= 0 {
                closeDescriptor(state.wakeRead)
                state.wakeRead = -1
            }
        }
        logger.info("UDP receive loop ended (fd closed) [\(name)]")
    }

    /// The sender as a `MatterAddress`, with `%ifname` appended for a scoped
    /// (link-local) IPv6 sender.
    private static func sender(_ from: sockaddr_storage) -> MatterAddress? {
        var storage = from
        return withUnsafeMutablePointer(to: &storage) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { address -> MatterAddress? in
                switch Int32(address.pointee.sa_family) {
                case AF_INET6:
                    let (scope, port) = address.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) {
                        ($0.pointee.sin6_scope_id, UInt16(bigEndian: $0.pointee.sin6_port))
                    }
                    guard var host = POSIXInterfaces.literal(address) else { return nil }
                    if scope > 0, let name = interfaceName(scope) { host += "%" + name }
                    return MatterAddress(host: host, port: port)
                case AF_INET:
                    let port = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                        UInt16(bigEndian: $0.pointee.sin_port)
                    }
                    return POSIXInterfaces.literal(address).map { MatterAddress(host: $0, port: port) }
                default:
                    return nil
                }
            }
        }
    }

    private static func arrivalPath(ifindex: UInt32, local: [CChar]) -> MatterPath? {
        let address = String(decoding: local.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
        guard ifindex != 0, !address.isEmpty, let name = interfaceName(ifindex) else { return nil }
        return MatterPath(interfaceIndex: ifindex, interfaceName: name, localAddress: address)
    }

    private static func interfaceName(_ index: UInt32) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(IF_NAMESIZE) + 1)
        guard if_indextoname(index, &buffer) != nil else { return nil }
        let name = String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
        return name.isEmpty ? nil : name
    }

    // MARK: - Helpers

    private func logInterfaceChanges(_ changes: [(name: String, problem: InterfaceProblem?)]) {
        for change in changes {
            switch change.problem {
            case .down?:
                logger.warning("Interface \(change.name) named in the Matter interface policy is down")
            case .missing?:
                logger.warning("Interface \(change.name) named in the Matter interface policy is missing")
            case nil:
                logger.info("Interface \(change.name) named in the Matter interface policy is available again")
            }
        }
    }

    /// The family of an address literal (IPv6 literals contain a colon).
    private static func family(of literal: String) -> Int32 {
        literal.contains(":") ? AF_INET6 : AF_INET
    }

    private static func reason(_ skip: PathSelection.Skip) -> String {
        switch skip {
        case .missing: "missing"
        case .down: "down"
        case .excluded: "excluded"
        case .noRoute: "no route"
        }
    }

    private static func describe(_ err: Int32) -> String {
        String(cString: strerror(err))
    }

    private static func withSockaddr<R>(
        _ destination: Destination,
        port: UInt16,
        _ body: (UnsafePointer<sockaddr>, socklen_t) -> R
    ) -> R {
        if destination.family == AF_INET6 {
            var address = sockaddr_in6()
            #if canImport(Darwin)
            address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            #endif
            address.sin6_family = sa_family_t(AF_INET6)
            address.sin6_port = port.bigEndian
            address.sin6_scope_id = destination.scope
            _ = inet_pton(AF_INET6, destination.literal, &address.sin6_addr)
            return withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    body($0, socklen_t(MemoryLayout<sockaddr_in6>.size))
                }
            }
        } else {
            var address = sockaddr_in()
            #if canImport(Darwin)
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            #endif
            address.sin_family = sa_family_t(AF_INET)
            address.sin_port = port.bigEndian
            _ = inet_pton(AF_INET, destination.literal, &address.sin_addr)
            return withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    body($0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
    }
}

/// `close(2)`; a free function so the core's own `close()` does not shadow it.
private func closeDescriptor(_ fd: Int32) {
    #if canImport(Darwin)
    _ = Darwin.close(fd)
    #else
    _ = Glibc.close(fd)
    #endif
}
#endif
