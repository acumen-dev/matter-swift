// LoopbackTransport.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(Darwin)
import Foundation
import MatterTransport

/// POSIX-based UDP transport for integration tests.
///
/// Uses a single POSIX socket for both `sendto()` and `recvfrom()`, with a
/// shared receive loop started once during `bind()`. This mirrors the pattern
/// used by `AppleUDPTransport` — a single `recvfrom` thread feeds a shared
/// `AsyncStream`, and `receive()` returns that same stream every time.
///
/// All blocking POSIX calls are dispatched to a background thread to avoid
/// blocking the Swift concurrency cooperative thread pool.
final class LoopbackTransport: MatterUDPTransport, @unchecked Sendable {

    private var fd: Int32 = -1
    private let sendQueue = DispatchQueue(label: "loopback.transport.send")
    private let recvQueue = DispatchQueue(label: "loopback.transport.recv")
    private var receiveContinuation: AsyncStream<(Data, MatterAddress)>.Continuation?
    private var receiveStream: AsyncStream<(Data, MatterAddress)>?
    private var running = false

    // MARK: - Init

    init() {
        let (stream, continuation) = AsyncStream<(Data, MatterAddress)>.makeStream()
        self.receiveStream = stream
        self.receiveContinuation = continuation
    }

    // MARK: - MatterUDPTransport

    func bind(port: UInt16) async throws {
        let socketFD = socket(AF_INET, SOCK_DGRAM, 0)
        guard socketFD >= 0 else {
            throw LoopbackTransportError.socketCreationFailed
        }

        var reuseAddr: Int32 = 1
        setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &reuseAddr, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = INADDR_LOOPBACK.bigEndian

        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.bind(socketFD, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else {
            Darwin.close(socketFD)
            throw LoopbackTransportError.bindFailed(errno)
        }

        self.fd = socketFD
        self.running = true

        // Start the single shared receive loop
        startReceiveLoop()
    }

    func send(_ data: Data, to address: MatterAddress) async throws {
        let socketFD = self.fd
        guard socketFD >= 0 else { throw LoopbackTransportError.notBound }

        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            sendQueue.async {
                var destAddr = sockaddr_in()
                destAddr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                destAddr.sin_family = sa_family_t(AF_INET)
                destAddr.sin_port = address.port.bigEndian
                inet_pton(AF_INET, address.host, &destAddr.sin_addr)

                let sent = data.withUnsafeBytes { buffer in
                    withUnsafePointer(to: &destAddr) { ptr in
                        ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                            sendto(socketFD, buffer.baseAddress, buffer.count, 0,
                                   sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
                        }
                    }
                }

                if sent >= 0 {
                    cont.resume()
                } else {
                    cont.resume(throwing: LoopbackTransportError.sendFailed(errno))
                }
            }
        }
    }

    func receive() -> AsyncStream<(Data, MatterAddress)> {
        receiveStream ?? AsyncStream { $0.finish() }
    }

    func close() async {
        running = false

        if fd >= 0 {
            Darwin.close(fd)
            fd = -1
        }

        receiveContinuation?.finish()
        receiveContinuation = nil
    }

    // MARK: - Internal

    /// Single shared receive loop — runs once, feeds the shared AsyncStream.
    private func startReceiveLoop() {
        let socketFD = self.fd

        recvQueue.async { [weak self] in
            var buffer = [UInt8](repeating: 0, count: 65536)

            while self?.running == true {
                var senderAddr = sockaddr_in()
                var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)

                let received = withUnsafeMutablePointer(to: &senderAddr) { ptr in
                    ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                        recvfrom(socketFD, &buffer, buffer.count, 0, sockPtr, &addrLen)
                    }
                }

                guard received > 0 else { break }

                let data = Data(buffer[..<received])

                var hostBuf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                inet_ntop(AF_INET, &senderAddr.sin_addr, &hostBuf, socklen_t(INET_ADDRSTRLEN))
                let host = hostBuf.withUnsafeBufferPointer { buf in
                    String(cString: buf.baseAddress!)
                }
                let port = UInt16(bigEndian: senderAddr.sin_port)

                self?.receiveContinuation?.yield((data, MatterAddress(host: host, port: port)))
            }
        }
    }
}

// MARK: - Errors

enum LoopbackTransportError: Error {
    case socketCreationFailed
    case bindFailed(Int32)
    case sendFailed(Int32)
    case notBound
}
#endif
