// AppleUDPTransport.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTransport
import Logging

/// Apple platform UDP transport using a POSIX UDP socket.
///
/// Uses a single POSIX socket for both inbound and outbound datagrams.
/// The receive loop runs on a dedicated `DispatchQueue` to avoid blocking
/// the Swift cooperative thread pool. Inbound datagrams are yielded to an
/// `AsyncStream` consumed by the server's receive loop.
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
public final class AppleUDPTransport: MatterUDPTransport, @unchecked Sendable {

    // MARK: - State

    private let receiveQueue = DispatchQueue(label: "matter.udp.receive", qos: .userInitiated)
    private var fd: Int32 = -1
    private var receiveContinuation: AsyncStream<(Data, MatterAddress)>.Continuation?
    private var receiveStream: AsyncStream<(Data, MatterAddress)>?
    private var receiveRunning = false
    private let logger: Logger

    // MARK: - Init

    public init(logger: Logger = Logger(label: "matter.apple.udp")) {
        self.logger = logger
        let (stream, continuation) = AsyncStream<(Data, MatterAddress)>.makeStream()
        self.receiveStream = stream
        self.receiveContinuation = continuation
    }

    // MARK: - MatterUDPTransport

    public func bind(port: UInt16) async throws {
        let socketFD = socket(AF_INET, SOCK_DGRAM, 0)
        guard socketFD >= 0 else {
            throw TransportError.socketCreationFailed
        }

        var reuseAddr: Int32 = 1
        setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &reuseAddr, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = INADDR_ANY.bigEndian

        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.bind(socketFD, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else {
            Darwin.close(socketFD)
            throw TransportError.bindFailed(errno)
        }

        self.fd = socketFD
        self.receiveRunning = true

        logger.info("UDP transport bound on port \(port)")

        // Start receive loop on a dedicated dispatch queue
        startReceiveLoop()
    }

    public func send(_ data: Data, to address: MatterAddress) async throws {
        let socketFD = self.fd
        guard socketFD >= 0 else {
            throw TransportError.notBound
        }

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
        guard sent >= 0 else {
            throw TransportError.sendFailed(errno)
        }
    }

    public func receive() -> AsyncStream<(Data, MatterAddress)> {
        receiveStream ?? AsyncStream { $0.finish() }
    }

    public func close() async {
        receiveRunning = false

        if fd >= 0 {
            Darwin.close(fd)
            fd = -1
        }

        receiveContinuation?.finish()
        receiveContinuation = nil
    }

    // MARK: - Internal

    /// Blocking receive loop dispatched to a background queue.
    ///
    /// Reads datagrams using `recvfrom()` and yields them to the async stream.
    /// The loop terminates when `receiveRunning` is set to `false` or the
    /// socket is closed (causing `recvfrom` to return -1).
    private func startReceiveLoop() {
        let socketFD = self.fd
        receiveQueue.async { [weak self] in
            var buffer = [UInt8](repeating: 0, count: 65536)

            while self?.receiveRunning == true {
                var senderAddr = sockaddr_in()
                var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)

                let received = withUnsafeMutablePointer(to: &senderAddr) { ptr in
                    ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                        recvfrom(socketFD, &buffer, buffer.count, 0, sockPtr, &addrLen)
                    }
                }

                guard received > 0 else {
                    // Socket closed or error — stop loop
                    break
                }

                let data = Data(buffer[..<received])

                // Extract sender address
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

enum TransportError: Error {
    case socketCreationFailed
    case bindFailed(Int32)
    case sendFailed(Int32)
    case notBound
}
