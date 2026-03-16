// TestUDPChannel.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(Darwin)
import Foundation
import MatterTransport

/// Bidirectional UDP channel for integration tests using POSIX sockets.
///
/// Network.framework's `NWConnection` creates "connected" UDP sockets that
/// filter by remote endpoint, making it difficult to receive responses from
/// a server that responds via a different source port. POSIX sockets handle
/// this natively — `sendto()` and `recvfrom()` work on the same socket.
///
/// All blocking POSIX calls are dispatched to a background thread to avoid
/// blocking the Swift concurrency cooperative thread pool.
final class TestUDPChannel: @unchecked Sendable {

    /// The actual port this channel is bound to.
    let port: UInt16

    private let fd: Int32
    private let queue = DispatchQueue(label: "test.udp.channel")

    // MARK: - Init

    /// Create a channel bound to an ephemeral port on localhost.
    init() throws {
        let socketFD = socket(AF_INET, SOCK_DGRAM, 0)
        guard socketFD >= 0 else {
            throw ChannelError.socketCreationFailed
        }

        // Enable address reuse
        var reuseAddr: Int32 = 1
        setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &reuseAddr, socklen_t(MemoryLayout<Int32>.size))

        // Bind to ephemeral port on loopback
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0  // ephemeral
        addr.sin_addr.s_addr = INADDR_LOOPBACK.bigEndian

        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                bind(socketFD, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else {
            Darwin.close(socketFD)
            throw ChannelError.bindFailed(errno)
        }

        // Get the actual bound port
        var boundAddr = sockaddr_in()
        var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &boundAddr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                getsockname(socketFD, sockPtr, &addrLen)
            }
        }

        self.fd = socketFD
        self.port = UInt16(bigEndian: boundAddr.sin_port)

        // Set receive timeout (10 seconds)
        var timeout = timeval(tv_sec: 10, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    }

    deinit {
        Darwin.close(fd)
    }

    // MARK: - Send

    /// Send data to a target address (dispatched to background thread).
    func send(_ data: Data, to address: MatterAddress) async throws {
        let fd = self.fd
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            queue.async {
                var destAddr = sockaddr_in()
                destAddr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                destAddr.sin_family = sa_family_t(AF_INET)
                destAddr.sin_port = address.port.bigEndian
                inet_pton(AF_INET, address.host, &destAddr.sin_addr)

                let sent = data.withUnsafeBytes { buffer in
                    withUnsafePointer(to: &destAddr) { ptr in
                        ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                            sendto(fd, buffer.baseAddress, buffer.count, 0,
                                   sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
                        }
                    }
                }

                if sent >= 0 {
                    cont.resume()
                } else {
                    cont.resume(throwing: ChannelError.sendFailed(errno))
                }
            }
        }
    }

    // MARK: - Receive

    /// Wait for the next incoming datagram (dispatched to background thread).
    func receiveOne() async throws -> (Data, MatterAddress) {
        let fd = self.fd
        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<(Data, MatterAddress), Error>) in
            queue.async {
                var buffer = [UInt8](repeating: 0, count: 65536)
                var senderAddr = sockaddr_in()
                var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)

                let received = withUnsafeMutablePointer(to: &senderAddr) { ptr in
                    ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                        recvfrom(fd, &buffer, buffer.count, 0, sockPtr, &addrLen)
                    }
                }

                guard received > 0 else {
                    cont.resume(throwing: ChannelError.receiveFailed(errno))
                    return
                }

                let data = Data(buffer[..<received])

                // Extract sender address
                var hostBuf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                inet_ntop(AF_INET, &senderAddr.sin_addr, &hostBuf, socklen_t(INET_ADDRSTRLEN))
                let host = hostBuf.withUnsafeBufferPointer { buf in
                    String(cString: buf.baseAddress!)
                }
                let port = UInt16(bigEndian: senderAddr.sin_port)

                cont.resume(returning: (data, MatterAddress(host: host, port: port)))
            }
        }
    }

    // MARK: - Close

    func close() {
        Darwin.close(fd)
    }

    enum ChannelError: Error {
        case socketCreationFailed
        case bindFailed(Int32)
        case sendFailed(Int32)
        case receiveFailed(Int32)
    }
}
#endif
