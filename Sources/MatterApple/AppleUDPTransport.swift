// AppleUDPTransport.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Network
import MatterTransport
import Logging

/// Apple platform UDP transport using Network.framework.
///
/// Uses `NWListener` for inbound datagrams and a connection pool for outbound.
/// Each inbound datagram arrives as a new `NWConnection` from the listener.
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

    private let queue = DispatchQueue(label: "matter.udp.transport", qos: .userInitiated)
    private var listener: NWListener?
    private var connectionPool: [MatterAddress: NWConnection] = [:]
    private var receiveContinuation: AsyncStream<(Data, MatterAddress)>.Continuation?
    private var receiveStream: AsyncStream<(Data, MatterAddress)>?
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
        let params = NWParameters.udp
        params.allowLocalEndpointReuse = true

        let nwPort = NWEndpoint.Port(rawValue: port) ?? .any
        let nwListener = try NWListener(using: params, on: nwPort)

        nwListener.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                if let actualPort = nwListener.port {
                    self.logger.info("UDP listener ready on port \(actualPort.rawValue)")
                }
            case .failed(let error):
                self.logger.error("UDP listener failed: \(error)")
                self.receiveContinuation?.finish()
            case .cancelled:
                self.logger.debug("UDP listener cancelled")
            default:
                break
            }
        }

        nwListener.newConnectionHandler = { [weak self] connection in
            self?.handleInboundConnection(connection)
        }

        nwListener.start(queue: queue)
        self.listener = nwListener

        // Wait for the listener to become ready
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            nwListener.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .ready:
                    if let actualPort = nwListener.port {
                        self.logger.info("UDP listener ready on port \(actualPort.rawValue)")
                    }
                    cont.resume()
                case .failed(let error):
                    self.logger.error("UDP listener failed: \(error)")
                    self.receiveContinuation?.finish()
                    cont.resume(throwing: error)
                case .cancelled:
                    self.logger.debug("UDP listener cancelled")
                    cont.resume(throwing: CancellationError())
                default:
                    break
                }
            }
        }
    }

    public func send(_ data: Data, to address: MatterAddress) async throws {
        let connection = getOrCreateConnection(to: address)
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connection.send(
                content: data,
                completion: .contentProcessed { error in
                    if let error {
                        cont.resume(throwing: error)
                    } else {
                        cont.resume()
                    }
                }
            )
        }
    }

    public func receive() -> AsyncStream<(Data, MatterAddress)> {
        receiveStream ?? AsyncStream { $0.finish() }
    }

    public func close() async {
        listener?.cancel()
        listener = nil

        for (_, connection) in connectionPool {
            connection.cancel()
        }
        connectionPool.removeAll()

        receiveContinuation?.finish()
        receiveContinuation = nil
    }

    // MARK: - Internal

    /// Handle an inbound connection from the listener.
    ///
    /// Each UDP datagram arrives as a new `NWConnection`. We read one message,
    /// yield it to the receive stream, then cancel the connection.
    private func handleInboundConnection(_ connection: NWConnection) {
        connection.start(queue: queue)
        connection.receiveMessage { [weak self] content, _, _, error in
            guard let self else { return }
            if let error {
                self.logger.debug("Inbound receive error: \(error)")
                connection.cancel()
                return
            }
            guard let data = content,
                  let remoteEndpoint = connection.currentPath?.remoteEndpoint,
                  let sender = MatterAddress(endpoint: remoteEndpoint) else {
                connection.cancel()
                return
            }
            self.receiveContinuation?.yield((data, sender))
            connection.cancel()
        }
    }

    /// Get or create an outbound connection for the given address.
    private func getOrCreateConnection(to address: MatterAddress) -> NWConnection {
        if let existing = connectionPool[address] {
            return existing
        }
        let endpoint = NWEndpoint.hostPort(from: address)
        let connection = NWConnection(to: endpoint, using: .udp)
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .failed(let error):
                self.logger.debug("Outbound connection to \(address) failed: \(error)")
                self.queue.async {
                    self.connectionPool.removeValue(forKey: address)
                }
            case .cancelled:
                self.queue.async {
                    self.connectionPool.removeValue(forKey: address)
                }
            default:
                break
            }
        }
        connection.start(queue: queue)
        connectionPool[address] = connection
        return connection
    }
}
