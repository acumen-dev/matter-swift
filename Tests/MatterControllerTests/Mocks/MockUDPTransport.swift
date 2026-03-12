// MockUDPTransport.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTransport

/// Mock UDP transport for testing.
///
/// Supports scripted responses: queue a response for a given address,
/// and when `send()` is called the response is delivered via the
/// receive stream.
actor MockUDPTransport: MatterUDPTransport {

    // MARK: - State

    private var queuedResponses: [(Data, MatterAddress)] = []
    private(set) var sentMessages: [(Data, MatterAddress)] = []
    private var continuation: AsyncStream<(Data, MatterAddress)>.Continuation?
    private var stream: AsyncStream<(Data, MatterAddress)>?

    init() {
        let (stream, continuation) = AsyncStream<(Data, MatterAddress)>.makeStream()
        self.stream = stream
        self.continuation = continuation
    }

    // MARK: - Test Helpers

    /// Queue a response to be delivered when the next message is sent.
    func queueResponse(_ data: Data, from address: MatterAddress) {
        queuedResponses.append((data, address))
    }

    /// Queue multiple responses.
    func queueResponses(_ responses: [(Data, MatterAddress)]) {
        queuedResponses.append(contentsOf: responses)
    }

    // MARK: - MatterUDPTransport

    nonisolated func send(_ data: Data, to address: MatterAddress) async throws {
        await recordSend(data, to: address)
    }

    nonisolated func receive() -> AsyncStream<(Data, MatterAddress)> {
        // We need to return a stream that yields queued responses.
        // Since we can't call actor methods from nonisolated context synchronously,
        // return the pre-created stream.
        AsyncStream { continuation in
            Task {
                let responses = await self.drainAndGetStream()
                for response in responses {
                    continuation.yield(response)
                }
            }
        }
    }

    nonisolated func bind(port: UInt16) async throws {
        // No-op for mock
    }

    nonisolated func close() async {
        await closeContinuation()
    }

    // MARK: - Internal

    private func recordSend(_ data: Data, to address: MatterAddress) {
        sentMessages.append((data, address))

        // Deliver next queued response if available
        if !queuedResponses.isEmpty {
            let (responseData, responseAddr) = queuedResponses.removeFirst()
            continuation?.yield((responseData, responseAddr))
        }
    }

    private func drainAndGetStream() -> [(Data, MatterAddress)] {
        // Return any already-queued responses for immediate consumption
        let responses = queuedResponses
        queuedResponses.removeAll()
        return responses
    }

    private func closeContinuation() {
        continuation?.finish()
        continuation = nil
    }
}
