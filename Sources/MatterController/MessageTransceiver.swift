// MessageTransceiver.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTransport

/// Send/receive helper wrapping a `MatterUDPTransport`.
///
/// Provides a `sendAndReceive` method that sends a datagram and waits for
/// the first response from the same address, with a configurable timeout.
struct MessageTransceiver: Sendable {

    let transport: any MatterUDPTransport

    // MARK: - Fire-and-Forget

    /// Send data without waiting for a response.
    func send(_ data: Data, to address: MatterAddress) async throws {
        try await transport.send(data, to: address)
    }

    // MARK: - Request/Response

    /// Send data and wait for a response from the same address.
    ///
    /// Uses a task group: one task listens on the transport's receive stream
    /// for the first datagram from `address`, another sleeps for the timeout
    /// duration. The first to complete wins; the other is cancelled.
    ///
    /// - Parameters:
    ///   - data: The datagram to send.
    ///   - address: The destination (and expected source of response).
    ///   - timeout: Maximum time to wait for a response.
    /// - Returns: The response data.
    /// - Throws: `ControllerError.timeout` if no response arrives in time.
    func sendAndReceive(
        _ data: Data,
        to address: MatterAddress,
        timeout: Duration
    ) async throws -> Data {
        try await transport.send(data, to: address)

        return try await withThrowingTaskGroup(of: Data.self) { group in
            // Task 1: Listen for response
            group.addTask {
                let stream = transport.receive()
                for await (responseData, sender) in stream {
                    if sender == address {
                        return responseData
                    }
                }
                throw ControllerError.transportError("Receive stream ended unexpectedly")
            }

            // Task 2: Timeout
            group.addTask {
                try await Task.sleep(for: timeout)
                throw ControllerError.timeout("No response within \(timeout)")
            }

            // First to complete wins
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
    }
}
