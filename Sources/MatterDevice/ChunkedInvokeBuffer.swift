// ChunkedInvokeBuffer.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterProtocol

/// Reassembles chunked `InvokeRequest` messages on a per-exchange basis.
///
/// The Matter specification allows invoke requests that exceed the UDP MTU to be
/// split across multiple messages using the `moreChunkedMessages` flag (§8.6.3).
/// Each intermediate chunk carries `moreChunkedMessages = true`; the final chunk
/// carries `false`.
///
/// `ChunkedInvokeBuffer` buffers command invocations from intermediate chunks and
/// returns a merged `InvokeRequest` once the final chunk arrives.
///
/// Stale buffers (exchanges that never sent a final chunk) are cleaned up
/// by `purgeStale(olderThan:)`.
///
/// ```swift
/// let buffer = ChunkedInvokeBuffer()
///
/// // Intermediate chunk — returns nil (more chunks expected)
/// let result1 = await buffer.addChunk(exchangeID: 7, request: chunk1)  // nil
///
/// // Final chunk — returns merged InvokeRequest
/// let result2 = await buffer.addChunk(exchangeID: 7, request: chunk2)  // merged
/// ```
public actor ChunkedInvokeBuffer {

    // MARK: - Internal State

    struct PendingInvoke {
        var commands: [CommandDataIB]
        let timedRequest: Bool
        let suppressResponse: Bool
        let startTime: Date
    }

    private var pending: [UInt16: PendingInvoke] = [:]

    // MARK: - Init

    public init() {}

    // MARK: - Public API

    /// Add an invoke chunk for the given exchange.
    ///
    /// - Parameters:
    ///   - exchangeID: The exchange ID that owns this invoke sequence.
    ///   - request: The invoke request chunk.
    ///   - now: Current timestamp (injectable for testing).
    /// - Returns: The merged `InvokeRequest` when the final chunk arrives; `nil` when
    ///            more chunks are expected.
    public func addChunk(
        exchangeID: UInt16,
        request: InvokeRequest,
        now: Date = Date()
    ) -> InvokeRequest? {
        // Non-chunked invoke with no prior buffer — pass through immediately
        if !request.moreChunkedMessages && pending[exchangeID] == nil {
            return request
        }

        // Accumulate commands into the buffer
        if var existing = pending[exchangeID] {
            existing.commands.append(contentsOf: request.invokeRequests)
            if request.moreChunkedMessages {
                pending[exchangeID] = existing
                return nil
            } else {
                // Final chunk — merge and return
                pending.removeValue(forKey: exchangeID)
                return InvokeRequest(
                    suppressResponse: existing.suppressResponse,
                    timedRequest: existing.timedRequest,
                    invokeRequests: existing.commands,
                    moreChunkedMessages: false
                )
            }
        } else {
            // First chunk of a new chunked invoke sequence
            let newPending = PendingInvoke(
                commands: request.invokeRequests,
                timedRequest: request.timedRequest,
                suppressResponse: request.suppressResponse,
                startTime: now
            )
            if request.moreChunkedMessages {
                pending[exchangeID] = newPending
                return nil
            } else {
                // Single-message invoke that went through the buffer path — return it
                return request
            }
        }
    }

    /// Remove buffered invokes older than `timeout` seconds.
    ///
    /// Call this periodically (e.g., in the report loop) to reclaim memory from
    /// exchanges that started a chunked invoke sequence but never completed it.
    ///
    /// - Parameters:
    ///   - timeout: Maximum age in seconds before a pending invoke is discarded.
    ///   - now: Current timestamp (injectable for testing).
    public func purgeStale(olderThan timeout: TimeInterval = 30, now: Date = Date()) {
        pending = pending.filter { _, value in
            now.timeIntervalSince(value.startTime) < timeout
        }
    }
}
