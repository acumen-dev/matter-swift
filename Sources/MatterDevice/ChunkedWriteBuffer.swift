// ChunkedWriteBuffer.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterProtocol

/// Reassembles chunked `WriteRequest` messages on a per-exchange basis.
///
/// The Matter specification allows write requests that exceed the UDP MTU to be
/// split across multiple messages using the `moreChunkedMessages` flag. Each
/// intermediate chunk carries `moreChunkedMessages = true`; the final chunk
/// carries `false`.
///
/// `ChunkedWriteBuffer` buffers attribute data from intermediate chunks and
/// returns a merged `WriteRequest` once the final chunk arrives.
///
/// Stale buffers (exchanges that never sent a final chunk) are cleaned up
/// by `purgeStale(olderThan:)`.
///
/// ```swift
/// let buffer = ChunkedWriteBuffer()
///
/// // Intermediate chunk — returns nil (more chunks expected)
/// let result1 = await buffer.addChunk(exchangeID: 7, request: chunk1)  // nil
///
/// // Final chunk — returns merged WriteRequest
/// let result2 = await buffer.addChunk(exchangeID: 7, request: chunk2)  // merged
/// ```
public actor ChunkedWriteBuffer {

    // MARK: - Internal State

    struct PendingWrite {
        var writes: [AttributeDataIB]
        let timedRequest: Bool
        let suppressResponse: Bool
        let startTime: Date
    }

    private var pending: [UInt16: PendingWrite] = [:]

    // MARK: - Init

    public init() {}

    // MARK: - Public API

    /// Add a write chunk for the given exchange.
    ///
    /// - Parameters:
    ///   - exchangeID: The exchange ID that owns this write sequence.
    ///   - request: The write request chunk.
    ///   - now: Current timestamp (injectable for testing).
    /// - Returns: The merged `WriteRequest` when the final chunk arrives; `nil` when
    ///            more chunks are expected.
    public func addChunk(
        exchangeID: UInt16,
        request: WriteRequest,
        now: Date = Date()
    ) -> WriteRequest? {
        // Non-chunked write with no prior buffer — pass through immediately
        if !request.moreChunkedMessages && pending[exchangeID] == nil {
            return request
        }

        // Accumulate writes into the buffer
        if var existing = pending[exchangeID] {
            existing.writes.append(contentsOf: request.writeRequests)
            if request.moreChunkedMessages {
                pending[exchangeID] = existing
                return nil
            } else {
                // Final chunk — merge and return
                pending.removeValue(forKey: exchangeID)
                return WriteRequest(
                    suppressResponse: existing.suppressResponse,
                    timedRequest: existing.timedRequest,
                    writeRequests: existing.writes,
                    moreChunkedMessages: false
                )
            }
        } else {
            // First chunk of a new chunked write sequence
            let newPending = PendingWrite(
                writes: request.writeRequests,
                timedRequest: request.timedRequest,
                suppressResponse: request.suppressResponse,
                startTime: now
            )
            if request.moreChunkedMessages {
                pending[exchangeID] = newPending
                return nil
            } else {
                // Single-message write that went through the buffer path — return it
                return request
            }
        }
    }

    /// Remove buffered writes older than `timeout` seconds.
    ///
    /// Call this periodically (e.g., in the report loop) to reclaim memory from
    /// exchanges that started a chunked write sequence but never completed it.
    ///
    /// - Parameters:
    ///   - timeout: Maximum age in seconds before a pending write is discarded.
    ///   - now: Current timestamp (injectable for testing).
    public func purgeStale(olderThan timeout: TimeInterval = 30, now: Date = Date()) {
        pending = pending.filter { _, value in
            now.timeIntervalSince(value.startTime) < timeout
        }
    }
}
