// ChunkedInvokeBufferTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterProtocol
@testable import MatterDevice

@Suite("ChunkedInvokeBuffer")
struct ChunkedInvokeBufferTests {

    // MARK: - Helpers

    private func makeInvokeRequest(
        moreChunkedMessages: Bool,
        commandCount: Int = 1,
        startEndpoint: UInt16 = 1
    ) -> InvokeRequest {
        let commands = (0..<commandCount).map { i in
            CommandDataIB(
                commandPath: CommandPath(
                    endpointID: EndpointID(rawValue: UInt16(startEndpoint) + UInt16(i)),
                    clusterID: ClusterID(rawValue: 0x0006),
                    commandID: CommandID(rawValue: 0x0001)
                ),
                commandFields: nil
            )
        }
        return InvokeRequest(
            suppressResponse: false,
            timedRequest: false,
            invokeRequests: commands,
            moreChunkedMessages: moreChunkedMessages
        )
    }

    // MARK: - Test 1: Non-chunked invoke passes through immediately

    @Test("Non-chunked invoke (moreChunkedMessages=false, no buffer) passes through immediately")
    func nonChunkedInvokePassesThrough() async {
        let buffer = ChunkedInvokeBuffer()
        let request = makeInvokeRequest(moreChunkedMessages: false)

        let result = await buffer.addChunk(exchangeID: 1, request: request)

        #expect(result != nil)
        #expect(result?.invokeRequests.count == 1)
        #expect(result?.moreChunkedMessages == false)
    }

    // MARK: - Test 2: Three chunks on same exchangeID → merged result

    @Test("Three chunks on the same exchangeID are merged into one InvokeRequest")
    func threeChunksMerged() async {
        let buffer = ChunkedInvokeBuffer()
        let exchangeID: UInt16 = 7

        let chunk1 = makeInvokeRequest(moreChunkedMessages: true, commandCount: 2, startEndpoint: 1)
        let chunk2 = makeInvokeRequest(moreChunkedMessages: true, commandCount: 2, startEndpoint: 3)
        let chunk3 = makeInvokeRequest(moreChunkedMessages: false, commandCount: 2, startEndpoint: 5)

        // First chunk: more expected
        let r1 = await buffer.addChunk(exchangeID: exchangeID, request: chunk1)
        #expect(r1 == nil, "Expected nil for intermediate chunk 1")

        // Second chunk: more expected
        let r2 = await buffer.addChunk(exchangeID: exchangeID, request: chunk2)
        #expect(r2 == nil, "Expected nil for intermediate chunk 2")

        // Third chunk: final — should return merged result
        let merged = await buffer.addChunk(exchangeID: exchangeID, request: chunk3)
        #expect(merged != nil)
        #expect(merged?.invokeRequests.count == 6, "Expected all 6 commands merged")
        #expect(merged?.moreChunkedMessages == false)
    }

    // MARK: - Test 3: purgeStale removes buffered invokes after timeout

    @Test("purgeStale removes buffered invokes that have exceeded the timeout")
    func purgeStaleRemovesOldBuffers() async {
        let buffer = ChunkedInvokeBuffer()
        let exchangeID: UInt16 = 42

        // Add a first chunk (simulating start time in the past)
        let pastDate = Date(timeIntervalSinceNow: -60)  // 60 seconds ago
        let chunk = makeInvokeRequest(moreChunkedMessages: true)
        let r = await buffer.addChunk(exchangeID: exchangeID, request: chunk, now: pastDate)
        #expect(r == nil)

        // Purge stale buffers older than 30 seconds
        await buffer.purgeStale(olderThan: 30, now: Date())

        // After purge, the exchange buffer should be gone.
        // Adding a non-chunked request to the same exchange should pass through immediately.
        let finalChunk = makeInvokeRequest(moreChunkedMessages: false, commandCount: 1, startEndpoint: 10)
        let afterPurge = await buffer.addChunk(exchangeID: exchangeID, request: finalChunk)
        #expect(afterPurge != nil, "After purge, non-chunked invoke should pass through immediately")
        // The result should have only 1 command (the final chunk), not merged with purged data
        #expect(afterPurge?.invokeRequests.count == 1)
    }
}
