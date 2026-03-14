// ChunkedWriteBufferTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterProtocol
@testable import MatterDevice

@Suite("ChunkedWriteBuffer")
struct ChunkedWriteBufferTests {

    // MARK: - Helpers

    private func makeWriteRequest(
        moreChunkedMessages: Bool,
        attributeCount: Int = 1,
        startEndpoint: UInt16 = 1
    ) -> WriteRequest {
        let writes = (0..<attributeCount).map { i in
            AttributeDataIB(
                dataVersion: DataVersion(rawValue: 0),
                path: AttributePath(
                    endpointID: EndpointID(rawValue: UInt16(startEndpoint) + UInt16(i)),
                    clusterID: ClusterID(rawValue: 0x0006),
                    attributeID: AttributeID(rawValue: 0x0000)
                ),
                data: .bool(true)
            )
        }
        return WriteRequest(
            suppressResponse: false,
            timedRequest: false,
            writeRequests: writes,
            moreChunkedMessages: moreChunkedMessages
        )
    }

    // MARK: - Test 1: Non-chunked write passes through immediately

    @Test("Non-chunked write (moreChunkedMessages=false, no buffer) passes through immediately")
    func nonChunkedWritePassesThrough() async {
        let buffer = ChunkedWriteBuffer()
        let request = makeWriteRequest(moreChunkedMessages: false)

        let result = await buffer.addChunk(exchangeID: 1, request: request)

        #expect(result != nil)
        #expect(result?.writeRequests.count == 1)
        #expect(result?.moreChunkedMessages == false)
    }

    // MARK: - Test 2: Three chunks on same exchangeID → merged result

    @Test("Three chunks on the same exchangeID are merged into one WriteRequest")
    func threeChunksMerged() async {
        let buffer = ChunkedWriteBuffer()
        let exchangeID: UInt16 = 7

        let chunk1 = makeWriteRequest(moreChunkedMessages: true, attributeCount: 2, startEndpoint: 1)
        let chunk2 = makeWriteRequest(moreChunkedMessages: true, attributeCount: 2, startEndpoint: 3)
        let chunk3 = makeWriteRequest(moreChunkedMessages: false, attributeCount: 2, startEndpoint: 5)

        // First chunk: more expected
        let r1 = await buffer.addChunk(exchangeID: exchangeID, request: chunk1)
        #expect(r1 == nil, "Expected nil for intermediate chunk 1")

        // Second chunk: more expected
        let r2 = await buffer.addChunk(exchangeID: exchangeID, request: chunk2)
        #expect(r2 == nil, "Expected nil for intermediate chunk 2")

        // Third chunk: final — should return merged result
        let merged = await buffer.addChunk(exchangeID: exchangeID, request: chunk3)
        #expect(merged != nil)
        #expect(merged?.writeRequests.count == 6, "Expected all 6 write requests merged")
        #expect(merged?.moreChunkedMessages == false)
    }

    // MARK: - Test 3: purgeStale removes buffered writes after timeout

    @Test("purgeStale removes buffered writes that have exceeded the timeout")
    func purgeStaleRemovesOldBuffers() async {
        let buffer = ChunkedWriteBuffer()
        let exchangeID: UInt16 = 42

        // Add a first chunk (simulating start time in the past)
        let pastDate = Date(timeIntervalSinceNow: -60)  // 60 seconds ago
        let chunk = makeWriteRequest(moreChunkedMessages: true)
        let r = await buffer.addChunk(exchangeID: exchangeID, request: chunk, now: pastDate)
        #expect(r == nil)

        // Before purge: the exchange should still be buffered
        // Verify by trying to add the final chunk — it should merge with the existing buffer
        // but first let's purge with a 30-second timeout

        // Purge stale buffers older than 30 seconds
        await buffer.purgeStale(olderThan: 30, now: Date())

        // After purge, the exchange buffer should be gone.
        // Adding a non-chunked request to the same exchange should pass through immediately
        // (no existing buffer means it's treated as a standalone write).
        let finalChunk = makeWriteRequest(moreChunkedMessages: false, attributeCount: 1, startEndpoint: 10)
        let afterPurge = await buffer.addChunk(exchangeID: exchangeID, request: finalChunk)
        #expect(afterPurge != nil, "After purge, non-chunked write should pass through immediately")
        // The result should have only 1 write (the final chunk's writes), not merged with purged data
        #expect(afterPurge?.writeRequests.count == 1)
    }

    // MARK: - Test 4: Two concurrent exchanges tracked independently

    @Test("Two concurrent exchanges are tracked independently")
    func twoConcurrentExchanges() async {
        let buffer = ChunkedWriteBuffer()

        let exchange1: UInt16 = 100
        let exchange2: UInt16 = 200

        // Start both exchanges with intermediate chunks
        let chunk1a = makeWriteRequest(moreChunkedMessages: true, attributeCount: 1, startEndpoint: 1)
        let chunk2a = makeWriteRequest(moreChunkedMessages: true, attributeCount: 1, startEndpoint: 11)

        let r1a = await buffer.addChunk(exchangeID: exchange1, request: chunk1a)
        let r2a = await buffer.addChunk(exchangeID: exchange2, request: chunk2a)
        #expect(r1a == nil)
        #expect(r2a == nil)

        // Add another intermediate chunk for exchange1 only
        let chunk1b = makeWriteRequest(moreChunkedMessages: true, attributeCount: 1, startEndpoint: 2)
        let r1b = await buffer.addChunk(exchangeID: exchange1, request: chunk1b)
        #expect(r1b == nil)

        // Finalize exchange2 — should only have exchange2's writes
        let chunk2b = makeWriteRequest(moreChunkedMessages: false, attributeCount: 1, startEndpoint: 12)
        let merged2 = await buffer.addChunk(exchangeID: exchange2, request: chunk2b)
        #expect(merged2 != nil)
        #expect(merged2?.writeRequests.count == 2, "Exchange2 should have 2 writes")
        // Verify exchange2's endpoint IDs (11 and 12)
        let exchange2Endpoints = merged2?.writeRequests.compactMap { $0.path.endpointID?.rawValue }.sorted()
        #expect(exchange2Endpoints == [11, 12])

        // Finalize exchange1 — should have exchange1's writes only (1 and 2)
        let chunk1c = makeWriteRequest(moreChunkedMessages: false, attributeCount: 1, startEndpoint: 3)
        let merged1 = await buffer.addChunk(exchangeID: exchange1, request: chunk1c)
        #expect(merged1 != nil)
        #expect(merged1?.writeRequests.count == 3, "Exchange1 should have 3 writes")
        let exchange1Endpoints = merged1?.writeRequests.compactMap { $0.path.endpointID?.rawValue }.sorted()
        #expect(exchange1Endpoints == [1, 2, 3])
    }
}
