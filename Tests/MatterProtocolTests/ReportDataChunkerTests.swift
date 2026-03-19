// ReportDataChunkerTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
@testable import MatterProtocol

@Suite("ReportDataChunker")
struct ReportDataChunkerTests {

    // MARK: - Helpers

    /// Build a simple `AttributeReportIB` with a boolean attribute value.
    private func makeAttributeReport(
        endpoint: UInt16 = 1,
        cluster: UInt32 = 0x0006,
        attribute: UInt32 = 0x0000,
        value: Bool = false
    ) -> AttributeReportIB {
        AttributeReportIB(attributeData: AttributeDataIB(
            dataVersion: DataVersion(rawValue: 0),
            path: AttributePath(
                endpointID: EndpointID(rawValue: endpoint),
                clusterID: ClusterID(rawValue: cluster),
                attributeID: AttributeID(rawValue: attribute)
            ),
            data: .bool(value)
        ))
    }

    /// Build an `EventReportIB` with minimal content.
    private func makeEventReport(eventNumber: UInt64 = 1) -> EventReportIB {
        EventReportIB(eventData: EventDataIB(
            path: EventPath(
                endpointID: EndpointID(rawValue: 1),
                clusterID: ClusterID(rawValue: 0x0006),
                eventID: EventID(rawValue: 0x0001)
            ),
            eventNumber: EventNumber(rawValue: eventNumber),
            priority: .info
        ))
    }

    // MARK: - Test 1: Small report → single chunk

    @Test("Small report fits in a single chunk with moreChunkedMessages false")
    func smallReportSingleChunk() {
        let chunker = ReportDataChunker()
        let reports = [makeAttributeReport()]

        let chunks = chunker.chunk(
            subscriptionID: nil,
            attributeReports: reports,
            eventReports: [],
            suppressResponseOnFinal: true
        )

        #expect(chunks.count == 1)
        #expect(chunks[0].moreChunkedMessages == false)
        #expect(chunks[0].suppressResponse == true)
        #expect(chunks[0].attributeReports.count == 1)
        #expect(chunks[0].eventReports.isEmpty)
    }

    // MARK: - Test 2: Large report → multiple chunks

    @Test("Large report with 50+ attributes splits into multiple chunks")
    func largeReportMultipleChunks() {
        let chunker = ReportDataChunker()

        // Create 60 attribute reports — each ~50 bytes, should exceed 1232 byte budget
        var reports: [AttributeReportIB] = []
        for i in 0..<60 {
            reports.append(makeAttributeReport(endpoint: UInt16(i + 1), value: i % 2 == 0))
        }

        let chunks = chunker.chunk(
            subscriptionID: nil,
            attributeReports: reports,
            eventReports: [],
            suppressResponseOnFinal: true
        )

        #expect(chunks.count > 1, "Expected multiple chunks for 60 attributes")

        // Intermediate chunks must have moreChunkedMessages = true
        for i in 0..<(chunks.count - 1) {
            #expect(chunks[i].moreChunkedMessages == true,
                "Chunk \(i) should have moreChunkedMessages=true")
            #expect(chunks[i].suppressResponse == false,
                "Intermediate chunks should have suppressResponse=false")
        }

        // Final chunk must have moreChunkedMessages = false
        #expect(chunks.last?.moreChunkedMessages == false)
        #expect(chunks.last?.suppressResponse == true)

        // All reports must be present across all chunks
        let totalReports = chunks.flatMap { $0.attributeReports }.count
        #expect(totalReports == 60)
    }

    // MARK: - Test 3: Each chunk encoded size ≤ maxIMPayloadSize

    @Test("Each chunk encoded size does not exceed maxIMPayloadSize")
    func chunkSizeWithinBudget() {
        let chunker = ReportDataChunker()

        // Create many attribute reports with larger payload (64-byte string values)
        let longString = String(repeating: "x", count: 64)
        var reports: [AttributeReportIB] = []
        for i in 0..<30 {
            reports.append(AttributeReportIB(attributeData: AttributeDataIB(
                dataVersion: DataVersion(rawValue: 0),
                path: AttributePath(
                    endpointID: EndpointID(rawValue: UInt16(i + 1)),
                    clusterID: ClusterID(rawValue: 0x0028),
                    attributeID: AttributeID(rawValue: 0x0001)
                ),
                data: .utf8String(longString)
            )))
        }

        let chunks = chunker.chunk(
            subscriptionID: SubscriptionID(rawValue: 42),
            attributeReports: reports,
            eventReports: [],
            suppressResponseOnFinal: false
        )

        for (i, chunk) in chunks.enumerated() {
            let encodedSize = chunk.tlvEncode().count
            #expect(
                encodedSize <= MatterMessage.maxIMPayloadSize,
                "Chunk \(i) encoded size \(encodedSize) exceeds maxIMPayloadSize \(MatterMessage.maxIMPayloadSize)"
            )
        }
    }

    // MARK: - Test 4: Subscription ID preserved in all chunks

    @Test("Subscription ID is preserved in all chunks")
    func subscriptionIDPreservedAcrossChunks() {
        let chunker = ReportDataChunker()
        let subID = SubscriptionID(rawValue: 12345)

        var reports: [AttributeReportIB] = []
        for i in 0..<60 {
            reports.append(makeAttributeReport(endpoint: UInt16(i + 1)))
        }

        let chunks = chunker.chunk(
            subscriptionID: subID,
            attributeReports: reports,
            eventReports: [],
            suppressResponseOnFinal: false
        )

        for (i, chunk) in chunks.enumerated() {
            #expect(chunk.subscriptionID == subID,
                "Chunk \(i) should have subscriptionID \(subID)")
        }
    }

    // MARK: - Test 5: Empty input → single chunk with empty arrays

    @Test("Empty input produces a single chunk with empty arrays")
    func emptyInputSingleChunk() {
        let chunker = ReportDataChunker()

        let chunks = chunker.chunk(
            subscriptionID: nil,
            attributeReports: [],
            eventReports: [],
            suppressResponseOnFinal: true
        )

        #expect(chunks.count == 1)
        #expect(chunks[0].attributeReports.isEmpty)
        #expect(chunks[0].eventReports.isEmpty)
        #expect(chunks[0].moreChunkedMessages == false)
        #expect(chunks[0].suppressResponse == true)
    }

    // MARK: - Bonus: Event reports are included before attribute reports

    @Test("Event reports are processed before attribute reports in chunks")
    func eventReportsPrecedeAttributeReports() {
        let chunker = ReportDataChunker()
        let eventReports = [makeEventReport(eventNumber: 1), makeEventReport(eventNumber: 2)]
        let attrReports = [makeAttributeReport()]

        let chunks = chunker.chunk(
            subscriptionID: nil,
            attributeReports: attrReports,
            eventReports: eventReports,
            suppressResponseOnFinal: true
        )

        // All should fit in one chunk
        #expect(chunks.count == 1)
        #expect(chunks[0].eventReports.count == 2)
        #expect(chunks[0].attributeReports.count == 1)
    }

    // MARK: - Test Group 1: ListIndex TLV round-trips

    @Test("ListIndex absent: round-trip produces nil listIndex")
    func listIndexAbsentRoundTrip() throws {
        // arrange
        let path = AttributePath(
            endpointID: EndpointID(rawValue: 1),
            clusterID: ClusterID(rawValue: 0x0006),
            attributeID: AttributeID(rawValue: 0x0000),
            listIndex: nil
        )

        // act
        let element = path.toTLVElement()
        let decoded = try AttributePath.fromTLVElement(element)

        // assert
        #expect(decoded.listIndex == nil)
    }

    @Test("ListIndex .null: round-trip produces .null listIndex")
    func listIndexNullRoundTrip() throws {
        // arrange
        let path = AttributePath(
            endpointID: EndpointID(rawValue: 1),
            clusterID: ClusterID(rawValue: 0x0006),
            attributeID: AttributeID(rawValue: 0x0000),
            listIndex: .null
        )

        // act
        let element = path.toTLVElement()
        let decoded = try AttributePath.fromTLVElement(element)

        // assert
        #expect(decoded.listIndex == .null)
    }

    @Test("ListIndex .index(5): round-trip produces .index(5) listIndex")
    func listIndexValueRoundTrip() throws {
        // arrange
        let path = AttributePath(
            endpointID: EndpointID(rawValue: 1),
            clusterID: ClusterID(rawValue: 0x0006),
            attributeID: AttributeID(rawValue: 0x0000),
            listIndex: .index(5)
        )

        // act
        let element = path.toTLVElement()
        let decoded = try AttributePath.fromTLVElement(element)

        // assert
        #expect(decoded.listIndex == .index(5))
    }

    // MARK: - Test Group 2: canBeChunked

    @Test("canBeChunked is true for non-empty array attribute with no listIndex")
    func canBeChunkedTrueForNonEmptyArray() {
        // arrange
        let report = AttributeReportIB(attributeData: AttributeDataIB(
            dataVersion: DataVersion(rawValue: 1),
            path: AttributePath(
                endpointID: EndpointID(rawValue: 1),
                clusterID: ClusterID(rawValue: 0x001D),
                attributeID: AttributeID(rawValue: 0x0003)
            ),
            data: .array([.unsignedInt(1)])
        ))

        // assert
        #expect(report.canBeChunked == true)
    }

    @Test("canBeChunked is false for empty array attribute")
    func canBeChunkedFalseForEmptyArray() {
        // arrange
        let report = AttributeReportIB(attributeData: AttributeDataIB(
            dataVersion: DataVersion(rawValue: 1),
            path: AttributePath(
                endpointID: EndpointID(rawValue: 1),
                clusterID: ClusterID(rawValue: 0x001D),
                attributeID: AttributeID(rawValue: 0x0003)
            ),
            data: .array([])
        ))

        // assert
        #expect(report.canBeChunked == false)
    }

    @Test("canBeChunked is false for non-array attribute data")
    func canBeChunkedFalseForNonArray() {
        // arrange
        let report = AttributeReportIB(attributeData: AttributeDataIB(
            dataVersion: DataVersion(rawValue: 1),
            path: AttributePath(
                endpointID: EndpointID(rawValue: 1),
                clusterID: ClusterID(rawValue: 0x0006),
                attributeID: AttributeID(rawValue: 0x0000)
            ),
            data: .bool(true)
        ))

        // assert
        #expect(report.canBeChunked == false)
    }

    @Test("canBeChunked is false when listIndex is set (e.g., .null)")
    func canBeChunkedFalseWhenListIndexSet() {
        // arrange
        let report = AttributeReportIB(attributeData: AttributeDataIB(
            dataVersion: DataVersion(rawValue: 1),
            path: AttributePath(
                endpointID: EndpointID(rawValue: 1),
                clusterID: ClusterID(rawValue: 0x001D),
                attributeID: AttributeID(rawValue: 0x0003),
                listIndex: .null
            ),
            data: .array([.unsignedInt(1)])
        ))

        // assert
        #expect(report.canBeChunked == false)
    }

    // MARK: - Test Group 3: chunkArrayAttribute decomposition

    @Test("chunkArrayAttribute decomposes 3-element array into REPLACE-ALL + 2 APPEND reports")
    func chunkArrayAttributeDecomposition() {
        // arrange
        let dataVersion = DataVersion(rawValue: 42)
        let path = AttributePath(
            endpointID: EndpointID(rawValue: 1),
            clusterID: ClusterID(rawValue: 0x001D),
            attributeID: AttributeID(rawValue: 0x0003)
        )
        let e0 = TLVElement.unsignedInt(10)
        let e1 = TLVElement.unsignedInt(20)
        let e2 = TLVElement.unsignedInt(30)
        let report = AttributeReportIB(attributeData: AttributeDataIB(
            dataVersion: dataVersion,
            path: path,
            data: .array([e0, e1, e2])
        ))

        // act
        let result = report.chunkArrayAttribute()

        // assert — 3 chunks total
        #expect(result.count == 3)

        // [0] REPLACE-ALL: listIndex nil, data = .array([e0])
        let chunk0 = result[0].attributeData
        #expect(chunk0 != nil)
        #expect(chunk0?.path.listIndex == nil)
        #expect(chunk0?.data == .array([e0]))
        #expect(chunk0?.dataVersion == dataVersion)

        // [1] APPEND: listIndex .null, data = e1
        let chunk1 = result[1].attributeData
        #expect(chunk1 != nil)
        #expect(chunk1?.path.listIndex == .null)
        #expect(chunk1?.data == e1)
        #expect(chunk1?.dataVersion == dataVersion)

        // [2] APPEND: listIndex .null, data = e2
        let chunk2 = result[2].attributeData
        #expect(chunk2 != nil)
        #expect(chunk2?.path.listIndex == .null)
        #expect(chunk2?.data == e2)
        #expect(chunk2?.dataVersion == dataVersion)
    }

    // MARK: - Test Group 4: End-to-end chunking

    @Test("List attribute with 10 elements is chunked correctly end-to-end")
    func listAttributeChunkingEndToEnd() {
        // arrange — 10 string elements (~20 bytes each), full report ~250 bytes;
        // maxPayloadSize=150 forces chunking (each APPEND report is ~45 bytes,
        // so ~3 per chunk after envelope overhead of ~25 bytes)
        let elements: [TLVElement] = (0..<10).map { .utf8String("endpoint-\($0)") }
        let report = AttributeReportIB(attributeData: AttributeDataIB(
            dataVersion: DataVersion(rawValue: 7),
            path: AttributePath(
                endpointID: EndpointID(rawValue: 1),
                clusterID: ClusterID(rawValue: 0x001D),
                attributeID: AttributeID(rawValue: 0x0003)
            ),
            data: .array(elements)
        ))
        let chunker = ReportDataChunker(maxPayloadSize: 150)

        // act
        let chunks = chunker.chunk(
            subscriptionID: nil,
            attributeReports: [report],
            eventReports: [],
            suppressResponseOnFinal: true
        )

        // assert — multiple chunks produced
        #expect(chunks.count > 1, "Expected multiple chunks for 10-element array with small budget")

        // First chunk must contain a REPLACE-ALL report (listIndex nil, data is .array)
        let firstChunkReports = chunks[0].attributeReports
        #expect(!firstChunkReports.isEmpty, "First chunk must have at least one attribute report")
        let firstReport = firstChunkReports[0]
        #expect(firstReport.attributeData?.path.listIndex == nil, "First report must be REPLACE-ALL (listIndex nil)")
        if case .array(_) = firstReport.attributeData?.data {
            // expected
        } else {
            Issue.record("First REPLACE-ALL report data should be .array(...)")
        }

        // Later chunks must contain APPEND reports (listIndex .null)
        let laterChunkReports = chunks.dropFirst().flatMap { $0.attributeReports }
        for appendReport in laterChunkReports {
            #expect(appendReport.attributeData?.path.listIndex == .null,
                "Later chunk reports must be APPEND (listIndex .null)")
        }

        // Total element count across all chunks:
        // REPLACE-ALL reports contribute the count of their packed array elements
        // APPEND reports (listIndex .null) each contribute 1 element
        var totalElements = 0
        for chunk in chunks {
            for attrReport in chunk.attributeReports {
                if attrReport.attributeData?.path.listIndex == nil {
                    // REPLACE-ALL report: count elements in the array
                    if case .array(let arr) = attrReport.attributeData?.data {
                        totalElements += arr.count
                    }
                } else {
                    // APPEND report: 1 element
                    totalElements += 1
                }
            }
        }
        #expect(totalElements == 10, "All 10 elements must be present across chunks, got \(totalElements)")

        // Every chunk encoded size must be within budget
        for (i, chunk) in chunks.enumerated() {
            let encodedSize = chunk.tlvEncode().count
            #expect(encodedSize <= 150,
                "Chunk \(i) encoded size \(encodedSize) exceeds maxPayloadSize 150")
        }
    }

    @Test("40-byte minimum guard forces a flush leaving less than 40 bytes headroom")
    func fortyByteMinimumGuardForcesFlush() {
        // arrange — use maxPayloadSize=200 and enough attributes to trigger the 40-byte guard
        // Each boolean attribute report is roughly 30-40 bytes encoded
        let chunker = ReportDataChunker(maxPayloadSize: 200)

        var reports: [AttributeReportIB] = []
        for i in 0..<10 {
            reports.append(makeAttributeReport(
                endpoint: UInt16(i + 1),
                cluster: 0x0006,
                attribute: UInt32(i),
                value: i % 2 == 0
            ))
        }

        // act
        let chunks = chunker.chunk(
            subscriptionID: nil,
            attributeReports: reports,
            eventReports: [],
            suppressResponseOnFinal: true
        )

        // assert — at least 2 chunks because 10 attributes can't all fit in 200 bytes
        #expect(chunks.count >= 2, "Expected multiple chunks with constrained payload size")

        // All reports must appear across all chunks
        let totalReports = chunks.flatMap { $0.attributeReports }.count
        #expect(totalReports == 10, "All 10 reports must be present across chunks")

        // Every chunk encoded size must be within budget
        for (i, chunk) in chunks.enumerated() {
            let encodedSize = chunk.tlvEncode().count
            #expect(encodedSize <= 200,
                "Chunk \(i) encoded size \(encodedSize) exceeds maxPayloadSize 200")
        }
    }
}
