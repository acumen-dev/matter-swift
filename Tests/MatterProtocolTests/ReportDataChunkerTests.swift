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
}
