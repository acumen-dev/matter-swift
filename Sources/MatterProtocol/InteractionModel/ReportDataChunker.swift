// ReportDataChunker.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

/// Splits large Interaction Model report data across multiple `ReportData` messages.
///
/// Matter requires all messages to fit within ~1280 bytes (UDP MTU). When a read
/// or subscription report contains more attribute/event data than fits in a single
/// message, the data must be split across multiple `ReportData` chunks. Intermediate
/// chunks carry `moreChunkedMessages = true`; the final chunk carries `false`.
///
/// ```swift
/// let chunker = ReportDataChunker()
/// let chunks = chunker.chunk(
///     subscriptionID: subID,
///     attributeReports: reports,
///     eventReports: [],
///     suppressResponseOnFinal: true
/// )
/// // chunks[0].moreChunkedMessages == true  (if multiple)
/// // chunks.last?.moreChunkedMessages == false
/// ```
public struct ReportDataChunker: Sendable {

    /// Maximum TLV payload size per chunk.
    public let maxPayloadSize: Int

    public init(maxPayloadSize: Int = MatterMessage.maxIMPayloadSize) {
        self.maxPayloadSize = maxPayloadSize
    }

    // MARK: - Public API

    /// Chunk a set of attribute and event reports into one or more `ReportData` messages.
    ///
    /// - Parameters:
    ///   - subscriptionID: Subscription ID to embed in every chunk (nil for read responses).
    ///   - attributeReports: Attribute reports to include.
    ///   - eventReports: Event reports to include (encoded first per spec ordering).
    ///   - suppressResponseOnFinal: Value of `suppressResponse` on the last (or only) chunk.
    /// - Returns: Array of `ReportData` messages. Never empty — at minimum one empty chunk.
    public func chunk(
        subscriptionID: SubscriptionID?,
        attributeReports: [AttributeReportIB],
        eventReports: [EventReportIB],
        suppressResponseOnFinal: Bool
    ) -> [ReportData] {
        // Edge case: empty input → single empty chunk
        if attributeReports.isEmpty && eventReports.isEmpty {
            return [ReportData(
                subscriptionID: subscriptionID,
                attributeReports: [],
                eventReports: [],
                moreChunkedMessages: false,
                suppressResponse: suppressResponseOnFinal
            )]
        }

        // Measure envelope overhead: a skeleton ReportData with empty arrays + moreChunkedMessages=true
        let skeletonOverhead = envelopeOverhead(subscriptionID: subscriptionID)
        let budget = maxPayloadSize - skeletonOverhead

        var chunks: [ReportData] = []
        var currentEvents: [EventReportIB] = []
        var currentAttributes: [AttributeReportIB] = []
        var currentSize = 0

        // Helper: flush current accumulator as an intermediate chunk
        func flushChunk() {
            let chunk = ReportData(
                subscriptionID: subscriptionID,
                attributeReports: currentAttributes,
                eventReports: currentEvents,
                moreChunkedMessages: true,
                suppressResponse: false
            )
            chunks.append(chunk)
            currentEvents = []
            currentAttributes = []
            currentSize = 0
        }

        // Process event reports first (per spec ordering)
        for event in eventReports {
            let itemSize = encodedSize(event)
            if currentSize + itemSize > budget && (!currentEvents.isEmpty || !currentAttributes.isEmpty) {
                flushChunk()
            }
            currentEvents.append(event)
            currentSize += itemSize
        }

        // Process attribute reports
        for attr in attributeReports {
            let itemSize = encodedSize(attr)
            if currentSize + itemSize > budget && (!currentEvents.isEmpty || !currentAttributes.isEmpty) {
                flushChunk()
            }
            currentAttributes.append(attr)
            currentSize += itemSize
        }

        // Emit final chunk
        let finalChunk = ReportData(
            subscriptionID: subscriptionID,
            attributeReports: currentAttributes,
            eventReports: currentEvents,
            moreChunkedMessages: false,
            suppressResponse: suppressResponseOnFinal
        )
        chunks.append(finalChunk)

        return chunks
    }

    // MARK: - Private Helpers

    /// Compute the TLV size of the envelope of an empty `ReportData` (with moreChunkedMessages=true).
    ///
    /// This overhead is subtracted from `maxPayloadSize` to get the budget available
    /// for actual report items.
    private func envelopeOverhead(subscriptionID: SubscriptionID?) -> Int {
        let skeleton = ReportData(
            subscriptionID: subscriptionID,
            attributeReports: [],
            eventReports: [],
            moreChunkedMessages: true,
            suppressResponse: false
        )
        return TLVEncoder.encode(skeleton.toTLVElement()).count
    }

    /// Compute the TLV-encoded size of a single `AttributeReportIB`.
    private func encodedSize(_ report: AttributeReportIB) -> Int {
        TLVEncoder.encode(report.toTLVElement()).count
    }

    /// Compute the TLV-encoded size of a single `EventReportIB`.
    private func encodedSize(_ report: EventReportIB) -> Int {
        TLVEncoder.encode(report.toTLVElement()).count
    }
}
