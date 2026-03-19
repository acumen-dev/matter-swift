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

        // Process attribute reports.
        // Prefer breaking chunks at cluster boundaries (when endpoint or cluster changes).
        // matter.js uses a similar approach (needSendNext flag) — Apple Home's
        // ClusterStateCache may have issues with clusters split across chunks.
        var prevEndpoint: UInt16?
        var prevCluster: UInt32?
        for attr in attributeReports {
            let itemSize = encodedSize(attr)

            // Detect cluster boundary (endpoint or cluster changed)
            let attrEndpoint = attr.attributeData?.path.endpointID?.rawValue
                ?? attr.attributeStatus?.path.endpointID?.rawValue
            let attrCluster = attr.attributeData?.path.clusterID?.rawValue
                ?? attr.attributeStatus?.path.clusterID?.rawValue
            let clusterChanged = (prevEndpoint != nil || prevCluster != nil)
                && (attrEndpoint != prevEndpoint || attrCluster != prevCluster)

            // Flush if: (a) item won't fit, or (b) cluster boundary and chunk is non-trivial
            let wouldExceedBudget = currentSize + itemSize > budget
            let shouldBreakAtBoundary = clusterChanged && currentSize > budget / 2
            if (wouldExceedBudget || shouldBreakAtBoundary)
                && (!currentEvents.isEmpty || !currentAttributes.isEmpty) {
                flushChunk()
            }

            currentAttributes.append(attr)
            currentSize += itemSize
            prevEndpoint = attrEndpoint
            prevCluster = attrCluster
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

    /// Compute the TLV overhead of a `ReportData` envelope (with moreChunkedMessages=true).
    ///
    /// This overhead is subtracted from `maxPayloadSize` to get the budget available
    /// for actual report items.
    ///
    /// The skeleton uses empty arrays which are OMITTED from TLV encoding, but actual
    /// chunks include the `attributeReports` array container (2-byte tag + 1-byte
    /// end-of-container = 3 bytes) and potentially the `eventReports` container.
    /// We add 6 bytes to account for both possible array containers.
    private func envelopeOverhead(subscriptionID: SubscriptionID?) -> Int {
        let skeleton = ReportData(
            subscriptionID: subscriptionID,
            attributeReports: [],
            eventReports: [],
            moreChunkedMessages: true,
            suppressResponse: false
        )
        // +6 for attributeReports array container (3 bytes) + eventReports array container (3 bytes)
        // These are omitted from the skeleton but present in actual encoded chunks.
        return TLVEncoder.encode(skeleton.toTLVElement()).count + 6
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
