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
/// The chunker implements three key capabilities modeled on the matter.js reference:
///
/// 1. **List attribute chunking** — When a single array attribute (e.g., PartsList)
///    exceeds the chunk budget, it is decomposed into a REPLACE-ALL report (empty
///    array, `listIndex` absent) plus individual APPEND reports (`listIndex = null`)
///    that are greedily packed across messages.
///
/// 2. **40-byte minimum guard** — Items are not added when fewer than 40 bytes
///    remain in the current chunk, preventing edge cases where encoding variance
///    causes an overfull message.
///
/// 3. **Item queueing** — If an item does not fit the current chunk, it is queued
///    so smaller items from the same cluster can fill the remaining space. Cluster
///    boundaries trigger a flush of the queue before new clusters are started.
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

    /// Minimum bytes that must remain available before we stop adding items.
    /// An empty DataReport is roughly 23 bytes, so 40 bytes provides a safe margin.
    /// Matches matter.js `DATA_REPORT_MIN_AVAILABLE_BYTES_BEFORE_SENDING`.
    static let minAvailableBytesBeforeSending = 40

    /// Maximum queued attribute reports before forcing a flush.
    /// Matches matter.js `DATA_REPORT_MAX_QUEUED_ATTRIBUTE_MESSAGES`.
    static let maxQueuedAttributeMessages = 20

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

        let emptyEnvelopeSize = envelopeOverhead(subscriptionID: subscriptionID)
        // 3 bytes per array container (context tag + end-of-container)
        let arrayContainerOverhead = 3

        var chunks: [ReportData] = []
        var currentAttributes: [AttributeReportIB] = []
        var currentEvents: [EventReportIB] = []
        var messageSize = emptyEnvelopeSize

        // Helper: flush current accumulator as an intermediate chunk
        func flushChunk() {
            guard !currentAttributes.isEmpty || !currentEvents.isEmpty else { return }
            chunks.append(ReportData(
                subscriptionID: subscriptionID,
                attributeReports: currentAttributes,
                eventReports: currentEvents,
                moreChunkedMessages: true,
                suppressResponse: false
            ))
            currentAttributes = []
            currentEvents = []
            messageSize = emptyEnvelopeSize
        }

        // --- Process event reports first (per spec ordering) ---
        for event in eventReports {
            let itemSize = encodedSize(event)
            let overhead = currentEvents.isEmpty ? arrayContainerOverhead : 0
            if messageSize + overhead + itemSize > maxPayloadSize
                && (!currentEvents.isEmpty || !currentAttributes.isEmpty) {
                flushChunk()
            }
            if currentEvents.isEmpty {
                messageSize += arrayContainerOverhead
            }
            currentEvents.append(event)
            messageSize += itemSize
        }

        // --- Process attribute reports with queue ---
        var queue: [QueueItem] = []
        var inputIndex = 0
        var processQueueFirst = true

        while inputIndex < attributeReports.count || !queue.isEmpty {
            // Feed from input into queue when appropriate
            let shouldReadInput = inputIndex < attributeReports.count
                && (queue.isEmpty
                    || (queue.count <= Self.maxQueuedAttributeMessages
                        && !processQueueFirst
                        && !(queue.first?.needSendNext ?? false)))

            if shouldReadInput {
                let report = attributeReports[inputIndex]
                inputIndex += 1
                let size = encodedSize(report)

                if queue.isEmpty {
                    queue.append(QueueItem(report: report, encodedSize: size, needSendNext: false))
                } else {
                    let firstPath = queue[0].report.attributeData?.path
                    let newPath = report.attributeData?.path
                    let sameCluster = firstPath?.endpointID == newPath?.endpointID
                        && firstPath?.clusterID == newPath?.clusterID

                    if sameCluster {
                        // Prioritize same-cluster for better packing
                        queue.insert(QueueItem(report: report, encodedSize: size, needSendNext: false), at: 0)
                    } else {
                        // Cluster change: mark all queued items for immediate send
                        for i in queue.indices {
                            queue[i].needSendNext = true
                        }
                        queue.append(QueueItem(report: report, encodedSize: size, needSendNext: false))
                    }
                }
                continue
            }

            // All input consumed: mark remaining queue items for immediate send
            if inputIndex >= attributeReports.count && !queue.isEmpty {
                for i in queue.indices {
                    queue[i].needSendNext = true
                }
            }

            // Process queue front
            guard !queue.isEmpty else { break }
            let item = queue.removeFirst()

            let attrArrayOverhead = currentAttributes.isEmpty ? arrayContainerOverhead : 0
            let availableBytes = maxPayloadSize - messageSize - attrArrayOverhead

            if item.encodedSize <= availableBytes {
                // Item fits: add to current chunk
                if currentAttributes.isEmpty {
                    messageSize += arrayContainerOverhead
                }
                currentAttributes.append(item.report)
                messageSize += item.encodedSize
            } else if (item.needSendNext || inputIndex >= attributeReports.count)
                        && item.report.canBeChunked {
                // Array decomposition: break into REPLACE-ALL + APPEND elements
                let decomposed = item.report.chunkArrayAttribute()
                guard decomposed.count >= 2 else {
                    // Degenerate case: treat as non-chunkable
                    if !currentAttributes.isEmpty || !currentEvents.isEmpty {
                        flushChunk()
                    }
                    if currentAttributes.isEmpty {
                        messageSize += arrayContainerOverhead
                    }
                    currentAttributes.append(item.report)
                    messageSize += item.encodedSize
                    continue
                }

                // First chunk is REPLACE-ALL (with first element packed in)
                let replaceAll = decomposed[0]
                let replaceAllSize = encodedSize(replaceAll)
                let initialOverhead = currentAttributes.isEmpty ? arrayContainerOverhead : 0

                if replaceAllSize <= maxPayloadSize - messageSize - initialOverhead {
                    // REPLACE-ALL fits in current chunk
                    if currentAttributes.isEmpty {
                        messageSize += arrayContainerOverhead
                    }
                    currentAttributes.append(replaceAll)
                    messageSize += replaceAllSize

                    // Greedily pack APPEND elements
                    var appendIndex = 1
                    while appendIndex < decomposed.count {
                        let appendItem = decomposed[appendIndex]
                        let appendSize = encodedSize(appendItem)
                        if messageSize + appendSize > maxPayloadSize {
                            break
                        }
                        currentAttributes.append(appendItem)
                        messageSize += appendSize
                        appendIndex += 1
                    }

                    // Queue remaining APPEND elements with needSendNext
                    if appendIndex < decomposed.count {
                        let remaining = decomposed[appendIndex...]
                        for chunk in remaining.reversed() {
                            queue.insert(
                                QueueItem(report: chunk, encodedSize: encodedSize(chunk), needSendNext: true),
                                at: 0
                            )
                        }
                    }
                } else {
                    // REPLACE-ALL doesn't fit: flush and retry
                    if !currentAttributes.isEmpty || !currentEvents.isEmpty {
                        flushChunk()
                    }
                    // Re-queue all decomposed chunks
                    for chunk in decomposed.reversed() {
                        queue.insert(
                            QueueItem(report: chunk, encodedSize: encodedSize(chunk), needSendNext: true),
                            at: 0
                        )
                    }
                }
            } else if item.needSendNext {
                // Item must go now but doesn't fit: flush and retry
                flushChunk()
                queue.insert(item, at: 0)
            } else {
                // Item doesn't fit and isn't urgent: re-queue at end, try smaller items
                queue.append(item)
                processQueueFirst = false
            }

            // 40-byte minimum guard
            let currentAvailable = maxPayloadSize - messageSize
            if currentAvailable < Self.minAvailableBytesBeforeSending
                && (!currentAttributes.isEmpty || !currentEvents.isEmpty) {
                flushChunk()
                processQueueFirst = true
            }

            // Queue overflow guard
            if queue.count >= Self.maxQueuedAttributeMessages
                && (!currentAttributes.isEmpty || !currentEvents.isEmpty) {
                flushChunk()
                processQueueFirst = true
            }

            // Queue front needSendNext guard
            if let first = queue.first, first.needSendNext,
               first.encodedSize > maxPayloadSize - messageSize - (currentAttributes.isEmpty ? arrayContainerOverhead : 0),
               !currentAttributes.isEmpty || !currentEvents.isEmpty {
                flushChunk()
                processQueueFirst = true
            }
        }

        // Emit final chunk
        chunks.append(ReportData(
            subscriptionID: subscriptionID,
            attributeReports: currentAttributes,
            eventReports: currentEvents,
            moreChunkedMessages: false,
            suppressResponse: suppressResponseOnFinal
        ))

        return chunks
    }

    // MARK: - Private Helpers

    /// A queued attribute report with cached encoded size.
    private struct QueueItem {
        let report: AttributeReportIB
        let encodedSize: Int
        var needSendNext: Bool
    }

    /// Compute the TLV overhead of a `ReportData` envelope (with moreChunkedMessages=true).
    ///
    /// This includes the structure container, subscription ID, moreChunkedMessages flag,
    /// suppressResponse flag, and InteractionModelRevision — but NOT the attribute/event
    /// array containers (those are accounted for separately per the 3-byte overhead).
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
