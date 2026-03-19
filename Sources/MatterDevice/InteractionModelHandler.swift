// InteractionModelHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Logging
import MatterTypes
import MatterModel
import MatterProtocol

// MARK: - IMHandleResult

/// The result of handling an Interaction Model message.
///
/// Simple responses (write, invoke, status) carry one or more `(opcode, data)` pairs.
/// Large read/subscribe reports that exceed the UDP MTU carry a `ChunkedReportContext`
/// that delivers chunks one at a time as the client acknowledges each with a StatusResponse.
public enum IMHandleResult: Sendable {
    /// One or more response messages ready to send immediately.
    case responses([(InteractionModelOpcode, Data)])
    /// A multi-chunk report — send the first chunk, then deliver subsequent chunks
    /// each time the client sends a StatusResponse.
    case chunkedReport(ChunkedReportContext)

    /// Convenience accessor: extract the response pairs if this is a `.responses` result.
    /// Returns nil if this is a chunked report.
    public var responsePairs: [(InteractionModelOpcode, Data)]? {
        if case .responses(let pairs) = self { return pairs }
        return nil
    }

    /// Convenience accessor: returns all (opcode, data) pairs from a `.responses` result,
    /// or the first chunk encoded as a single pair from a `.chunkedReport`.
    /// Useful for tests that only need to inspect simple responses.
    public var allPairs: [(InteractionModelOpcode, Data)] {
        switch self {
        case .responses(let pairs):
            return pairs
        case .chunkedReport(var context):
            var pairs: [(InteractionModelOpcode, Data)] = []
            while let chunk = context.nextChunk() {
                pairs.append((.reportData, chunk.tlvEncode()))
            }
            for trailing in context.trailingResponses {
                pairs.append(trailing)
            }
            return pairs
        }
    }
}

/// Tracks chunked report delivery state for a single exchange.
///
/// Created by `InteractionModelHandler` when a report exceeds the UDP MTU.
/// The caller sends `nextChunk()` to retrieve the next chunk to transmit, and
/// checks `isComplete` to know when all chunks have been delivered.
///
/// `trailingResponses` are sent after the final chunk (e.g., a `SubscribeResponse`
/// that must follow the last report chunk).
public struct ChunkedReportContext: Sendable {
    /// All report chunks.
    public let chunks: [ReportData]
    /// Additional `(opcode, data)` pairs to send after the final chunk is acknowledged.
    public let trailingResponses: [(InteractionModelOpcode, Data)]
    /// Index of the next chunk to deliver via `nextChunk()`.
    public private(set) var nextChunkIndex: Int = 0
    /// True when all chunks have been delivered.
    public var isComplete: Bool { nextChunkIndex >= chunks.count }
    /// True when the server initiated this exchange (subscription reports).
    /// False when the client initiated (read/subscribe request responses).
    public let isServerInitiated: Bool

    public init(chunks: [ReportData], trailingResponses: [(InteractionModelOpcode, Data)] = [], isServerInitiated: Bool = false) {
        self.chunks = chunks
        self.trailingResponses = trailingResponses
        self.isServerInitiated = isServerInitiated
    }

    /// Return the next chunk and advance the index. Returns nil when exhausted.
    public mutating func nextChunk() -> ReportData? {
        guard nextChunkIndex < chunks.count else { return nil }
        defer { nextChunkIndex += 1 }
        return chunks[nextChunkIndex]
    }
}

/// Server-side Interaction Model message handler.
///
/// Receives decoded IM messages and produces responses using the `EndpointManager`
/// for data access and `SubscriptionManager` for subscriptions.
/// Does NOT handle transport or encryption — operates on decoded payloads.
///
/// When an `IMRequestContext` is provided, ACL checks are enforced on every operation:
/// - Read/Subscribe: requires `View` privilege; wildcard reads silently skip denied paths,
///   targeted reads return `unsupportedAccess`.
/// - Write: requires `Operate` privilege; ACL cluster writes require `Administer`.
/// - Invoke: requires `Operate` privilege.
/// - PASE sessions bypass all ACL checks (implicit Administer).
///
/// When no context is provided (nil), no ACL enforcement is applied — backward
/// compatible for tests that don't need ACL testing.
///
/// Timed interaction enforcement:
/// - A `TimedRequest` message records a time-bounded window for an exchange.
/// - Subsequent `WriteRequest` or `InvokeRequest` with `timedRequest = true` must arrive
///   within the window; otherwise the request is rejected with `timedRequestMismatch`.
/// - Commands whose handler returns `requiresTimedInteraction == true` must be preceded
///   by a `TimedRequest`; without one the response carries `needsTimedInteraction`.
///
/// ```swift
/// let handler = InteractionModelHandler(
///     endpoints: endpointManager,
///     subscriptions: subscriptionManager,
///     store: attributeStore,
///     timedRequestTracker: timedRequestTracker
/// )
///
/// let responses = try await handler.handleMessage(
///     opcode: .readRequest,
///     payload: requestData,
///     sessionID: session.id,
///     fabricIndex: session.fabricIndex,
///     exchangeID: exchangeHeader.exchangeID,
///     requestContext: aclContext
/// )
/// ```
public struct InteractionModelHandler: Sendable {

    private let endpoints: EndpointManager
    private let subscriptions: SubscriptionManager
    private let store: AttributeStore
    private let timedRequestTracker: TimedRequestTracker
    private let chunkedWriteBuffer: ChunkedWriteBuffer
    private let chunkedInvokeBuffer: ChunkedInvokeBuffer
    private let logger: Logger

    public init(
        endpoints: EndpointManager,
        subscriptions: SubscriptionManager,
        store: AttributeStore,
        timedRequestTracker: TimedRequestTracker = TimedRequestTracker(),
        chunkedWriteBuffer: ChunkedWriteBuffer = ChunkedWriteBuffer(),
        chunkedInvokeBuffer: ChunkedInvokeBuffer = ChunkedInvokeBuffer(),
        logger: Logger = Logger(label: "matter.device.im")
    ) {
        self.endpoints = endpoints
        self.subscriptions = subscriptions
        self.store = store
        self.timedRequestTracker = timedRequestTracker
        self.chunkedWriteBuffer = chunkedWriteBuffer
        self.chunkedInvokeBuffer = chunkedInvokeBuffer
        self.logger = logger
    }

    // MARK: - Message Dispatch

    /// Handle an incoming IM message.
    ///
    /// - Parameters:
    ///   - opcode: The IM opcode identifying the message type.
    ///   - payload: TLV-encoded message body.
    ///   - sessionID: Session this message arrived on.
    ///   - fabricIndex: Fabric of the session.
    ///   - exchangeID: Exchange this message belongs to (used for timed window tracking).
    ///   - requestContext: Session context for ACL enforcement. Nil means no enforcement.
    /// - Returns: `IMHandleResult` — either immediate response pairs or a chunked report context.
    public func handleMessage(
        opcode: InteractionModelOpcode,
        payload: Data,
        sessionID: UInt16,
        fabricIndex: FabricIndex,
        exchangeID: UInt16 = 0,
        requestContext: IMRequestContext? = nil
    ) async throws -> IMHandleResult {
        logger.debug("IM message: opcode=\(opcode) exchangeID=\(exchangeID) payloadSize=\(payload.count) session=\(sessionID) fabric=\(fabricIndex.rawValue)")
        switch opcode {
        case .readRequest:
            return try await handleRead(payload: payload, requestContext: requestContext)
        case .writeRequest:
            return try await handleWrite(payload: payload, exchangeID: exchangeID, requestContext: requestContext)
        case .invokeRequest:
            return try await handleInvoke(payload: payload, exchangeID: exchangeID, requestContext: requestContext)
        case .subscribeRequest:
            return try await handleSubscribe(payload: payload, sessionID: sessionID, fabricIndex: fabricIndex, requestContext: requestContext)
        case .statusResponse:
            return try handleStatusResponse(payload: payload)
        case .timedRequest:
            return try await handleTimedRequest(payload: payload, exchangeID: exchangeID)
        default:
            return .responses([(.statusResponse, IMStatusResponse(status: StatusIB.invalidAction.status).tlvEncode())])
        }
    }

    // MARK: - Timed Request

    /// Handle a TimedRequest message by recording the timeout window for the exchange.
    ///
    /// Returns a success StatusResponse. The actual write or invoke that follows must
    /// arrive within the window.
    private func handleTimedRequest(
        payload: Data,
        exchangeID: UInt16
    ) async throws -> IMHandleResult {
        let request = try TimedRequest.fromTLV(payload)
        await timedRequestTracker.recordTimedRequest(exchangeID: exchangeID, timeoutMs: request.timeoutMs)
        return .responses([(.statusResponse, IMStatusResponse.success.tlvEncode())])
    }

    // MARK: - Read

    /// Handle a ReadRequest by reading attributes and events from the endpoint manager.
    ///
    /// Returns a single ReportData with `suppressResponse: true` for small reports.
    /// Large reports are split across multiple chunks using `ReportDataChunker`.
    ///
    /// ACL enforcement:
    /// - Each report is checked against the ACL with `View` privilege.
    /// - Wildcard reads silently drop denied reports.
    /// - Targeted reads replace denied reports with `unsupportedAccess` status.
    private func handleRead(
        payload: Data,
        requestContext: IMRequestContext?
    ) async throws -> IMHandleResult {
        let request = try ReadRequest.fromTLV(payload)
        for attr in request.attributeRequests {
            logger.debug("  ReadRequest attr: ep=\(attr.endpointID.map { "\($0.rawValue)" } ?? "*") cluster=0x\(String(format: "%04X", attr.clusterID?.rawValue ?? 0xFFFF)) attr=0x\(String(format: "%04X", attr.attributeID?.rawValue ?? 0xFFFF))")
        }
        let fabricIndex = requestContext?.checkerContext.fabricIndex
        let reports = endpoints.readAttributes(
            request.attributeRequests,
            fabricFiltered: request.isFabricFiltered,
            fabricIndex: fabricIndex,
            dataVersionFilters: request.dataVersionFilters
        )

        // Build a set of wildcard request paths (nil endpointID = wildcard)
        let wildcardPaths = Set(
            request.attributeRequests
                .filter { $0.endpointID == nil }
                .map { WildcardKey(clusterID: $0.clusterID, attributeID: $0.attributeID) }
        )
        let allWildcard = request.attributeRequests.contains { $0.endpointID == nil && $0.clusterID == nil && $0.attributeID == nil }

        let filteredReports = filterReportsForACL(
            reports: reports,
            requestContext: requestContext,
            wildcardPaths: wildcardPaths,
            allWildcard: allWildcard
        )

        // Read events only if the request includes event paths.
        // An empty eventRequests array means the client didn't request events (e.g., `onoff read`).
        let eventReports: [EventReportIB]
        if !request.eventRequests.isEmpty {
            let eventMin: EventNumber? = request.eventFilters.map(\.eventMin).min(by: { $0.rawValue < $1.rawValue })
            eventReports = await endpoints.readEvents(request.eventRequests, eventMin: eventMin)
        } else {
            eventReports = []
        }

        // Chunk the report data (suppressResponse=true on the final chunk for standalone reads)
        let chunker = ReportDataChunker()
        let chunks = chunker.chunk(
            subscriptionID: nil,
            attributeReports: filteredReports,
            eventReports: eventReports,
            suppressResponseOnFinal: true
        )

        if chunks.count == 1 {
            return .responses([(.reportData, chunks[0].tlvEncode())])
        } else {
            return .chunkedReport(ChunkedReportContext(chunks: chunks))
        }
    }

    // MARK: - Write

    /// Handle a WriteRequest by writing attributes via the endpoint manager.
    ///
    /// Chunked write support:
    /// - If `request.moreChunkedMessages == true`, the request is buffered until the
    ///   final chunk arrives. Intermediate chunks receive a success StatusResponse.
    ///
    /// Timed write enforcement:
    /// - If `request.timedRequest == true`, the exchange must have a valid timed window;
    ///   otherwise all writes are rejected with `timedRequestMismatch` (0xCB).
    ///
    /// ACL enforcement:
    /// - Each write is checked before execution.
    /// - ACL cluster (0x001F) writes require `Administer` privilege.
    /// - All other writes require `Operate` privilege.
    /// - Denied writes produce `unsupportedAccess` status without executing.
    private func handleWrite(
        payload: Data,
        exchangeID: UInt16,
        requestContext: IMRequestContext?
    ) async throws -> IMHandleResult {
        let rawRequest = try WriteRequest.fromTLV(payload)

        // Handle chunked write reassembly
        guard let request = await chunkedWriteBuffer.addChunk(exchangeID: exchangeID, request: rawRequest) else {
            // More chunks expected — acknowledge with success StatusResponse
            return .responses([(.statusResponse, IMStatusResponse.success.tlvEncode())])
        }

        // Timed interaction window enforcement
        if request.timedRequest {
            let windowResult = await timedRequestTracker.consumeTimedWindow(exchangeID: exchangeID)
            if windowResult != .valid {
                // Reject all writes — timedRequestMismatch (0xCB)
                let timedMismatchStatus = StatusIB(status: IMStatusCode.timedRequestMismatch.rawValue)
                let rejectedStatuses = request.writeRequests.map { writeReq in
                    AttributeStatusIB(path: writeReq.path, status: timedMismatchStatus)
                }
                let response = WriteResponse(writeResponses: rejectedStatuses)
                return .responses([(.writeResponse, response.tlvEncode())])
            }
        }

        if let ctx = requestContext {
            // Pre-filter writes: separate allowed from denied
            var allowedWrites: [AttributeDataIB] = []
            var deniedStatuses: [AttributeStatusIB] = []

            for writeReq in request.writeRequests {
                let path = writeReq.path
                guard let endpointID = path.endpointID, let clusterID = path.clusterID else {
                    // Wildcard writes are not valid per spec — pass through to endpoint manager
                    allowedWrites.append(writeReq)
                    continue
                }

                // ACL cluster writes require Administer; others require Operate
                let requiredPrivilege: AccessControlCluster.Privilege =
                    clusterID == .accessControl ? .administer : .operate

                let decision = ACLChecker.check(
                    requiredPrivilege: requiredPrivilege,
                    endpointID: endpointID,
                    clusterID: clusterID,
                    context: ctx.checkerContext,
                    acls: ctx.acls
                )

                if decision == .allowed {
                    allowedWrites.append(writeReq)
                } else {
                    deniedStatuses.append(AttributeStatusIB(
                        path: path,
                        status: .unsupportedAccess
                    ))
                }
            }

            // Execute allowed writes
            let writeStatuses = allowedWrites.isEmpty ? [] : endpoints.writeAttributes(allowedWrites)

            // Notify subscriptions of attribute changes
            let dirty = store.dirtyPaths()
            if !dirty.isEmpty {
                await subscriptions.attributesChanged(dirty)
            }

            let response = WriteResponse(writeResponses: deniedStatuses + writeStatuses)
            return .responses([(.writeResponse, response.tlvEncode())])
        } else {
            // No ACL context — execute all writes
            let statuses = endpoints.writeAttributes(request.writeRequests)

            let dirty = store.dirtyPaths()
            if !dirty.isEmpty {
                await subscriptions.attributesChanged(dirty)
            }

            let response = WriteResponse(writeResponses: statuses)
            return .responses([(.writeResponse, response.tlvEncode())])
        }
    }

    // MARK: - Invoke

    /// Handle an InvokeRequest by routing commands to cluster handlers.
    ///
    /// Timed invoke enforcement:
    /// - If `request.timedRequest == true`, the exchange must have a valid timed window;
    ///   otherwise all commands are rejected with `timedRequestMismatch` (0xCB).
    /// - Per-command: if a command requires timed interaction and `timedRequest == false`,
    ///   that command is rejected with `needsTimedInteraction` (0xC6).
    ///
    /// ACL enforcement:
    /// - Each command is checked before execution with `Operate` privilege.
    /// - Denied commands produce `unsupportedAccess` command status.
    private func handleInvoke(
        payload: Data,
        exchangeID: UInt16,
        requestContext: IMRequestContext?
    ) async throws -> IMHandleResult {
        let rawRequest = try InvokeRequest.fromTLV(payload)

        // Handle chunked invoke reassembly
        guard let request = await chunkedInvokeBuffer.addChunk(exchangeID: exchangeID, request: rawRequest) else {
            // More chunks expected — acknowledge with success StatusResponse
            return .responses([(.statusResponse, IMStatusResponse.success.tlvEncode())])
        }

        var invokeResponses: [InvokeResponseIB] = []

        // Timed interaction window enforcement (whole-request check)
        if request.timedRequest {
            let windowResult = await timedRequestTracker.consumeTimedWindow(exchangeID: exchangeID)
            if windowResult != .valid {
                // Reject all commands — timedRequestMismatch (0xCB)
                let timedMismatchStatus = StatusIB(status: IMStatusCode.timedRequestMismatch.rawValue)
                let rejectedResponses = request.invokeRequests.map { cmd in
                    InvokeResponseIB(status: CommandStatusIB(
                        commandPath: cmd.commandPath,
                        status: timedMismatchStatus
                    ))
                }
                let response = InvokeResponse(invokeResponses: rejectedResponses)
                return .responses([(.invokeResponse, response.tlvEncode())])
            }
        }

        for cmd in request.invokeRequests {
            logger.debug("  InvokeRequest: ep=\(cmd.commandPath.endpointID.rawValue) cluster=0x\(String(format: "%04X", cmd.commandPath.clusterID.rawValue)) command=0x\(String(format: "%02X", cmd.commandPath.commandID.rawValue))")
            // ACL check before execution
            if let ctx = requestContext {
                let decision = ACLChecker.check(
                    requiredPrivilege: .operate,
                    endpointID: cmd.commandPath.endpointID,
                    clusterID: cmd.commandPath.clusterID,
                    context: ctx.checkerContext,
                    acls: ctx.acls
                )
                if decision == .denied {
                    invokeResponses.append(InvokeResponseIB(status: CommandStatusIB(
                        commandPath: cmd.commandPath,
                        status: .unsupportedAccess
                    )))
                    continue
                }
            }

            // Per-command timed interaction check:
            // If the command requires a timed window but timedRequest was false, reject.
            if !request.timedRequest {
                let handler = endpoints.clusterHandler(
                    endpointID: cmd.commandPath.endpointID,
                    clusterID: cmd.commandPath.clusterID
                )
                if let handler, handler.requiresTimedInteraction(commandID: cmd.commandPath.commandID) {
                    invokeResponses.append(InvokeResponseIB(status: CommandStatusIB(
                        commandPath: cmd.commandPath,
                        status: StatusIB(status: IMStatusCode.needsTimedInteraction.rawValue)
                    )))
                    continue
                }
            }

            do {
                let (result, recordedEvents) = try await endpoints.handleCommand(path: cmd.commandPath, fields: cmd.commandFields)
                if let responseData = result {
                    // Command returned response data.
                    // Per Matter spec §10.7.14.2, the CommandPath in InvokeResponse MUST use
                    // the response command ID (e.g. ArmFailSafeResponse=0x01, not ArmFailSafe=0x00).
                    let handler = endpoints.clusterHandler(
                        endpointID: cmd.commandPath.endpointID,
                        clusterID: cmd.commandPath.clusterID
                    )
                    let responseID = handler?.responseCommandID(for: cmd.commandPath.commandID)
                        ?? cmd.commandPath.commandID
                    let responsePath = CommandPath(
                        endpointID: cmd.commandPath.endpointID,
                        clusterID: cmd.commandPath.clusterID,
                        commandID: responseID
                    )
                    logger.debug("  InvokeResponse: ep=\(cmd.commandPath.endpointID.rawValue) cluster=0x\(String(format: "%04X", cmd.commandPath.clusterID.rawValue)) command=0x\(String(format: "%02X", responseID.rawValue)) → responseData(\(responseData))")
                    invokeResponses.append(InvokeResponseIB(command: CommandDataIB(
                        commandPath: responsePath,
                        commandFields: responseData
                    )))
                } else {
                    // Success, no response data
                    logger.debug("  InvokeResponse: ep=\(cmd.commandPath.endpointID.rawValue) cluster=0x\(String(format: "%04X", cmd.commandPath.clusterID.rawValue)) command=0x\(String(format: "%02X", cmd.commandPath.commandID.rawValue)) → success")
                    invokeResponses.append(InvokeResponseIB(status: CommandStatusIB(
                        commandPath: cmd.commandPath,
                        status: .success
                    )))
                }

                // Notify subscriptions of events generated by this command
                for event in recordedEvents {
                    await subscriptions.eventRecorded(event)
                }
            } catch {
                logger.debug("  InvokeResponse: ep=\(cmd.commandPath.endpointID.rawValue) cluster=0x\(String(format: "%04X", cmd.commandPath.clusterID.rawValue)) command=0x\(String(format: "%02X", cmd.commandPath.commandID.rawValue)) → ERROR: \(error)")
                invokeResponses.append(InvokeResponseIB(status: CommandStatusIB(
                    commandPath: cmd.commandPath,
                    status: .invalidAction
                )))
            }
        }

        // Notify subscriptions of attribute changes from commands
        let dirty = store.dirtyPaths()
        if !dirty.isEmpty {
            await subscriptions.attributesChanged(dirty)
        }

        let response = InvokeResponse(invokeResponses: invokeResponses)
        return .responses([(.invokeResponse, response.tlvEncode())])
    }

    // MARK: - Subscribe

    /// Handle a SubscribeRequest by creating a subscription and returning the initial report.
    ///
    /// Large initial reports are split across multiple chunks using `ReportDataChunker`.
    /// The `SubscribeResponse` is always sent after the final report chunk.
    ///
    /// ACL enforcement: Same as Read — the initial report is ACL-filtered.
    private func handleSubscribe(
        payload: Data,
        sessionID: UInt16,
        fabricIndex: FabricIndex,
        requestContext: IMRequestContext?
    ) async throws -> IMHandleResult {
        let request = try SubscribeRequest.fromTLV(payload)
        logger.debug("[SUBSCRIBE-DIAG] SubscribeRequest: \(request.attributeRequests.count) attrPaths, \(request.eventRequests.count) eventPaths, \(request.eventFilters.count) eventFilters, keepSubs=\(request.keepSubscriptions), fabricFiltered=\(request.isFabricFiltered), min=\(request.minIntervalFloor), max=\(request.maxIntervalCeiling)")

        // Create subscription
        let (subID, maxInterval) = await subscriptions.subscribe(
            request: request,
            sessionID: sessionID,
            fabricIndex: fabricIndex
        )

        // Build initial report with all requested attributes
        let subscribeFabricIndex = requestContext?.checkerContext.fabricIndex
        let reports = endpoints.readAttributes(
            request.attributeRequests,
            fabricFiltered: request.isFabricFiltered,
            fabricIndex: subscribeFabricIndex,
            dataVersionFilters: request.dataVersionFilters
        )

        // Build wildcard info for ACL filtering
        let wildcardPaths = Set(
            request.attributeRequests
                .filter { $0.endpointID == nil }
                .map { WildcardKey(clusterID: $0.clusterID, attributeID: $0.attributeID) }
        )
        let allWildcard = request.attributeRequests.contains { $0.endpointID == nil && $0.clusterID == nil && $0.attributeID == nil }

        let filteredReports = filterReportsForACL(
            reports: reports,
            requestContext: requestContext,
            wildcardPaths: wildcardPaths,
            allWildcard: allWildcard
        )

        // Read initial event reports for subscribed event paths (only if event paths were requested)
        let eventReports: [EventReportIB]
        if !request.eventRequests.isEmpty {
            let eventMin: EventNumber? = request.eventFilters.map(\.eventMin).min(by: { $0.rawValue < $1.rawValue })
            eventReports = await endpoints.readEvents(request.eventRequests, eventMin: eventMin)
        } else {
            eventReports = []
        }

        logger.debug("[SUBSCRIBE-DIAG] Priming report: \(filteredReports.count) attrs, \(eventReports.count) events")

        let subResponse = SubscribeResponse(
            subscriptionID: subID,
            maxInterval: maxInterval
        )

        // Sort attribute reports by (endpoint, cluster, attribute) for deterministic ordering.
        // Apple Home may require attributes in ascending order per Matter spec recommendation.
        let sortedReports = filteredReports.sorted { a, b in
            let aPath = a.attributeData?.path ?? a.attributeStatus?.path ?? AttributePath()
            let bPath = b.attributeData?.path ?? b.attributeStatus?.path ?? AttributePath()
            let aEp = aPath.endpointID?.rawValue ?? 0
            let bEp = bPath.endpointID?.rawValue ?? 0
            if aEp != bEp { return aEp < bEp }
            let aCl = aPath.clusterID?.rawValue ?? 0
            let bCl = bPath.clusterID?.rawValue ?? 0
            if aCl != bCl { return aCl < bCl }
            let aAt = aPath.attributeID?.rawValue ?? 0
            let bAt = bPath.attributeID?.rawValue ?? 0
            return aAt < bAt
        }

        // Chunk the initial report (suppressResponse=false — client must ack each chunk)
        let chunker = ReportDataChunker()
        let chunks = chunker.chunk(
            subscriptionID: subID,
            attributeReports: sortedReports,
            eventReports: eventReports,
            suppressResponseOnFinal: false
        )

        // [SUBSCRIBE-DIAG] Log what's in each chunk for debugging Apple Home compatibility
        for (i, chunk) in chunks.enumerated() {
            let attrSummary = chunk.attributeReports.compactMap { report -> String? in
                guard let data = report.attributeData else { return nil }
                let ep = data.path.endpointID?.rawValue ?? 0
                let cl = data.path.clusterID?.rawValue ?? 0
                let at = data.path.attributeID?.rawValue ?? 0
                return "ep\(ep)/0x\(String(cl, radix: 16, uppercase: true))/0x\(String(at, radix: 16, uppercase: true))"
            }
            let chunkTLV = chunk.tlvEncode()
            let fullHex = chunkTLV.map { String(format: "%02x", $0) }.joined(separator: " ")
            logger.debug("[SUBSCRIBE-DIAG] Chunk \(i+1)/\(chunks.count) (\(chunkTLV.count)B, \(attrSummary.count) attrs): \(attrSummary.joined(separator: ", "))")
            logger.debug("[SUBSCRIBE-DIAG] Chunk \(i+1) FULL TLV: \(fullHex)")
        }

        // Always use ChunkedReportContext, even for single-chunk subscribe reports.
        // The SubscribeResponse MUST be sent only after the client acknowledges the
        // final ReportData with a StatusResponse (Matter spec §8.5.3). Sending
        // ReportData and SubscribeResponse together as .responses() violates the
        // protocol — Apple Home never gets its StatusResponse ACKed and retransmits
        // indefinitely.
        return .chunkedReport(ChunkedReportContext(
            chunks: chunks,
            trailingResponses: [(.subscribeResponse, subResponse.tlvEncode())]
        ))
    }

    // MARK: - Status Response

    /// Handle an incoming StatusResponse.
    ///
    /// StatusResponse messages keep subscriptions alive. The status is decoded
    /// but no response message is needed.
    private func handleStatusResponse(payload: Data) throws -> IMHandleResult {
        let _ = try IMStatusResponse.fromTLV(payload)
        // No response needed for status response acknowledgments
        return .responses([])
    }

    // MARK: - ACL Helpers

    /// Key for identifying wildcard request paths.
    private struct WildcardKey: Hashable {
        let clusterID: ClusterID?
        let attributeID: AttributeID?
    }

    /// Determine if a report originated from a wildcard request.
    ///
    /// A report is considered wildcard-originated if:
    /// 1. There was an all-wildcard request (nil endpoint, cluster, and attribute), OR
    /// 2. The report's cluster/attribute matches a wildcard request path (nil endpoint).
    private func isWildcardOriginated(
        report: AttributeReportIB,
        wildcardPaths: Set<WildcardKey>,
        allWildcard: Bool
    ) -> Bool {
        if allWildcard { return true }
        guard let data = report.attributeData else { return false }
        let key = WildcardKey(clusterID: data.path.clusterID, attributeID: data.path.attributeID)
        // Check for exact match or partially-wildcarded request paths
        return wildcardPaths.contains(key)
            || wildcardPaths.contains(WildcardKey(clusterID: data.path.clusterID, attributeID: nil))
            || wildcardPaths.contains(WildcardKey(clusterID: nil, attributeID: data.path.attributeID))
            || wildcardPaths.contains(WildcardKey(clusterID: nil, attributeID: nil))
    }

    /// Filter attribute reports according to ACL rules.
    ///
    /// - Wildcard-originated denied reports are silently dropped.
    /// - Targeted denied reports are replaced with `unsupportedAccess` status.
    /// - Reports without concrete endpoint/cluster paths pass through.
    private func filterReportsForACL(
        reports: [AttributeReportIB],
        requestContext: IMRequestContext?,
        wildcardPaths: Set<WildcardKey>,
        allWildcard: Bool
    ) -> [AttributeReportIB] {
        guard let ctx = requestContext else { return reports }

        var filtered: [AttributeReportIB] = []
        for report in reports {
            // Status reports (errors) pass through unchanged
            guard let data = report.attributeData else {
                filtered.append(report)
                continue
            }

            // Need concrete endpoint and cluster for ACL check
            guard let endpointID = data.path.endpointID, let clusterID = data.path.clusterID else {
                filtered.append(report)
                continue
            }

            let decision = ACLChecker.check(
                requiredPrivilege: .view,
                endpointID: endpointID,
                clusterID: clusterID,
                context: ctx.checkerContext,
                acls: ctx.acls
            )

            if decision == .allowed {
                filtered.append(report)
            } else if isWildcardOriginated(report: report, wildcardPaths: wildcardPaths, allWildcard: allWildcard) {
                // Wildcard: silently skip
                continue
            } else {
                // Targeted: return unsupportedAccess status
                filtered.append(AttributeReportIB(attributeStatus: AttributeStatusIB(
                    path: data.path,
                    status: .unsupportedAccess
                )))
            }
        }
        return filtered
    }
}
