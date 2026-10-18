// ControllerSubscription.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Logging
import Tracing
import MatterTypes
import MatterProtocol

/// What a subscription tells its caller.
public enum SubscriptionEvent: Sendable, Equatable {
    /// A subscription is (re-)established. Its priming report follows as `.report`.
    case established(SubscriptionID, negotiatedMaxInterval: UInt16)
    /// One `ReportData` (a priming chunk, a data report, or an empty keep-alive).
    case report(SubscriptionReport)
    /// No report within the liveness deadline, or re-establishment failed.
    /// The subscription keeps re-subscribing until cancelled. A late report
    /// may still be delivered after `.lost` and before the next `.established`.
    case lost(String)
}

/// One live subscription to one node.
///
/// Establishes the subscription, answers every report the device sends,
/// declares it lost when no report arrives within the negotiated max interval
/// plus the liveness margin, and re-subscribes with backoff without replaying
/// events already delivered. Events are surfaced on ``events``.
public actor ControllerSubscription {

    /// Supplies the local session ID to subscribe on (establishing CASE if needed).
    public typealias SessionProvider = @Sendable () async throws -> UInt16

    /// Told when establishing on a session fails (never for cancellation), so
    /// the owner can drop a session that has gone stale.
    typealias EstablishFailureHook = @Sendable (_ sessionID: UInt16, _ error: any Error) async -> Void

    public nonisolated let events: AsyncStream<SubscriptionEvent>
    private let continuation: AsyncStream<SubscriptionEvent>.Continuation

    nonisolated let nodeID: NodeID
    private let request: SubscriptionRequest
    private let messenger: ControllerMessenger
    private let client: SubscriptionClient
    private let sessionProvider: SessionProvider
    private let livenessMargin: Duration
    private let operationTimeout: Duration
    private let onEstablishFailure: EstablishFailureHook
    /// Parents the `matter.subscribe` and `matter.subscription` spans.
    private let context: ServiceContext
    /// The live `matter.subscription` span: one per established subscription, ended on loss or cancel.
    private var subscriptionSpan: (any Span)?
    /// When the last report (first chunk) arrived, for `<prefix>_report_interval`.
    private var lastReportAt: ContinuousClock.Instant?
    private var telemetry: ControllerTelemetry { messenger.telemetry }
    nonisolated let logger: Logger

    public private(set) var currentSubscriptionID: SubscriptionID?
    /// The local session ID the current subscription was established on.
    private var currentSessionID: UInt16?
    /// Highest event number delivered across every subscription this object has held.
    private var highestEventNumber: EventNumber?
    private var cancelled = false
    private var monitor: Task<Void, Never>?

    init(
        nodeID: NodeID,
        request: SubscriptionRequest,
        messenger: ControllerMessenger,
        client: SubscriptionClient,
        sessionProvider: @escaping SessionProvider,
        livenessMargin: Duration,
        operationTimeout: Duration,
        logger: Logger,
        context: ServiceContext = .topLevel,
        onEstablishFailure: @escaping EstablishFailureHook = { _, _ in }
    ) {
        (events, continuation) = AsyncStream.makeStream(of: SubscriptionEvent.self)
        self.nodeID = nodeID
        self.request = request
        self.messenger = messenger
        self.client = client
        self.sessionProvider = sessionProvider
        self.livenessMargin = livenessMargin
        self.operationTimeout = operationTimeout
        self.logger = logger.withSubsystem(.subscription)
        self.context = context
        self.onEstablishFailure = onEstablishFailure
    }

    /// Whether ``cancel()`` has been called.
    public var isCancelled: Bool { cancelled }

    /// Establish the first subscription. Throws if that fails; later
    /// re-establishments are retried internally by the liveness monitor.
    func start() async throws {
        try await establish()
        startMonitor()
    }

    public func cancel() async {
        guard !cancelled else { return }
        cancelled = true
        // Cleared before any await so a concurrent establish() cannot commit over it.
        let id = currentSubscriptionID
        let sessionID = currentSessionID
        currentSubscriptionID = nil
        currentSessionID = nil
        monitor?.cancel()
        monitor = nil
        if id != nil { recordLoss(.closed, id: id) }
        endSubscriptionSpan(error: nil)
        continuation.finish()
        if let id, let sessionID {
            await messenger.setSubscriptionHandler(nil, for: id, sessionID: sessionID)
            await client.remove(subscriptionID: id, peerNodeID: nodeID)
        }
    }

    // MARK: - Liveness

    /// Re-subscribe delay after `attempt` consecutive failures: 1 s doubling, capped at 300 s.
    static func backoff(attempt: Int) -> Duration {
        let seconds = attempt >= 9 ? 300 : min(300, 1 << max(0, attempt))
        return .seconds(seconds)
    }

    /// Watch the current subscription's liveness; re-subscribe when it dies.
    private func startMonitor() {
        guard !cancelled else { return }
        monitor?.cancel()
        monitor = Task { [weak self] in
            await self?.monitorLoop()
        }
    }

    private func monitorLoop() async {
        while !cancelled, !Task.isCancelled, let id = currentSubscriptionID, let sessionID = currentSessionID {
            // Both reads before any decision, so nothing suspends between the deadline check and the loss.
            let sessionAlive = await messenger.registeredSessionIDs.contains(sessionID)
            let record = await client.subscription(for: id, peerNodeID: nodeID)
            guard !cancelled, currentSubscriptionID == id else { return }
            var reason = "subscription record missing"
            var loss = SubscriptionLossReason.session
            if let record {
                let deadline = record.livenessDeadline(margin: livenessMargin)
                let now = messenger.clock.now
                if now < deadline {
                    logger.trace("Liveness deadline recomputed: \(MatterLogValue.milliseconds(deadline - now)) ms from now", metadata: metadata(id))
                    do { try await messenger.clock.sleep(until: deadline) } catch { return }
                    continue
                }
                reason = "no report within \(record.negotiatedMaxInterval) s + margin"
                // The text stays as it is (callers match on it); the cause is in `matter.reason`.
                loss = sessionAlive ? .liveness : .session
            }
            // Clear before any await so cancel() and the loop agree on what is held.
            currentSubscriptionID = nil
            currentSessionID = nil
            continuation.yield(.lost(reason))
            recordLoss(loss, id: id, reason: reason)
            await messenger.setSubscriptionHandler(nil, for: id, sessionID: sessionID)
            await client.remove(subscriptionID: id, peerNodeID: nodeID)
            await resubscribe()
        }
    }

    private func resubscribe() async {
        var attempt = 0
        while !cancelled {
            let backoff = Self.backoff(attempt: attempt)
            var attemptMetadata = metadata(nil)
            attemptMetadata[MatterLogKey.attempt] = MatterLogValue.decimal(attempt + 1)
            logger.info("Re-subscribing in \(backoff) (attempt \(attempt + 1))", metadata: attemptMetadata)
            do {
                try await messenger.clock.sleep(until: messenger.clock.now + backoff)
            } catch { return }
            guard !cancelled else { return }
            telemetry.metrics.resubscribes.increment()
            do {
                try await establish()
                return
            } catch {
                if error is CancellationError, cancelled || Task.isCancelled { return }
                guard !cancelled else { return }
                let reason = "re-subscribe failed: \(error)"
                continuation.yield(.lost(reason))
                if isSubscriptionAborted(error, cancelled: cancelled) {
                    // The messenger stopped under it: not a failure, so not counted.
                    logger.debug("Re-subscribe aborted: \(error)", metadata: attemptMetadata)
                } else {
                    recordLoss(.resubscribeFailed, id: nil, reason: reason)
                }
                attempt += 1
            }
        }
    }

    // MARK: - Telemetry

    /// The end of a subscription: its info line (`Subscription lost: <reason>`, or
    /// `Subscription closed` for ``SubscriptionLossReason/closed``) with `matter.reason`,
    /// `<prefix>_subscription_lost_total{reason}`, and the live subscription span ended, with
    /// error status for a loss and none for a close.
    private func recordLoss(_ loss: SubscriptionLossReason, id: SubscriptionID?, reason: String? = nil) {
        var lossMetadata = metadata(id)
        lossMetadata[MatterLogKey.reason] = .string(loss.rawValue)
        logger.info("\(reason.map { "Subscription lost: \($0)" } ?? "Subscription closed")", metadata: lossMetadata)
        telemetry.metrics.subscriptionLoss(loss)
        endSubscriptionSpan(error: reason)
    }

    private func beginSubscriptionSpan(id: SubscriptionID, sessionID: UInt16, maxInterval: UInt16) {
        endSubscriptionSpan(error: nil)
        let span = telemetry.tracer.startSpan("matter.subscription", context: context, ofKind: .consumer)
        if span.isRecording {
            annotate(span, sessionID: sessionID, id: id)
            span.attributes["matter.max_interval_s"] = Int(maxInterval)
        }
        subscriptionSpan = span
    }

    private func endSubscriptionSpan(error message: String?) {
        guard let span = subscriptionSpan else { return }
        subscriptionSpan = nil
        if let message { span.setStatus(SpanStatus(code: .error, message: message)) }
        span.end()
    }

    /// `matter.node`, plus `matter.session` and `matter.subscription` when given.
    private func annotate(_ span: any Span, sessionID: UInt16? = nil, id: SubscriptionID? = nil) {
        span.attributes[MatterLogKey.node] = MatterLogValue.hexString(nodeID.rawValue)
        if let sessionID { span.attributes[MatterLogKey.session] = MatterLogValue.hexString(sessionID) }
        if let id { span.attributes[MatterLogKey.subscription] = MatterLogValue.hexString(id.rawValue) }
    }

    /// `matter.node`, and `matter.subscription` when known.
    private nonisolated func metadata(_ id: SubscriptionID?) -> Logger.Metadata {
        var metadata = Logger.Metadata.node(nodeID)
        if let id { metadata[MatterLogKey.subscription] = MatterLogValue.hex(id.rawValue) }
        return metadata
    }

    // MARK: - Establishment

    /// The first event number to ask for: one past the highest delivered, or
    /// the caller's persisted minimum if nothing has been delivered yet.
    private var nextEventMin: EventNumber? {
        if let highest = highestEventNumber { return EventNumber(rawValue: highest.rawValue + 1) }
        return request.eventMin
    }

    private func establish() async throws {
        guard !cancelled else { throw CancellationError() }
        let sessionID = try await sessionProvider()
        do {
            try await establish(on: sessionID)
        } catch {
            if !(error is CancellationError) { await onEstablishFailure(sessionID, error) }
            throw error
        }
    }

    /// One establishment inside its `matter.subscribe` span (child of ``context``). An
    /// establishment cancelled or ended by `stop()` ends its span without error status.
    private func establish(on sessionID: UInt16) async throws {
        guard !cancelled else { throw CancellationError() }
        let span = telemetry.tracer.startSpan("matter.subscribe", context: context, ofKind: .client)
        defer { span.end() }
        if span.isRecording { annotate(span, sessionID: sessionID) }
        do {
            try await performEstablish(on: sessionID, span: span)
        } catch {
            if !isSubscriptionAborted(error, cancelled: cancelled) {
                span.recordError(error)
                span.setStatus(SpanStatus(code: .error, message: String(describing: error)))
            }
            throw error
        }
    }

    private func performEstablish(on sessionID: UInt16, span: any Span) async throws {
        let exchange = try await messenger.openExchange(sessionID: sessionID, context: span.context)
        var outgoing = request
        outgoing.eventMin = nextEventMin
        var requestMetadata = metadata(nil)
        requestMetadata[MatterLogKey.session] = MatterLogValue.hex(sessionID)
        do {
            guard !cancelled else { throw CancellationError() }
            logger.debug("Subscribe request: \(outgoing.attributePaths.count) attribute path(s), \(outgoing.eventPaths.count) event path(s), interval \(outgoing.minInterval)–\(outgoing.maxInterval) s, eventMin \(outgoing.eventMin.map { String($0.rawValue) } ?? "none")", metadata: requestMetadata)
            var message = try await exchange.request(
                protocolID: .interactionModel,
                opcode: InteractionModelOpcode.subscribeRequest.rawValue,
                payload: client.subscribeRequest(for: outgoing),
                timeout: operationTimeout
            )
            var priming: [SubscriptionReport] = []
            // Priming report: answer every chunk; SubscribeResponse follows the last one.
            while message.opcode == InteractionModelOpcode.reportData.rawValue {
                guard !cancelled else { throw CancellationError() }
                let report = try await client.record(reportData: message.payload, from: nodeID, at: messenger.clock.now)
                guard !cancelled else { throw CancellationError() }
                priming.append(report)
                message = try await exchange.request(
                    protocolID: .interactionModel,
                    opcode: InteractionModelOpcode.statusResponse.rawValue,
                    payload: IMStatusResponse.success.tlvEncode(),
                    timeout: operationTimeout
                )
            }
            guard !cancelled else { throw CancellationError() }
            if message.opcode == InteractionModelOpcode.statusResponse.rawValue {
                let status = try IMStatusResponse.fromTLV(message.payload).status
                var refused = requestMetadata
                refused[MatterLogKey.imStatus] = MatterLogValue.hex(status)
                logger.debug("Subscribe refused", metadata: refused)
                throw ControllerError.imStatus(status)
            }
            guard message.opcode == InteractionModelOpcode.subscribeResponse.rawValue else {
                throw MessagingError.unexpectedProtocol(protocolID: message.protocolID, opcode: message.opcode)
            }
            let subscription = try await client.register(
                responseData: message.payload, peerNodeID: nodeID, request: outgoing, at: messenger.clock.now
            )
            let id = subscription.subscriptionID
            guard !cancelled else {
                await client.remove(subscriptionID: id, peerNodeID: nodeID)
                throw CancellationError()
            }
            // Commit state and surface events with no await in between, so a
            // report routed once the handler is live cannot overtake them.
            currentSubscriptionID = id
            currentSessionID = sessionID
            continuation.yield(.established(id, negotiatedMaxInterval: subscription.negotiatedMaxInterval))
            logger.debug("Subscribe response: max interval \(subscription.negotiatedMaxInterval) s, \(priming.count) priming chunk(s)", metadata: metadata(id))
            logger.info("Subscription established, max interval \(subscription.negotiatedMaxInterval) s", metadata: metadata(id))
            if span.isRecording { annotate(span, id: id) }
            beginSubscriptionSpan(id: id, sessionID: sessionID, maxInterval: subscription.negotiatedMaxInterval)
            lastReportAt = nil
            for (index, report) in priming.enumerated() { deliver(report, id: id, chunk: index + 1) }
            // Register before closing: a report sent right after SubscribeResponse
            // must reach this subscription, not the messenger's fallback.
            await messenger.setSubscriptionHandler(handler(for: id), for: id, sessionID: sessionID)
            if cancelled {
                await messenger.setSubscriptionHandler(nil, for: id, sessionID: sessionID)
                await client.remove(subscriptionID: id, peerNodeID: nodeID)
                throw CancellationError()
            }
            await exchange.close()
        } catch {
            await exchange.close()
            throw error
        }
    }

    // MARK: - Reports

    /// The messenger handler for one subscription ID: answer every chunk
    /// (unless the device suppressed the response), then hand the reports to
    /// the actor.
    ///
    /// Each report is delivered before its StatusResponse is sent, which keeps
    /// reports ordered for a device that waits for the StatusResponse between
    /// reports. A publisher that does not wait can still interleave, because
    /// each unsolicited report runs in its own task.
    private nonisolated func handler(for id: SubscriptionID) -> ControllerMessenger.UnsolicitedHandler {
        { [weak self] message, exchange in
            guard let self else { return }
            var current = message
            var chunk = 1
            while true {
                let decoded: ReportData
                do {
                    decoded = try ReportData.fromTLV(current.payload)
                } catch {
                    self.logger.warning("Subscription \(id.rawValue): undecodable ReportData: \(error)", metadata: self.metadata(id))
                    return
                }
                if chunk > 1, decoded.subscriptionID != id {
                    self.logger.warning("Subscription \(id.rawValue): chunk carries subscription ID \(String(describing: decoded.subscriptionID?.rawValue)); stopping chain", metadata: self.metadata(id))
                    return
                }
                let report: SubscriptionReport
                do {
                    report = try await self.client.record(reportData: current.payload, from: self.nodeID, at: self.messenger.clock.now)
                } catch {
                    self.logger.warning("Subscription \(id.rawValue): could not record report: \(error)", metadata: self.metadata(id))
                    return
                }
                // Deliver before acknowledging: the device sends report N+1 only
                // once it has N's StatusResponse, so N is already surfaced.
                await self.deliver(report, id: id, chunk: chunk)
                if !report.suppressResponse {
                    do {
                        try await exchange.send(
                            protocolID: .interactionModel,
                            opcode: InteractionModelOpcode.statusResponse.rawValue,
                            payload: IMStatusResponse.success.tlvEncode()
                        )
                    } catch {
                        self.logger.warning("Subscription \(id.rawValue): StatusResponse send failed: \(error)", metadata: self.metadata(id))
                    }
                }
                guard report.moreChunkedMessages else { return }
                do {
                    current = try await exchange.receive(timeout: self.operationTimeout)
                } catch {
                    self.logger.warning("Subscription \(id.rawValue): chunk chain broken: \(error)", metadata: self.metadata(id))
                    return
                }
                chunk += 1
            }
        }
    }

    private func deliver(_ report: SubscriptionReport, id: SubscriptionID, chunk: Int) {
        guard !cancelled else { return }
        noteReport(report, id: id, chunk: chunk)
        let numbers = report.events.compactMap { $0.eventData?.eventNumber }
        if let highest = numbers.max() {
            highestEventNumber = max(highestEventNumber ?? highest, highest)
        }
        continuation.yield(.report(report))
    }

    /// One ReportData: the report interval (first chunk), its debug line, its attribute values
    /// at trace (redacted for sensitive clusters), a `report` event on the subscription span
    /// and a short `matter.report` span. The path list is built only when one of those is
    /// logged or traced: reports can be frequent.
    private func noteReport(_ report: SubscriptionReport, id: SubscriptionID, chunk: Int) {
        let now = messenger.clock.now
        if chunk == 1 {
            if let last = lastReportAt { telemetry.metrics.reportInterval.record(duration: now - last) }
            lastReportAt = now
        }
        let reportSpan = telemetry.tracer.startSpan("matter.report", context: subscriptionSpan?.context ?? context, ofKind: .consumer)
        defer { reportSpan.end() }
        let eventSpan = subscriptionSpan.flatMap { $0.isRecording ? $0 : nil }
        let logged = logger.logLevel <= .debug
        guard logged || eventSpan != nil || reportSpan.isRecording else { return }
        let paths = report.attributes.map(IMFormat.describe)
        if logged {
            let reportMetadata = metadata(id)
            logger.debug("ReportData chunk \(chunk)\(report.moreChunkedMessages ? " (more follow)" : ""): \(report.attributes.count) attribute(s), \(report.events.count) event(s) [\(paths.joined(separator: ", "))]", metadata: reportMetadata)
            if logger.logLevel <= .trace {
                for attribute in report.attributes {
                    guard let data = attribute.attributeData else { continue }
                    logger.trace("Report \(IMFormat.path(data.path)) = \(IMFormat.value(data.data, clusterID: data.path.clusterID))", metadata: reportMetadata)
                }
            }
        }
        eventSpan?.addEvent(SpanEvent(name: "report", attributes: [
            "matter.chunk": .int64(Int64(chunk)),
            MatterLogKey.attribute: .stringArray(paths),
        ]))
        if reportSpan.isRecording {
            annotate(reportSpan, id: id)
            reportSpan.attributes[MatterLogKey.attribute] = SpanAttribute.stringArray(paths)
        }
    }
}
