// ControllerSubscription.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterProtocol

/// What a subscription tells its caller.
public enum SubscriptionEvent: Sendable, Equatable {
    /// A subscription is (re-)established. Its priming report follows as `.report`.
    case established(SubscriptionID, negotiatedMaxInterval: UInt16)
    /// One `ReportData` (a priming chunk, a data report, or an empty keep-alive).
    case report(SubscriptionReport)
    /// No report within the liveness deadline, or re-establishment failed.
    /// The subscription keeps re-subscribing until cancelled.
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

    public nonisolated let events: AsyncStream<SubscriptionEvent>
    private let continuation: AsyncStream<SubscriptionEvent>.Continuation

    private let nodeID: NodeID
    private let request: SubscriptionRequest
    private let messenger: ControllerMessenger
    private let client: SubscriptionClient
    private let sessionProvider: SessionProvider
    private let livenessMargin: Duration
    private let operationTimeout: Duration

    public private(set) var currentSubscriptionID: SubscriptionID?
    /// The local session ID the current subscription was established on.
    private var currentSessionID: UInt16?
    /// Highest event number delivered across every subscription this object has held.
    private var highestEventNumber: EventNumber?
    private var cancelled = false

    init(
        nodeID: NodeID,
        request: SubscriptionRequest,
        messenger: ControllerMessenger,
        client: SubscriptionClient,
        sessionProvider: @escaping SessionProvider,
        livenessMargin: Duration,
        operationTimeout: Duration
    ) {
        (events, continuation) = AsyncStream.makeStream(of: SubscriptionEvent.self)
        self.nodeID = nodeID
        self.request = request
        self.messenger = messenger
        self.client = client
        self.sessionProvider = sessionProvider
        self.livenessMargin = livenessMargin
        self.operationTimeout = operationTimeout
    }

    /// Establish the first subscription. Throws if that fails; later
    /// re-establishments are retried internally (Task 5).
    func start() async throws {
        try await establish()
    }

    public func cancel() async {
        guard !cancelled else { return }
        cancelled = true
        if let id = currentSubscriptionID, let sessionID = currentSessionID {
            await messenger.setSubscriptionHandler(nil, for: id, sessionID: sessionID)
            await client.remove(subscriptionID: id, peerNodeID: nodeID)
        }
        currentSubscriptionID = nil
        currentSessionID = nil
        continuation.finish()
    }

    // MARK: - Establishment

    /// The first event number to ask for: one past the highest delivered, or
    /// the caller's persisted minimum if nothing has been delivered yet.
    private var nextEventMin: EventNumber? {
        if let highest = highestEventNumber { return EventNumber(rawValue: highest.rawValue + 1) }
        return request.eventMin
    }

    private func establish() async throws {
        let sessionID = try await sessionProvider()
        let exchange = try await messenger.openExchange(sessionID: sessionID)
        var outgoing = request
        outgoing.eventMin = nextEventMin
        do {
            var message = try await exchange.request(
                protocolID: .interactionModel,
                opcode: InteractionModelOpcode.subscribeRequest.rawValue,
                payload: client.subscribeRequest(for: outgoing),
                timeout: operationTimeout
            )
            var priming: [SubscriptionReport] = []
            // Priming report: answer every chunk; SubscribeResponse follows the last one.
            while message.opcode == InteractionModelOpcode.reportData.rawValue {
                let report = try await client.record(reportData: message.payload, from: nodeID, at: messenger.clock.now)
                priming.append(report)
                message = try await exchange.request(
                    protocolID: .interactionModel,
                    opcode: InteractionModelOpcode.statusResponse.rawValue,
                    payload: IMStatusResponse.success.tlvEncode(),
                    timeout: operationTimeout
                )
            }
            if message.opcode == InteractionModelOpcode.statusResponse.rawValue {
                throw ControllerError.imStatus(try IMStatusResponse.fromTLV(message.payload).status)
            }
            guard message.opcode == InteractionModelOpcode.subscribeResponse.rawValue else {
                throw MessagingError.unexpectedProtocol(protocolID: message.protocolID, opcode: message.opcode)
            }
            let subscription = try await client.register(
                responseData: message.payload, peerNodeID: nodeID, request: request, at: messenger.clock.now
            )
            // Register before closing: a report sent right after SubscribeResponse
            // must reach this subscription, not the messenger's fallback.
            await messenger.setSubscriptionHandler(handler(for: subscription.subscriptionID), for: subscription.subscriptionID, sessionID: sessionID)
            await exchange.close()
            currentSubscriptionID = subscription.subscriptionID
            currentSessionID = sessionID
            continuation.yield(.established(subscription.subscriptionID, negotiatedMaxInterval: subscription.negotiatedMaxInterval))
            for report in priming { deliver(report) }
        } catch {
            await exchange.close()
            throw error
        }
    }

    // MARK: - Reports

    /// The messenger handler for one subscription ID: answer every chunk
    /// (unless the device suppressed the response), then hand the reports to
    /// the actor.
    private nonisolated func handler(for id: SubscriptionID) -> ControllerMessenger.UnsolicitedHandler {
        { [weak self] message, exchange in
            guard let self else { return }
            var current = message
            while true {
                guard let report = try? await self.client.record(reportData: current.payload, from: self.nodeID, at: self.messenger.clock.now) else { return }
                if !report.suppressResponse {
                    try? await exchange.send(
                        protocolID: .interactionModel,
                        opcode: InteractionModelOpcode.statusResponse.rawValue,
                        payload: IMStatusResponse.success.tlvEncode()
                    )
                }
                await self.deliver(report)
                guard report.moreChunkedMessages,
                      let next = try? await exchange.receive(timeout: self.operationTimeout) else { return }
                current = next
            }
        }
    }

    private func deliver(_ report: SubscriptionReport) {
        guard !cancelled else { return }
        let numbers = report.events.compactMap { $0.eventData?.eventNumber }
        if let highest = numbers.max() {
            highestEventNumber = max(highestEventNumber ?? highest, highest)
        }
        continuation.yield(.report(report))
    }
}
