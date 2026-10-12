// SubscriptionClient.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterProtocol

/// What a caller asks to subscribe to.
public struct SubscriptionRequest: Sendable, Equatable {
    public var attributePaths: [AttributePath]
    public var eventPaths: [EventPath]
    /// Minimum reporting interval floor, in seconds.
    public var minInterval: UInt16
    /// Maximum reporting interval ceiling requested, in seconds. The device may
    /// grant a longer interval (an ICD often does); liveness uses the granted one.
    public var maxInterval: UInt16
    /// The first event number wanted — a persisted high-water mark + 1 — so a
    /// new subscription does not replay events already delivered.
    public var eventMin: EventNumber?
    public var isFabricFiltered: Bool

    public init(
        attributePaths: [AttributePath] = [],
        eventPaths: [EventPath] = [],
        minInterval: UInt16 = 1,
        maxInterval: UInt16,
        eventMin: EventNumber? = nil,
        isFabricFiltered: Bool = true
    ) {
        self.attributePaths = attributePaths
        self.eventPaths = eventPaths
        self.minInterval = minInterval
        self.maxInterval = maxInterval
        self.eventMin = eventMin
        self.isFabricFiltered = isFabricFiltered
    }
}

/// One `ReportData`, parsed: attributes **and** events.
public struct SubscriptionReport: Sendable, Equatable {
    public let attributes: [AttributeReportIB]
    public let events: [EventReportIB]
    public let moreChunkedMessages: Bool
    /// The device does not want a `StatusResponse` for this report.
    public let suppressResponse: Bool
}

/// A client-side subscription record.
public struct ClientSubscription: Sendable, Equatable {
    public let subscriptionID: SubscriptionID
    public let peerNodeID: NodeID
    public let request: SubscriptionRequest
    /// The max interval the device granted in `SubscribeResponse`, in seconds.
    public let negotiatedMaxInterval: UInt16
    public let establishedAt: ContinuousClock.Instant
    public var lastReportAt: ContinuousClock.Instant
    /// The highest event number delivered on this subscription.
    public var highestEventNumber: EventNumber?

    /// When the subscription is dead if no report has arrived: the last report
    /// plus the **negotiated** max interval plus `margin` (the MRP exhaustion
    /// horizon for the peer, so a report still being retransmitted is not
    /// mistaken for silence).
    public func livenessDeadline(margin: Duration) -> ContinuousClock.Instant {
        lastReportAt + .seconds(Int(negotiatedMaxInterval)) + margin
    }
}

/// Bookkeeping for the controller's subscriptions: builds requests, registers
/// the device's `SubscribeResponse`, and records reports (attributes, events,
/// the event high-water mark and the last-report time).
public actor SubscriptionClient {

    private var subscriptions: [SubscriptionID: ClientSubscription] = [:]

    public init() {}

    /// Encode a `SubscribeRequest`. `eventMin` becomes the event filter; pass
    /// `nil` to receive whatever the device holds.
    public nonisolated func subscribeRequest(for request: SubscriptionRequest, eventMin: EventNumber?) -> Data {
        SubscribeRequest(
            keepSubscriptions: true,
            minIntervalFloor: request.minInterval,
            maxIntervalCeiling: request.maxInterval,
            attributeRequests: request.attributePaths,
            eventRequests: request.eventPaths,
            eventFilters: eventMin.map { [EventFilterIB(nodeID: nil, eventMin: $0)] } ?? [],
            isFabricFiltered: request.isFabricFiltered
        ).tlvEncode()
    }

    /// Register a subscription from the device's `SubscribeResponse`.
    public func register(
        responseData: Data,
        peerNodeID: NodeID,
        request: SubscriptionRequest,
        at now: ContinuousClock.Instant
    ) throws -> ClientSubscription {
        let response = try SubscribeResponse.fromTLV(responseData)
        let subscription = ClientSubscription(
            subscriptionID: response.subscriptionID,
            peerNodeID: peerNodeID,
            request: request,
            negotiatedMaxInterval: response.maxInterval,
            establishedAt: now,
            lastReportAt: now,
            highestEventNumber: nil
        )
        subscriptions[response.subscriptionID] = subscription
        return subscription
    }

    /// Parse a `ReportData`. If it names a known subscription, update that
    /// subscription's last-report time and event high-water mark.
    public func record(reportData: Data, at now: ContinuousClock.Instant) throws -> SubscriptionReport {
        let report = try ReportData.fromTLV(reportData)
        if let id = report.subscriptionID, var subscription = subscriptions[id] {
            subscription.lastReportAt = now
            let numbers = report.eventReports.compactMap { $0.eventData?.eventNumber }
            if let highest = numbers.max() {
                subscription.highestEventNumber = max(subscription.highestEventNumber ?? highest, highest)
            }
            subscriptions[id] = subscription
        }
        return SubscriptionReport(
            attributes: report.attributeReports,
            events: report.eventReports,
            moreChunkedMessages: report.moreChunkedMessages,
            suppressResponse: report.suppressResponse
        )
    }

    public func subscription(for id: SubscriptionID) -> ClientSubscription? {
        subscriptions[id]
    }

    public func remove(subscriptionID: SubscriptionID) {
        subscriptions.removeValue(forKey: subscriptionID)
    }

    public var activeSubscriptions: [ClientSubscription] {
        Array(subscriptions.values)
    }

    public var count: Int {
        subscriptions.count
    }
}
