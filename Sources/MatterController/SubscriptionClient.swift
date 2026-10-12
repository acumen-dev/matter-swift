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
    /// The first event number to request. Callers pass a persisted high-water
    /// mark + 1 so a new subscription does not replay events already delivered;
    /// `nil` requests whatever the device holds.
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

    public init(
        attributes: [AttributeReportIB],
        events: [EventReportIB],
        moreChunkedMessages: Bool = false,
        suppressResponse: Bool = false
    ) {
        self.attributes = attributes
        self.events = events
        self.moreChunkedMessages = moreChunkedMessages
        self.suppressResponse = suppressResponse
    }
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

    public init(
        subscriptionID: SubscriptionID,
        peerNodeID: NodeID,
        request: SubscriptionRequest,
        negotiatedMaxInterval: UInt16,
        establishedAt: ContinuousClock.Instant,
        lastReportAt: ContinuousClock.Instant,
        highestEventNumber: EventNumber? = nil
    ) {
        self.subscriptionID = subscriptionID
        self.peerNodeID = peerNodeID
        self.request = request
        self.negotiatedMaxInterval = negotiatedMaxInterval
        self.establishedAt = establishedAt
        self.lastReportAt = lastReportAt
        self.highestEventNumber = highestEventNumber
    }

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
///
/// Subscription IDs are assigned by each device, so records are keyed by the
/// pair (peer node, subscription ID).
public actor SubscriptionClient {

    private struct Key: Hashable, Sendable {
        let peerNodeID: NodeID
        let subscriptionID: SubscriptionID
    }

    private var subscriptions: [Key: ClientSubscription] = [:]

    public init() {}

    /// Encode a `SubscribeRequest` from `request`. Its `eventMin`, when set,
    /// becomes the event filter; when `nil`, no filter is sent.
    public nonisolated func subscribeRequest(for request: SubscriptionRequest) -> Data {
        SubscribeRequest(
            keepSubscriptions: true,
            minIntervalFloor: request.minInterval,
            maxIntervalCeiling: request.maxInterval,
            attributeRequests: request.attributePaths,
            eventRequests: request.eventPaths,
            eventFilters: request.eventMin.map { [EventFilterIB(nodeID: nil, eventMin: $0)] } ?? [],
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
            lastReportAt: now
        )
        subscriptions[Key(peerNodeID: peerNodeID, subscriptionID: response.subscriptionID)] = subscription
        return subscription
    }

    /// Parse a `ReportData` received from `peerNodeID`. If it names a subscription
    /// registered with that peer, update that record's last-report time and event
    /// high-water mark. The mark never moves backwards.
    public func record(reportData: Data, from peerNodeID: NodeID, at now: ContinuousClock.Instant) throws -> SubscriptionReport {
        let report = try ReportData.fromTLV(reportData)
        if let id = report.subscriptionID {
            let key = Key(peerNodeID: peerNodeID, subscriptionID: id)
            if var subscription = subscriptions[key] {
                subscription.lastReportAt = now
                let numbers = report.eventReports.compactMap { $0.eventData?.eventNumber }
                if let highest = numbers.max() {
                    subscription.highestEventNumber = max(subscription.highestEventNumber ?? highest, highest)
                }
                subscriptions[key] = subscription
            }
        }
        return SubscriptionReport(
            attributes: report.attributeReports,
            events: report.eventReports,
            moreChunkedMessages: report.moreChunkedMessages,
            suppressResponse: report.suppressResponse
        )
    }

    public func subscription(for id: SubscriptionID, peerNodeID: NodeID) -> ClientSubscription? {
        subscriptions[Key(peerNodeID: peerNodeID, subscriptionID: id)]
    }

    public func remove(subscriptionID: SubscriptionID, peerNodeID: NodeID) {
        subscriptions.removeValue(forKey: Key(peerNodeID: peerNodeID, subscriptionID: subscriptionID))
    }

    public var activeSubscriptions: [ClientSubscription] {
        Array(subscriptions.values)
    }

    public var count: Int {
        subscriptions.count
    }
}
