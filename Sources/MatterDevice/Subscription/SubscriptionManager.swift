// SubscriptionManager.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Logging
import MatterTypes
import MatterProtocol

/// Manages active attribute subscriptions for a Matter device.
///
/// Tracks which attributes each subscriber is watching, enforces min/max
/// reporting intervals, and identifies when reports need to be sent.
public actor SubscriptionManager {

    // MARK: - Active Subscription

    struct ActiveSubscription {
        let subscriptionID: SubscriptionID
        let sessionID: UInt16
        let fabricIndex: FabricIndex
        let attributePaths: [AttributePath]
        let eventPaths: [EventPath]
        let minInterval: UInt16  // seconds
        let maxInterval: UInt16  // seconds
        var lastReportTime: Date
        var lastStatusResponseTime: Date
        var pendingReport: Bool
        /// Whether subscription reports should apply fabric-scoped attribute filtering.
        let isFabricFiltered: Bool
        /// Last event number included in a report for this subscription.
        var lastEventNumber: EventNumber
        /// Whether an urgent event is pending that should bypass the minInterval check.
        var urgentPending: Bool
        /// Data version filters provided at subscribe time, applied to periodic reports.
        let dataVersionFilters: [DataVersionFilter]
    }

    // MARK: - State

    private var subscriptions: [SubscriptionID: ActiveSubscription] = [:]
    private var nextID: UInt32 = 1
    private let logger = Logger(label: "matter.device.subscriptions")

    public init() {}

    // MARK: - Subscribe

    /// Create a new subscription from a SubscribeRequest.
    /// Returns (subscriptionID, negotiated maxInterval).
    public func subscribe(
        request: SubscribeRequest,
        sessionID: UInt16,
        fabricIndex: FabricIndex,
        now: Date = Date()
    ) -> (SubscriptionID, UInt16) {
        let subID = SubscriptionID(rawValue: nextID)
        nextID += 1

        // Negotiate max interval: at least minIntervalFloor, at most maxIntervalCeiling.
        // Server can pick anything in [minIntervalFloor, maxIntervalCeiling].
        let negotiatedMax = max(request.minIntervalFloor, min(request.maxIntervalCeiling, 60))

        subscriptions[subID] = ActiveSubscription(
            subscriptionID: subID,
            sessionID: sessionID,
            fabricIndex: fabricIndex,
            attributePaths: request.attributeRequests,
            eventPaths: request.eventRequests,
            minInterval: request.minIntervalFloor,
            maxInterval: negotiatedMax,
            lastReportTime: now,
            lastStatusResponseTime: now,
            pendingReport: false,
            isFabricFiltered: request.isFabricFiltered,
            lastEventNumber: EventNumber(rawValue: 0),
            urgentPending: false,
            dataVersionFilters: request.dataVersionFilters
        )

        return (subID, negotiatedMax)
    }

    // MARK: - Attribute Change Notification

    /// Mark subscriptions as needing a report when their watched attributes change.
    public func attributesChanged(_ paths: [AttributePath]) {
        for id in subscriptions.keys {
            guard let sub = subscriptions[id] else { continue }
            // Check if any changed path matches any subscribed path
            let matches = paths.contains { changed in
                sub.attributePaths.contains { subscribed in
                    pathMatches(subscribed: subscribed, changed: changed)
                }
            }
            if matches {
                subscriptions[id]?.pendingReport = true
                logger.trace("[SUB-NOTIFY] Sub \(id) marked pending (session=\(sub.sessionID), \(sub.attributePaths.count) paths)")
            } else {
                let subPathsDesc = sub.attributePaths.map { "ep\($0.endpointID?.rawValue.description ?? "*")/cl\($0.clusterID?.rawValue.description ?? "*")/at\($0.attributeID?.rawValue.description ?? "*")" }
                logger.trace("[SUB-NOTIFY] Sub \(id) NO MATCH: subPaths=\(subPathsDesc)")
            }
        }
    }

    // MARK: - Pending Reports

    /// Get subscriptions that need a report sent.
    /// Returns reports where either:
    /// - Attributes/events changed AND minInterval has elapsed since last report
    /// - An urgent event is pending (bypasses minInterval check)
    /// - maxInterval has elapsed since last report (keepalive)
    public func pendingReports(now: Date = Date()) -> [PendingReport] {
        var reports: [PendingReport] = []

        for (id, sub) in subscriptions {
            let sinceLastReport = now.timeIntervalSince(sub.lastReportTime)

            // Urgent event: bypass minInterval
            if sub.urgentPending {
                reports.append(PendingReport(
                    subscriptionID: id,
                    sessionID: sub.sessionID,
                    reason: .urgentEvent
                ))
            }
            // Change-driven report: attributes/events changed and minInterval elapsed
            else if sub.pendingReport && sinceLastReport >= Double(sub.minInterval) {
                reports.append(PendingReport(
                    subscriptionID: id,
                    sessionID: sub.sessionID,
                    reason: .attributeChanged
                ))
                logger.trace("[SUB-PENDING] Sub \(id) pending: reason=attributeChanged sinceLastReport=\(String(format: "%.1f", sinceLastReport))s minInterval=\(sub.minInterval)")
            } else if sub.pendingReport {
                logger.trace("[SUB-PENDING] Sub \(id) pendingReport=true but gated: sinceLastReport=\(String(format: "%.1f", sinceLastReport))s < minInterval=\(sub.minInterval)")
            }
            // Max interval keepalive
            else if sinceLastReport >= Double(sub.maxInterval) {
                reports.append(PendingReport(
                    subscriptionID: id,
                    sessionID: sub.sessionID,
                    reason: .maxIntervalElapsed
                ))
            }
        }

        return reports
    }

    /// Record that a report was sent for a subscription.
    public func reportSent(subscriptionID: SubscriptionID, now: Date = Date()) {
        subscriptions[subscriptionID]?.lastReportTime = now
        subscriptions[subscriptionID]?.pendingReport = false
        subscriptions[subscriptionID]?.urgentPending = false
    }

    /// Record that a StatusResponse was received (keeps subscription alive).
    public func statusResponseReceived(subscriptionID: SubscriptionID, now: Date = Date()) {
        subscriptions[subscriptionID]?.lastStatusResponseTime = now
    }

    // MARK: - Expiry

    /// Check for timed-out subscriptions.
    /// A subscription expires if no StatusResponse within maxInterval + margin.
    public func expireStale(now: Date = Date()) -> [SubscriptionID] {
        let margin: TimeInterval = 10  // 10 seconds grace period
        var expired: [SubscriptionID] = []

        for (id, sub) in subscriptions {
            let sinceLast = now.timeIntervalSince(sub.lastStatusResponseTime)
            if sinceLast > Double(sub.maxInterval) + margin {
                expired.append(id)
            }
        }

        for id in expired {
            subscriptions.removeValue(forKey: id)
        }

        return expired
    }

    // MARK: - Removal

    /// Remove a specific subscription.
    public func remove(subscriptionID: SubscriptionID) {
        subscriptions.removeValue(forKey: subscriptionID)
    }

    /// Remove all subscriptions for a session.
    public func removeAll(sessionID: UInt16) {
        subscriptions = subscriptions.filter { $0.value.sessionID != sessionID }
    }

    /// Remove all subscriptions for a fabric.
    public func removeAll(fabricIndex: FabricIndex) {
        subscriptions = subscriptions.filter { $0.value.fabricIndex != fabricIndex }
    }

    /// Number of active subscriptions.
    public var count: Int { subscriptions.count }

    // MARK: - Event Notifications

    /// Mark subscriptions as needing a report when an event is recorded.
    ///
    /// Subscriptions whose event paths match the event are marked as pending.
    /// If the event is urgent, the `urgentPending` flag is set to bypass minInterval.
    public func eventRecorded(_ event: StoredEvent) {
        for id in subscriptions.keys {
            guard let sub = subscriptions[id] else { continue }
            // Check if any subscribed event path matches this event
            let matches = sub.eventPaths.isEmpty || sub.eventPaths.contains { path in
                eventPathMatches(path: path, event: event)
            }
            if matches {
                subscriptions[id]?.pendingReport = true
                if event.isUrgent {
                    subscriptions[id]?.urgentPending = true
                }
            }
        }
    }

    /// Get the event paths for a subscription.
    public func eventPaths(for subscriptionID: SubscriptionID) -> [EventPath]? {
        subscriptions[subscriptionID]?.eventPaths
    }

    /// Get the last event number included in a report for a subscription.
    public func lastEventNumber(for subscriptionID: SubscriptionID) -> EventNumber? {
        subscriptions[subscriptionID]?.lastEventNumber
    }

    /// Update the last event number for a subscription after a report is sent.
    public func updateLastEventNumber(for subscriptionID: SubscriptionID, to eventNumber: EventNumber) {
        subscriptions[subscriptionID]?.lastEventNumber = eventNumber
    }

    // MARK: - Accessor Methods

    /// Get the attribute paths for a subscription (for building reports).
    public func attributePaths(for subscriptionID: SubscriptionID) -> [AttributePath]? {
        subscriptions[subscriptionID]?.attributePaths
    }

    /// Return whether the subscription was created with fabric filtering enabled.
    public func isFabricFiltered(for subscriptionID: SubscriptionID) -> Bool {
        subscriptions[subscriptionID]?.isFabricFiltered ?? true
    }

    /// Return the fabric index for a subscription (used when building fabric-filtered reports).
    public func fabricIndex(for subscriptionID: SubscriptionID) -> FabricIndex? {
        subscriptions[subscriptionID]?.fabricIndex
    }

    /// Return the data version filters for a subscription (used when building reports).
    ///
    /// The filters were supplied by the client at subscribe time. They are applied to
    /// every periodic report so unchanged clusters are silently omitted.
    public func dataVersionFilters(for subscriptionID: SubscriptionID) -> [DataVersionFilter] {
        subscriptions[subscriptionID]?.dataVersionFilters ?? []
    }

    // MARK: - Path Matching

    /// Check if a changed path matches a subscribed path.
    ///
    /// Each nil field in the subscribed path acts as a wildcard:
    /// - `endpointID: nil` matches any endpoint
    /// - `clusterID: nil` matches any cluster
    /// - `attributeID: nil` matches any attribute
    private func pathMatches(subscribed: AttributePath, changed: AttributePath) -> Bool {
        if let subEP = subscribed.endpointID {
            if subEP != changed.endpointID { return false }
        }
        if let subCluster = subscribed.clusterID {
            if subCluster != changed.clusterID { return false }
        }
        if let subAttr = subscribed.attributeID {
            if subAttr != changed.attributeID { return false }
        }
        return true
    }

    /// Check if a stored event matches a subscribed event path.
    ///
    /// Each nil field in the subscribed path acts as a wildcard.
    private func eventPathMatches(path: EventPath, event: StoredEvent) -> Bool {
        if let ep = path.endpointID, ep != event.endpointID { return false }
        if let cl = path.clusterID, cl != event.clusterID { return false }
        if let evID = path.eventID, evID != event.eventID { return false }
        return true
    }
}

// MARK: - Pending Report

/// A subscription report that needs to be sent.
public struct PendingReport: Sendable {
    public let subscriptionID: SubscriptionID
    public let sessionID: UInt16
    public let reason: ReportReason

    public enum ReportReason: Sendable {
        case attributeChanged
        case maxIntervalElapsed
        case urgentEvent
    }
}
