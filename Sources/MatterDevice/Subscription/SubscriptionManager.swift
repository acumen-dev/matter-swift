// SubscriptionManager.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
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
        let minInterval: UInt16  // seconds
        let maxInterval: UInt16  // seconds
        var lastReportTime: Date
        var lastStatusResponseTime: Date
        var pendingReport: Bool
    }

    // MARK: - State

    private var subscriptions: [SubscriptionID: ActiveSubscription] = [:]
    private var nextID: UInt32 = 1

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
            minInterval: request.minIntervalFloor,
            maxInterval: negotiatedMax,
            lastReportTime: now,
            lastStatusResponseTime: now,
            pendingReport: false
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
            }
        }
    }

    // MARK: - Pending Reports

    /// Get subscriptions that need a report sent.
    /// Returns reports where either:
    /// - Attributes changed AND minInterval has elapsed since last report
    /// - maxInterval has elapsed since last report (keepalive)
    public func pendingReports(now: Date = Date()) -> [PendingReport] {
        var reports: [PendingReport] = []

        for (id, sub) in subscriptions {
            let sinceLastReport = now.timeIntervalSince(sub.lastReportTime)

            // Change-driven report: attributes changed and minInterval elapsed
            if sub.pendingReport && sinceLastReport >= Double(sub.minInterval) {
                reports.append(PendingReport(
                    subscriptionID: id,
                    sessionID: sub.sessionID,
                    reason: .attributeChanged
                ))
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

    /// Get the attribute paths for a subscription (for building reports).
    public func attributePaths(for subscriptionID: SubscriptionID) -> [AttributePath]? {
        subscriptions[subscriptionID]?.attributePaths
    }

    // MARK: - Path Matching

    /// Check if a changed path matches a subscribed path.
    /// Subscribed paths can have wildcard endpointID (nil).
    private func pathMatches(subscribed: AttributePath, changed: AttributePath) -> Bool {
        // Wildcard endpoint in subscription matches any endpoint
        if let subEP = subscribed.endpointID {
            if subEP != changed.endpointID { return false }
        }
        return subscribed.clusterID == changed.clusterID
            && subscribed.attributeID == changed.attributeID
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
    }
}
