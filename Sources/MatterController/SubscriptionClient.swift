// SubscriptionClient.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterProtocol

/// A client-side subscription tracking record.
public struct ClientSubscription: Sendable, Equatable {
    /// Server-assigned subscription ID.
    public let subscriptionID: SubscriptionID

    /// Peer node ID (the device being subscribed to).
    public let peerNodeID: NodeID

    /// Attribute paths being subscribed to.
    public let attributePaths: [AttributePath]

    /// Negotiated maximum reporting interval (seconds).
    public let maxIntervalSeconds: UInt16

    /// When this subscription was established.
    public let establishedAt: Date

    /// When the last report was received.
    public var lastReportAt: Date

    public init(
        subscriptionID: SubscriptionID,
        peerNodeID: NodeID,
        attributePaths: [AttributePath],
        maxIntervalSeconds: UInt16,
        establishedAt: Date = Date(),
        lastReportAt: Date? = nil
    ) {
        self.subscriptionID = subscriptionID
        self.peerNodeID = peerNodeID
        self.attributePaths = attributePaths
        self.maxIntervalSeconds = maxIntervalSeconds
        self.establishedAt = establishedAt
        self.lastReportAt = lastReportAt ?? establishedAt
    }

    /// Whether this subscription has expired (no report within 2x max interval).
    public func isExpired(now: Date = Date()) -> Bool {
        let deadline = lastReportAt.addingTimeInterval(Double(maxIntervalSeconds) * 2.0)
        return now > deadline
    }
}

/// Client-side subscription manager.
///
/// Tracks active subscriptions, builds subscribe requests, and parses
/// incoming report data. Thread-safe via actor isolation.
///
/// ```swift
/// let client = SubscriptionClient()
/// let reqData = client.createSubscribeRequest(
///     attributePaths: [path],
///     minIntervalFloor: 1,
///     maxIntervalCeiling: 60
/// )
/// // ... send request, receive SubscribeResponse ...
/// let sub = try await client.handleSubscribeResponse(
///     responseData: respData,
///     peerNodeID: deviceNodeID,
///     attributePaths: [path]
/// )
/// // ... later, receive ReportData ...
/// let reports = try await client.handleReportData(data: reportData)
/// ```
public actor SubscriptionClient {

    private var subscriptions: [SubscriptionID: ClientSubscription] = [:]

    public init() {}

    // MARK: - Subscribe Request

    /// Build a SubscribeRequest for attribute paths.
    ///
    /// This is a non-isolated helper (no state mutation needed).
    public nonisolated func createSubscribeRequest(
        attributePaths: [AttributePath],
        minIntervalFloor: UInt16 = 1,
        maxIntervalCeiling: UInt16 = 60,
        keepSubscriptions: Bool = true,
        isFabricFiltered: Bool = true
    ) -> Data {
        let request = SubscribeRequest(
            keepSubscriptions: keepSubscriptions,
            minIntervalFloor: minIntervalFloor,
            maxIntervalCeiling: maxIntervalCeiling,
            attributeRequests: attributePaths,
            isFabricFiltered: isFabricFiltered
        )
        return request.tlvEncode()
    }

    // MARK: - Subscribe Response

    /// Process a SubscribeResponse and register the subscription.
    ///
    /// - Parameters:
    ///   - responseData: TLV-encoded SubscribeResponse.
    ///   - peerNodeID: The device's node ID.
    ///   - attributePaths: The paths originally subscribed to.
    /// - Returns: The registered client subscription.
    public func handleSubscribeResponse(
        responseData: Data,
        peerNodeID: NodeID,
        attributePaths: [AttributePath]
    ) throws -> ClientSubscription {
        let response = try SubscribeResponse.fromTLV(responseData)

        let subscription = ClientSubscription(
            subscriptionID: response.subscriptionID,
            peerNodeID: peerNodeID,
            attributePaths: attributePaths,
            maxIntervalSeconds: response.maxInterval
        )

        subscriptions[response.subscriptionID] = subscription
        return subscription
    }

    // MARK: - Report Data

    /// Process incoming ReportData and update the subscription's last report time.
    ///
    /// Returns the parsed attribute reports for the caller to process.
    public func handleReportData(
        data: Data,
        subscriptionID: SubscriptionID? = nil
    ) throws -> [AttributeReportIB] {
        let report = try ReportData.fromTLV(data)

        // Update last report time if we have a subscription ID
        if let subID = subscriptionID ?? report.subscriptionID {
            if var sub = subscriptions[subID] {
                sub.lastReportAt = Date()
                subscriptions[subID] = sub
            }
        }

        return report.attributeReports
    }

    // MARK: - Queries

    /// Look up a subscription by ID.
    public func subscription(for id: SubscriptionID) -> ClientSubscription? {
        subscriptions[id]
    }

    /// Remove a subscription.
    public func remove(subscriptionID: SubscriptionID) {
        subscriptions.removeValue(forKey: subscriptionID)
    }

    /// All active subscriptions.
    public var activeSubscriptions: [ClientSubscription] {
        Array(subscriptions.values)
    }

    /// Find subscriptions that have expired (no report within 2x max interval).
    public func expiredSubscriptions(now: Date = Date()) -> [ClientSubscription] {
        subscriptions.values.filter { $0.isExpired(now: now) }
    }

    /// The number of active subscriptions.
    public var count: Int {
        subscriptions.count
    }
}
