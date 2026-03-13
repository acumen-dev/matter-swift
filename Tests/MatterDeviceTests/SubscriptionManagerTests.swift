// SubscriptionManagerTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterProtocol
@testable import MatterDevice

private let testFabric = FabricIndex(rawValue: 1)
private let testSession: UInt16 = 100

private func makePath(
    endpoint: UInt16? = 1,
    cluster: UInt32 = 6,
    attribute: UInt32 = 0
) -> AttributePath {
    AttributePath(
        endpointID: endpoint.map { EndpointID(rawValue: $0) },
        clusterID: ClusterID(rawValue: cluster),
        attributeID: AttributeID(rawValue: attribute)
    )
}

private func makeRequest(
    paths: [AttributePath],
    minInterval: UInt16 = 5,
    maxInterval: UInt16 = 60
) -> SubscribeRequest {
    SubscribeRequest(
        minIntervalFloor: minInterval,
        maxIntervalCeiling: maxInterval,
        attributeRequests: paths
    )
}

@Suite("Subscription Manager")
struct SubscriptionManagerTests {

    // MARK: - Subscribe

    @Test("Create subscription assigns ID and negotiates maxInterval")
    func createSubscription() async {
        let manager = SubscriptionManager()
        let request = makeRequest(paths: [makePath()], minInterval: 5, maxInterval: 120)

        let (subID, negotiatedMax) = await manager.subscribe(
            request: request,
            sessionID: testSession,
            fabricIndex: testFabric
        )

        #expect(subID.rawValue == 1)
        // Negotiated max is min(maxIntervalCeiling, 60) clamped to >= minIntervalFloor
        #expect(negotiatedMax == 60)
        #expect(await manager.count == 1)
    }

    // MARK: - Attribute Changes

    @Test("attributesChanged marks matching subscription pending")
    func attributesChangedMarksMatching() async {
        let manager = SubscriptionManager()
        let path = makePath(endpoint: 1, cluster: 6, attribute: 0)
        let request = makeRequest(paths: [path])
        let baseDate = Date(timeIntervalSinceReferenceDate: 0)

        let (subID, _) = await manager.subscribe(
            request: request,
            sessionID: testSession,
            fabricIndex: testFabric,
            now: baseDate
        )

        // Notify that the subscribed attribute changed
        await manager.attributesChanged([path])

        // After minInterval elapses, pending report should appear
        let afterMin = baseDate.addingTimeInterval(6)
        let reports = await manager.pendingReports(now: afterMin)

        #expect(reports.count == 1)
        #expect(reports.first?.subscriptionID == subID)
        #expect(reports.first?.reason == .attributeChanged)
    }

    @Test("attributesChanged does NOT affect non-matching subscription")
    func attributesChangedNonMatching() async {
        let manager = SubscriptionManager()
        let subscribedPath = makePath(endpoint: 1, cluster: 6, attribute: 0)
        let changedPath = makePath(endpoint: 1, cluster: 8, attribute: 0)  // Different cluster
        let request = makeRequest(paths: [subscribedPath])
        let baseDate = Date(timeIntervalSinceReferenceDate: 0)

        _ = await manager.subscribe(
            request: request,
            sessionID: testSession,
            fabricIndex: testFabric,
            now: baseDate
        )

        await manager.attributesChanged([changedPath])

        let afterMin = baseDate.addingTimeInterval(6)
        let reports = await manager.pendingReports(now: afterMin)

        // No change-driven reports (could have keepalive if maxInterval elapsed, but 6s < 60s)
        #expect(reports.isEmpty)
    }

    // MARK: - Interval Enforcement

    @Test("pendingReports respects minInterval")
    func pendingReportsRespectsMinInterval() async {
        let manager = SubscriptionManager()
        let path = makePath()
        let request = makeRequest(paths: [path], minInterval: 10, maxInterval: 60)
        let baseDate = Date(timeIntervalSinceReferenceDate: 0)

        _ = await manager.subscribe(
            request: request,
            sessionID: testSession,
            fabricIndex: testFabric,
            now: baseDate
        )

        await manager.attributesChanged([path])

        // Before minInterval (10s) elapses — no report yet
        let tooEarly = baseDate.addingTimeInterval(5)
        let earlyReports = await manager.pendingReports(now: tooEarly)
        #expect(earlyReports.isEmpty)

        // After minInterval elapses — report available
        let afterMin = baseDate.addingTimeInterval(11)
        let lateReports = await manager.pendingReports(now: afterMin)
        #expect(lateReports.count == 1)
        #expect(lateReports.first?.reason == .attributeChanged)
    }

    @Test("pendingReports returns keepalive on maxInterval elapsed")
    func maxIntervalKeepalive() async {
        let manager = SubscriptionManager()
        let path = makePath()
        let request = makeRequest(paths: [path], minInterval: 5, maxInterval: 30)
        let baseDate = Date(timeIntervalSinceReferenceDate: 0)

        _ = await manager.subscribe(
            request: request,
            sessionID: testSession,
            fabricIndex: testFabric,
            now: baseDate
        )

        // No attribute changes — just let maxInterval elapse
        let afterMax = baseDate.addingTimeInterval(31)
        let reports = await manager.pendingReports(now: afterMax)

        #expect(reports.count == 1)
        #expect(reports.first?.reason == .maxIntervalElapsed)
    }

    // MARK: - Report Sent

    @Test("reportSent clears pending and updates lastReportTime")
    func reportSentClearsPending() async {
        let manager = SubscriptionManager()
        let path = makePath()
        let request = makeRequest(paths: [path], minInterval: 5, maxInterval: 60)
        let baseDate = Date(timeIntervalSinceReferenceDate: 0)

        let (subID, _) = await manager.subscribe(
            request: request,
            sessionID: testSession,
            fabricIndex: testFabric,
            now: baseDate
        )

        await manager.attributesChanged([path])

        let afterMin = baseDate.addingTimeInterval(6)
        let reportsBefore = await manager.pendingReports(now: afterMin)
        #expect(reportsBefore.count == 1)

        // Mark report as sent
        await manager.reportSent(subscriptionID: subID, now: afterMin)

        // Pending should be cleared
        let reportsAfter = await manager.pendingReports(now: afterMin)
        #expect(reportsAfter.isEmpty)
    }

    // MARK: - Status Response

    @Test("statusResponseReceived keeps subscription alive")
    func statusResponseKeepsAlive() async {
        let manager = SubscriptionManager()
        let path = makePath()
        let request = makeRequest(paths: [path], minInterval: 5, maxInterval: 30)
        let baseDate = Date(timeIntervalSinceReferenceDate: 0)

        let (subID, _) = await manager.subscribe(
            request: request,
            sessionID: testSession,
            fabricIndex: testFabric,
            now: baseDate
        )

        // Send a status response at t=25 (before maxInterval+margin=40)
        let t25 = baseDate.addingTimeInterval(25)
        await manager.statusResponseReceived(subscriptionID: subID, now: t25)

        // At t=45, subscription should still be alive because last status was at t=25
        // maxInterval(30) + margin(10) = 40 seconds from last status = t=65
        let t45 = baseDate.addingTimeInterval(45)
        let expired = await manager.expireStale(now: t45)
        #expect(expired.isEmpty)
        #expect(await manager.count == 1)
    }

    // MARK: - Expiry

    @Test("expireStale removes timed-out subscription")
    func expireStaleRemoves() async {
        let manager = SubscriptionManager()
        let path = makePath()
        let request = makeRequest(paths: [path], minInterval: 5, maxInterval: 30)
        let baseDate = Date(timeIntervalSinceReferenceDate: 0)

        let (subID, _) = await manager.subscribe(
            request: request,
            sessionID: testSession,
            fabricIndex: testFabric,
            now: baseDate
        )

        // Don't send any status response. At t=41 (> maxInterval 30 + margin 10),
        // the subscription should expire.
        let pastExpiry = baseDate.addingTimeInterval(41)
        let expired = await manager.expireStale(now: pastExpiry)

        #expect(expired.count == 1)
        #expect(expired.first == subID)
        #expect(await manager.count == 0)
    }

    // MARK: - Removal

    @Test("remove cleans up subscription")
    func removeSubscription() async {
        let manager = SubscriptionManager()
        let request = makeRequest(paths: [makePath()])

        let (subID, _) = await manager.subscribe(
            request: request,
            sessionID: testSession,
            fabricIndex: testFabric
        )

        #expect(await manager.count == 1)
        await manager.remove(subscriptionID: subID)
        #expect(await manager.count == 0)
    }

    @Test("removeAll(sessionID:) removes all for session")
    func removeAllBySession() async {
        let manager = SubscriptionManager()
        let request1 = makeRequest(paths: [makePath(endpoint: 1)])
        let request2 = makeRequest(paths: [makePath(endpoint: 2)])

        _ = await manager.subscribe(request: request1, sessionID: 100, fabricIndex: testFabric)
        _ = await manager.subscribe(request: request2, sessionID: 100, fabricIndex: testFabric)

        #expect(await manager.count == 2)
        await manager.removeAll(sessionID: 100)
        #expect(await manager.count == 0)
    }

    @Test("removeAll(fabricIndex:) removes all for fabric")
    func removeAllByFabric() async {
        let manager = SubscriptionManager()
        let fabric1 = FabricIndex(rawValue: 1)
        let fabric2 = FabricIndex(rawValue: 2)
        let request = makeRequest(paths: [makePath()])

        _ = await manager.subscribe(request: request, sessionID: 100, fabricIndex: fabric1)
        _ = await manager.subscribe(request: request, sessionID: 200, fabricIndex: fabric1)
        _ = await manager.subscribe(request: request, sessionID: 300, fabricIndex: fabric2)

        #expect(await manager.count == 3)
        await manager.removeAll(fabricIndex: fabric1)
        #expect(await manager.count == 1)  // Only fabric2 remains
    }

    // MARK: - Multiple Subscriptions

    @Test("Multiple subscriptions on different paths work independently")
    func multipleSubscriptionsIndependent() async {
        let manager = SubscriptionManager()
        let pathA = makePath(endpoint: 1, cluster: 6, attribute: 0)
        let pathB = makePath(endpoint: 2, cluster: 8, attribute: 0)
        let baseDate = Date(timeIntervalSinceReferenceDate: 0)

        let (subA, _) = await manager.subscribe(
            request: makeRequest(paths: [pathA]),
            sessionID: 100,
            fabricIndex: testFabric,
            now: baseDate
        )
        let (subB, _) = await manager.subscribe(
            request: makeRequest(paths: [pathB]),
            sessionID: 200,
            fabricIndex: testFabric,
            now: baseDate
        )

        // Change only pathA
        await manager.attributesChanged([pathA])

        let afterMin = baseDate.addingTimeInterval(6)
        let reports = await manager.pendingReports(now: afterMin)

        #expect(reports.count == 1)
        #expect(reports.first?.subscriptionID == subA)

        // subB should not appear (no change and maxInterval not elapsed)
        #expect(!reports.contains { $0.subscriptionID == subB })
    }

    // MARK: - Wildcard Endpoint

    @Test("Wildcard endpoint in subscription matches any endpoint")
    func wildcardEndpointMatches() async {
        let manager = SubscriptionManager()
        // Subscribe with nil endpointID (wildcard)
        let wildcardPath = makePath(endpoint: nil, cluster: 6, attribute: 0)
        let request = makeRequest(paths: [wildcardPath])
        let baseDate = Date(timeIntervalSinceReferenceDate: 0)

        let (subID, _) = await manager.subscribe(
            request: request,
            sessionID: testSession,
            fabricIndex: testFabric,
            now: baseDate
        )

        // Change on endpoint 5 — should match the wildcard subscription
        let changedPath = makePath(endpoint: 5, cluster: 6, attribute: 0)
        await manager.attributesChanged([changedPath])

        let afterMin = baseDate.addingTimeInterval(6)
        let reports = await manager.pendingReports(now: afterMin)

        #expect(reports.count == 1)
        #expect(reports.first?.subscriptionID == subID)
        #expect(reports.first?.reason == .attributeChanged)
    }

    // MARK: - Attribute Paths Lookup

    @Test("attributePaths returns subscribed paths")
    func attributePathsLookup() async {
        let manager = SubscriptionManager()
        let path = makePath(endpoint: 1, cluster: 6, attribute: 0)
        let request = makeRequest(paths: [path])

        let (subID, _) = await manager.subscribe(
            request: request,
            sessionID: testSession,
            fabricIndex: testFabric
        )

        let paths = await manager.attributePaths(for: subID)
        #expect(paths?.count == 1)
        #expect(paths?.first == path)
    }

    @Test("attributePaths returns nil for unknown subscription")
    func attributePathsUnknown() async {
        let manager = SubscriptionManager()
        let unknownID = SubscriptionID(rawValue: 999)

        let paths = await manager.attributePaths(for: unknownID)
        #expect(paths == nil)
    }

    // MARK: - Wildcard Cluster Matching

    @Test("Wildcard cluster in subscription matches any cluster change")
    func wildcardClusterMatches() async {
        let manager = SubscriptionManager()
        // Subscribe with nil clusterID (wildcard)
        let wildcardPath = AttributePath(
            endpointID: EndpointID(rawValue: 1),
            clusterID: nil,
            attributeID: AttributeID(rawValue: 0)
        )
        let request = makeRequest(paths: [wildcardPath])
        let baseDate = Date(timeIntervalSinceReferenceDate: 0)

        let (subID, _) = await manager.subscribe(
            request: request,
            sessionID: testSession,
            fabricIndex: testFabric,
            now: baseDate
        )

        // Change on a specific cluster — should match wildcard subscription
        let changedPath = makePath(endpoint: 1, cluster: 8, attribute: 0)
        await manager.attributesChanged([changedPath])

        let afterMin = baseDate.addingTimeInterval(6)
        let reports = await manager.pendingReports(now: afterMin)

        #expect(reports.count == 1)
        #expect(reports.first?.subscriptionID == subID)
    }

    @Test("Wildcard attribute in subscription matches any attribute change")
    func wildcardAttributeMatches() async {
        let manager = SubscriptionManager()
        // Subscribe with nil attributeID (wildcard)
        let wildcardPath = AttributePath(
            endpointID: EndpointID(rawValue: 1),
            clusterID: ClusterID(rawValue: 6),
            attributeID: nil
        )
        let request = makeRequest(paths: [wildcardPath])
        let baseDate = Date(timeIntervalSinceReferenceDate: 0)

        let (subID, _) = await manager.subscribe(
            request: request,
            sessionID: testSession,
            fabricIndex: testFabric,
            now: baseDate
        )

        // Change on a specific attribute — should match wildcard subscription
        let changedPath = makePath(endpoint: 1, cluster: 6, attribute: 99)
        await manager.attributesChanged([changedPath])

        let afterMin = baseDate.addingTimeInterval(6)
        let reports = await manager.pendingReports(now: afterMin)

        #expect(reports.count == 1)
        #expect(reports.first?.subscriptionID == subID)
    }

    @Test("Full wildcard subscription matches everything")
    func fullWildcardMatchesEverything() async {
        let manager = SubscriptionManager()
        // Subscribe with all-nil path (full wildcard)
        let wildcardPath = AttributePath(endpointID: nil, clusterID: nil, attributeID: nil)
        let request = makeRequest(paths: [wildcardPath])
        let baseDate = Date(timeIntervalSinceReferenceDate: 0)

        let (subID, _) = await manager.subscribe(
            request: request,
            sessionID: testSession,
            fabricIndex: testFabric,
            now: baseDate
        )

        // Any change should match
        let changedPath = makePath(endpoint: 42, cluster: 999, attribute: 777)
        await manager.attributesChanged([changedPath])

        let afterMin = baseDate.addingTimeInterval(6)
        let reports = await manager.pendingReports(now: afterMin)

        #expect(reports.count == 1)
        #expect(reports.first?.subscriptionID == subID)
    }
}
