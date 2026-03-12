// SubscriptionClientTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
@testable import MatterController
@testable import MatterProtocol
import MatterTypes

@Suite("SubscriptionClient")
struct SubscriptionClientTests {

    private func makePath(
        endpoint: UInt16 = 1,
        cluster: UInt32 = 0x0006,
        attribute: UInt32 = 0x0000
    ) -> AttributePath {
        AttributePath(
            endpointID: EndpointID(rawValue: endpoint),
            clusterID: ClusterID(rawValue: cluster),
            attributeID: AttributeID(rawValue: attribute)
        )
    }

    @Test("Create subscribe request produces data")
    func createSubscribeRequest() {
        let client = SubscriptionClient()
        let path = makePath()

        let data = client.createSubscribeRequest(
            attributePaths: [path],
            minIntervalFloor: 1,
            maxIntervalCeiling: 60
        )

        #expect(data.count > 0)
    }

    @Test("Subscribe request is parseable")
    func subscribeRequestParseable() throws {
        let client = SubscriptionClient()
        let path = makePath()

        let data = client.createSubscribeRequest(
            attributePaths: [path],
            minIntervalFloor: 5,
            maxIntervalCeiling: 120
        )

        let parsed = try SubscribeRequest.fromTLV(data)
        #expect(parsed.minIntervalFloor == 5)
        #expect(parsed.maxIntervalCeiling == 120)
        #expect(parsed.keepSubscriptions == true)
        #expect(parsed.attributeRequests.count == 1)
    }

    @Test("Handle subscribe response registers subscription")
    func handleSubscribeResponse() async throws {
        let client = SubscriptionClient()
        let path = makePath()

        // Build a SubscribeResponse
        let response = SubscribeResponse(
            subscriptionID: SubscriptionID(rawValue: 42),
            maxInterval: 60
        )
        let responseData = response.tlvEncode()

        let sub = try await client.handleSubscribeResponse(
            responseData: responseData,
            peerNodeID: NodeID(rawValue: 10),
            attributePaths: [path]
        )

        #expect(sub.subscriptionID.rawValue == 42)
        #expect(sub.peerNodeID.rawValue == 10)
        #expect(sub.maxIntervalSeconds == 60)

        // Should be findable
        let found = await client.subscription(for: SubscriptionID(rawValue: 42))
        #expect(found != nil)
    }

    @Test("Subscription count tracks registrations")
    func subscriptionCount() async throws {
        let client = SubscriptionClient()
        let path = makePath()

        let resp1 = SubscribeResponse(subscriptionID: SubscriptionID(rawValue: 1), maxInterval: 60)
        let resp2 = SubscribeResponse(subscriptionID: SubscriptionID(rawValue: 2), maxInterval: 30)

        _ = try await client.handleSubscribeResponse(
            responseData: resp1.tlvEncode(),
            peerNodeID: NodeID(rawValue: 10),
            attributePaths: [path]
        )
        _ = try await client.handleSubscribeResponse(
            responseData: resp2.tlvEncode(),
            peerNodeID: NodeID(rawValue: 20),
            attributePaths: [path]
        )

        let count = await client.count
        #expect(count == 2)
    }

    @Test("Remove subscription")
    func removeSubscription() async throws {
        let client = SubscriptionClient()
        let path = makePath()

        let response = SubscribeResponse(subscriptionID: SubscriptionID(rawValue: 42), maxInterval: 60)
        _ = try await client.handleSubscribeResponse(
            responseData: response.tlvEncode(),
            peerNodeID: NodeID(rawValue: 10),
            attributePaths: [path]
        )

        await client.remove(subscriptionID: SubscriptionID(rawValue: 42))

        let found = await client.subscription(for: SubscriptionID(rawValue: 42))
        #expect(found == nil)

        let count = await client.count
        #expect(count == 0)
    }

    @Test("Subscription expiry detection")
    func subscriptionExpiry() {
        let now = Date()
        let sub = ClientSubscription(
            subscriptionID: SubscriptionID(rawValue: 1),
            peerNodeID: NodeID(rawValue: 10),
            attributePaths: [],
            maxIntervalSeconds: 60,
            establishedAt: now,
            lastReportAt: now
        )

        // Not expired immediately
        #expect(sub.isExpired(now: now) == false)

        // Not expired at maxInterval
        let atMax = now.addingTimeInterval(60)
        #expect(sub.isExpired(now: atMax) == false)

        // Expired at 2x maxInterval + 1
        let expired = now.addingTimeInterval(121)
        #expect(sub.isExpired(now: expired) == true)
    }

    @Test("Expired subscriptions query")
    func expiredSubscriptionsQuery() async throws {
        let client = SubscriptionClient()
        let path = makePath()
        let now = Date()

        let resp1 = SubscribeResponse(subscriptionID: SubscriptionID(rawValue: 1), maxInterval: 10)
        let resp2 = SubscribeResponse(subscriptionID: SubscriptionID(rawValue: 2), maxInterval: 600)

        _ = try await client.handleSubscribeResponse(
            responseData: resp1.tlvEncode(),
            peerNodeID: NodeID(rawValue: 10),
            attributePaths: [path]
        )
        _ = try await client.handleSubscribeResponse(
            responseData: resp2.tlvEncode(),
            peerNodeID: NodeID(rawValue: 20),
            attributePaths: [path]
        )

        // At 21 seconds, sub1 (maxInterval=10, 2x=20) should be expired
        let future = now.addingTimeInterval(21)
        let expired = await client.expiredSubscriptions(now: future)

        #expect(expired.count == 1)
        #expect(expired[0].subscriptionID.rawValue == 1)
    }

    @Test("Active subscriptions returns all")
    func activeSubscriptions() async throws {
        let client = SubscriptionClient()
        let path = makePath()

        let resp1 = SubscribeResponse(subscriptionID: SubscriptionID(rawValue: 1), maxInterval: 60)
        let resp2 = SubscribeResponse(subscriptionID: SubscriptionID(rawValue: 2), maxInterval: 60)

        _ = try await client.handleSubscribeResponse(
            responseData: resp1.tlvEncode(),
            peerNodeID: NodeID(rawValue: 10),
            attributePaths: [path]
        )
        _ = try await client.handleSubscribeResponse(
            responseData: resp2.tlvEncode(),
            peerNodeID: NodeID(rawValue: 20),
            attributePaths: [path]
        )

        let active = await client.activeSubscriptions
        #expect(active.count == 2)
    }

    @Test("Lookup returns nil for unknown subscription")
    func lookupUnknown() async {
        let client = SubscriptionClient()
        let found = await client.subscription(for: SubscriptionID(rawValue: 999))
        #expect(found == nil)
    }
}
