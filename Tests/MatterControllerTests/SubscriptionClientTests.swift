// SubscriptionClientTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterProtocol
@testable import MatterController

@Suite("SubscriptionClient")
struct SubscriptionClientTests {

    private let node = NodeID(rawValue: 0x1234)
    private let otherNode = NodeID(rawValue: 0x5678)
    private let onOff = AttributePath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0006), attributeID: AttributeID(rawValue: 0))
    private let lockOps = EventPath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0101), eventID: EventID(rawValue: 0x02))
    private let t0 = ContinuousClock().now

    private func request(eventMin: EventNumber? = nil) -> SubscriptionRequest {
        SubscriptionRequest(attributePaths: [onOff], eventPaths: [lockOps], minInterval: 1, maxInterval: 60, eventMin: eventMin)
    }

    private func event(_ number: UInt64) -> EventReportIB {
        EventReportIB(eventData: EventDataIB(path: lockOps, eventNumber: EventNumber(rawValue: number), priority: .info, data: .structure([])))
    }

    private func reportData(id: UInt32 = 5, events: [UInt64] = [], suppressResponse: Bool = false) -> Data {
        ReportData(
            subscriptionID: SubscriptionID(rawValue: id),
            eventReports: events.map { event($0) },
            suppressResponse: suppressResponse
        ).tlvEncode()
    }

    private func register(
        _ client: SubscriptionClient,
        id: UInt32 = 5,
        peer: NodeID? = nil,
        maxInterval: UInt16 = 600
    ) async throws -> ClientSubscription {
        try await client.register(
            responseData: SubscribeResponse(subscriptionID: SubscriptionID(rawValue: id), maxInterval: maxInterval).tlvEncode(),
            peerNodeID: peer ?? node, request: request(), at: t0
        )
    }

    @Test("The request carries attribute paths, event paths, intervals and the event filter")
    func requestEncoding() throws {
        let data = SubscriptionClient().subscribeRequest(for: request(eventMin: EventNumber(rawValue: 42)))
        let decoded = try SubscribeRequest.fromTLV(data)
        #expect(decoded.attributeRequests == [onOff])
        #expect(decoded.eventRequests == [lockOps])
        #expect(decoded.minIntervalFloor == 1 && decoded.maxIntervalCeiling == 60)
        #expect(decoded.eventFilters.map(\.eventMin) == [EventNumber(rawValue: 42)])
    }

    @Test("No event filter is sent when the request has no eventMin")
    func noFilterWithoutMinimum() throws {
        let decoded = try SubscribeRequest.fromTLV(SubscriptionClient().subscribeRequest(for: request(eventMin: nil)))
        #expect(decoded.eventFilters.isEmpty)
    }

    @Test("Liveness is judged on the negotiated max interval plus the margin, not the requested one")
    func negotiatedInterval() async throws {
        let sub = try await register(SubscriptionClient(), maxInterval: 600)   // asked for 60, granted 600
        #expect(sub.negotiatedMaxInterval == 600)
        #expect(sub.livenessDeadline(margin: .seconds(9)) == t0 + .seconds(609))
    }

    @Test("A fresh registration has no event high-water mark")
    func noMarkAfterRegister() async throws {
        let client = SubscriptionClient()
        let sub = try await register(client)
        #expect(sub.highestEventNumber == nil)
        #expect(await client.subscription(for: SubscriptionID(rawValue: 5), peerNodeID: node)?.highestEventNumber == nil)
    }

    @Test("Reports keep events, advance the high-water mark and the last-report time")
    func reportsKeepEvents() async throws {
        let client = SubscriptionClient()
        _ = try await register(client)
        let report = try await client.record(reportData: reportData(events: [7, 9, 8]), from: node, at: t0 + .seconds(30))
        #expect(report.events.count == 3)
        let sub = try #require(await client.subscription(for: SubscriptionID(rawValue: 5), peerNodeID: node))
        #expect(sub.highestEventNumber == EventNumber(rawValue: 9))
        #expect(sub.lastReportAt == t0 + .seconds(30))
    }

    @Test("The high-water mark does not regress when a later report carries only lower events")
    func markDoesNotRegress() async throws {
        let client = SubscriptionClient()
        _ = try await register(client)
        _ = try await client.record(reportData: reportData(events: [9]), from: node, at: t0 + .seconds(10))
        _ = try await client.record(reportData: reportData(events: [3, 4]), from: node, at: t0 + .seconds(20))
        let sub = try #require(await client.subscription(for: SubscriptionID(rawValue: 5), peerNodeID: node))
        #expect(sub.highestEventNumber == EventNumber(rawValue: 9))
        #expect(sub.lastReportAt == t0 + .seconds(20))
    }

    @Test("Two peers registering the same subscription ID stay separate")
    func peersAreKeptApart() async throws {
        let client = SubscriptionClient()
        _ = try await register(client, peer: node)
        _ = try await register(client, peer: otherNode)
        #expect(await client.count == 2)

        _ = try await client.record(reportData: reportData(events: [4]), from: node, at: t0 + .seconds(30))

        let mine = try #require(await client.subscription(for: SubscriptionID(rawValue: 5), peerNodeID: node))
        let theirs = try #require(await client.subscription(for: SubscriptionID(rawValue: 5), peerNodeID: otherNode))
        #expect(mine.lastReportAt == t0 + .seconds(30))
        #expect(mine.highestEventNumber == EventNumber(rawValue: 4))
        #expect(theirs.lastReportAt == t0)
        #expect(theirs.highestEventNumber == nil)
    }

    @Test("A report for an unknown subscription is still parsed but changes nothing")
    func unknownSubscription() async throws {
        let client = SubscriptionClient()
        let report = try await client.record(reportData: reportData(id: 99, suppressResponse: true), from: node, at: t0)
        #expect(report.suppressResponse)
        #expect(await client.count == 0)
    }

    @Test("A report naming a subscription registered with a different peer leaves the record unchanged")
    func unknownPairLeavesRecordAlone() async throws {
        let client = SubscriptionClient()
        _ = try await register(client, peer: node)
        _ = try await client.record(reportData: reportData(events: [6]), from: otherNode, at: t0 + .seconds(40))
        let sub = try #require(await client.subscription(for: SubscriptionID(rawValue: 5), peerNodeID: node))
        #expect(sub.lastReportAt == t0)
        #expect(sub.highestEventNumber == nil)
    }

    @Test("Lookup returns nil for an unknown (peer, subscription) pair")
    func lookupUnknownPair() async throws {
        let client = SubscriptionClient()
        _ = try await register(client, id: 5, peer: node)
        #expect(await client.subscription(for: SubscriptionID(rawValue: 6), peerNodeID: node) == nil)
        #expect(await client.subscription(for: SubscriptionID(rawValue: 5), peerNodeID: otherNode) == nil)
    }

    @Test("Remove deletes only the named (peer, subscription) record")
    func removeRoundTrip() async throws {
        let client = SubscriptionClient()
        _ = try await register(client, peer: node)
        _ = try await register(client, peer: otherNode)
        await client.remove(subscriptionID: SubscriptionID(rawValue: 5), peerNodeID: node)
        #expect(await client.count == 1)
        let remaining = await client.activeSubscriptions
        #expect(remaining.map(\.peerNodeID) == [otherNode])
        #expect(await client.subscription(for: SubscriptionID(rawValue: 5), peerNodeID: node) == nil)
    }
}
