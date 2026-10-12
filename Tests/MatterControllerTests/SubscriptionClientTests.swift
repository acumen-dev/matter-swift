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
    private let onOff = AttributePath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0006), attributeID: AttributeID(rawValue: 0))
    private let lockOps = EventPath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0101), eventID: EventID(rawValue: 0x02))
    private let t0 = ContinuousClock().now

    private func request(eventMin: EventNumber? = nil) -> SubscriptionRequest {
        SubscriptionRequest(attributePaths: [onOff], eventPaths: [lockOps], minInterval: 1, maxInterval: 60, eventMin: eventMin)
    }

    private func event(_ number: UInt64) -> EventReportIB {
        EventReportIB(eventData: EventDataIB(path: lockOps, eventNumber: EventNumber(rawValue: number), priority: .info, data: .structure([])))
    }

    private func register(_ client: SubscriptionClient, id: UInt32 = 5, maxInterval: UInt16 = 600) async throws -> ClientSubscription {
        try await client.register(
            responseData: SubscribeResponse(subscriptionID: SubscriptionID(rawValue: id), maxInterval: maxInterval).tlvEncode(),
            peerNodeID: node, request: request(), at: t0
        )
    }

    @Test("The request carries attribute paths, event paths, intervals and the event filter")
    func requestEncoding() throws {
        let data = SubscriptionClient().subscribeRequest(for: request(), eventMin: EventNumber(rawValue: 42))
        let decoded = try SubscribeRequest.fromTLV(data)
        #expect(decoded.attributeRequests == [onOff])
        #expect(decoded.eventRequests == [lockOps])
        #expect(decoded.minIntervalFloor == 1 && decoded.maxIntervalCeiling == 60)
        #expect(decoded.eventFilters.map(\.eventMin) == [EventNumber(rawValue: 42)])
    }

    @Test("No event filter is sent when no minimum is known")
    func noFilterWithoutMinimum() throws {
        let decoded = try SubscribeRequest.fromTLV(SubscriptionClient().subscribeRequest(for: request(), eventMin: nil))
        #expect(decoded.eventFilters.isEmpty)
    }

    @Test("Liveness is judged on the negotiated max interval plus the margin, not the requested one")
    func negotiatedInterval() async throws {
        let sub = try await register(SubscriptionClient(), maxInterval: 600)   // asked for 60, granted 600
        #expect(sub.negotiatedMaxInterval == 600)
        #expect(sub.livenessDeadline(margin: .seconds(9)) == t0 + .seconds(609))
    }

    @Test("Reports keep events, advance the high-water mark and the last-report time")
    func reportsKeepEvents() async throws {
        let client = SubscriptionClient()
        _ = try await register(client)
        let data = ReportData(subscriptionID: SubscriptionID(rawValue: 5), eventReports: [event(7), event(9), event(8)]).tlvEncode()
        let report = try await client.record(reportData: data, at: t0 + .seconds(30))
        #expect(report.events.count == 3)
        let sub = try #require(await client.subscription(for: SubscriptionID(rawValue: 5)))
        #expect(sub.highestEventNumber == EventNumber(rawValue: 9))
        #expect(sub.lastReportAt == t0 + .seconds(30))
    }

    @Test("A report for an unknown subscription is still parsed but changes nothing")
    func unknownSubscription() async throws {
        let client = SubscriptionClient()
        let report = try await client.record(reportData: ReportData(subscriptionID: SubscriptionID(rawValue: 99), suppressResponse: true).tlvEncode(), at: t0)
        #expect(report.suppressResponse)
        #expect(await client.count == 0)
    }
}
