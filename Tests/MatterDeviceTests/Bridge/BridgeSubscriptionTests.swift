// BridgeSubscriptionTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterModel
import MatterProtocol
@testable import MatterDevice

@Suite("Bridge Subscription Tests")
struct BridgeSubscriptionTests {

    private let testFabric = FabricIndex(rawValue: 1)
    private let testSession: UInt16 = 1

    // MARK: - Helpers

    private func makeBridgeWithSubscription() async throws -> (MatterBridge, BridgedEndpoint, SubscriptionID) {
        let bridge = MatterBridge()
        let light = bridge.addDimmableLight(name: "Kitchen Pendant")

        // Subscribe to OnOff attribute
        let subReq = SubscribeRequest(
            minIntervalFloor: 0,
            maxIntervalCeiling: 60,
            attributeRequests: [
                AttributePath(
                    endpointID: light.endpointID,
                    clusterID: .onOff,
                    attributeID: OnOffCluster.Attribute.onOff
                )
            ]
        )

        let responses = try await bridge.handleIM(
            opcode: .subscribeRequest,
            payload: subReq.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric
        ).allPairs

        let subResp = try SubscribeResponse.fromTLV(responses[1].1)
        return (bridge, light, subResp.subscriptionID)
    }

    // MARK: - Subscribe Through Bridge

    @Test("Subscribe through bridge returns initial report and subscribe response")
    func subscribeThroughBridge() async throws {
        let bridge = MatterBridge()
        let light = bridge.addDimmableLight(name: "Light")

        let subReq = SubscribeRequest(
            minIntervalFloor: 1,
            maxIntervalCeiling: 60,
            attributeRequests: [
                AttributePath(
                    endpointID: light.endpointID,
                    clusterID: .onOff,
                    attributeID: OnOffCluster.Attribute.onOff
                )
            ]
        )

        let responses = try await bridge.handleIM(
            opcode: .subscribeRequest,
            payload: subReq.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric
        ).allPairs

        #expect(responses.count == 2)
        #expect(responses[0].0 == .reportData)
        #expect(responses[1].0 == .subscribeResponse)

        let report = try ReportData.fromTLV(responses[0].1)
        #expect(report.subscriptionID != nil)
        #expect(report.attributeReports.count == 1)
    }

    // MARK: - Bridge-Side Change Triggers Pending Report

    @Test("Setting attribute from bridge side triggers pending subscription report")
    func bridgeSideChangeTriggersReport() async throws {
        let (bridge, light, _) = try await makeBridgeWithSubscription()

        // Clear dirty from subscription setup
        bridge.store.clearDirty()

        // Set attribute from bridge side
        await light.setOnOff(true)

        // Should have a pending report
        let pending = await bridge.pendingReports()
        #expect(pending.count == 1)
        #expect(pending[0].reason == .attributeChanged)
    }

    // MARK: - Build Report

    @Test("buildReport produces ReportData with subscriptionID and changed attributes")
    func buildReportData() async throws {
        let (bridge, light, subID) = try await makeBridgeWithSubscription()
        bridge.store.clearDirty()

        await light.setOnOff(true)

        let pending = await bridge.pendingReports()
        #expect(pending.count == 1)

        let reportChunks = await bridge.buildReport(for: pending[0])
        #expect(reportChunks != nil)
        let reportChunksList = try #require(reportChunks)
        #expect(!reportChunksList.isEmpty)

        let report = reportChunksList[0]
        #expect(report.subscriptionID == subID)
        #expect(report.suppressResponse == false)
        #expect(report.attributeReports.count == 1)
        #expect(report.attributeReports[0].attributeData?.data.boolValue == true)
    }

    // MARK: - Report Sent Resets Timer

    @Test("reportSent clears pending status")
    func reportSentClearsPending() async throws {
        let (bridge, light, subID) = try await makeBridgeWithSubscription()
        bridge.store.clearDirty()

        await light.setOnOff(true)

        // Should have a pending report
        var pending = await bridge.pendingReports()
        #expect(pending.count == 1)

        // Mark report as sent
        await bridge.reportSent(subscriptionID: subID)

        // No more pending (unless maxInterval elapsed, which hasn't)
        pending = await bridge.pendingReports()
        #expect(pending.isEmpty)
    }

    // MARK: - No Change = No Report

    @Test("Setting same value does not trigger subscription report")
    func noChangeNoReport() async throws {
        let (bridge, light, _) = try await makeBridgeWithSubscription()
        bridge.store.clearDirty()

        // OnOff is already false, setting false again should be a no-op
        await light.setOnOff(false)

        let pending = await bridge.pendingReports()
        #expect(pending.isEmpty)
    }

    // MARK: - Expiry Without StatusResponse

    @Test("Subscription expires without StatusResponse after maxInterval + margin")
    func subscriptionExpiry() async throws {
        let bridge = MatterBridge()
        let light = bridge.addDimmableLight(name: "Light")

        let subReq = SubscribeRequest(
            minIntervalFloor: 0,
            maxIntervalCeiling: 10,  // 10 second max
            attributeRequests: [
                AttributePath(
                    endpointID: light.endpointID,
                    clusterID: .onOff,
                    attributeID: OnOffCluster.Attribute.onOff
                )
            ]
        )

        _ = try await bridge.handleIM(
            opcode: .subscribeRequest,
            payload: subReq.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric
        )

        // Fast-forward past maxInterval + margin (10 + 10 + 1 = 21 seconds)
        let future = Date().addingTimeInterval(21)
        let expired = await bridge.expireStale(now: future)
        #expect(expired.count == 1)

        // No more active subscriptions
        bridge.store.clearDirty()
        await light.setOnOff(true)
        let pending = await bridge.pendingReports()
        #expect(pending.isEmpty)
    }

    // MARK: - Multiple Subscriptions

    @Test("Multiple subscriptions get independent reports")
    func multipleSubscriptions() async throws {
        let bridge = MatterBridge()
        let light1 = bridge.addDimmableLight(name: "Light 1")
        let light2 = bridge.addDimmableLight(name: "Light 2")

        // Subscribe to light1 OnOff
        let subReq1 = SubscribeRequest(
            minIntervalFloor: 0,
            maxIntervalCeiling: 60,
            attributeRequests: [
                AttributePath(
                    endpointID: light1.endpointID,
                    clusterID: .onOff,
                    attributeID: OnOffCluster.Attribute.onOff
                )
            ]
        )
        _ = try await bridge.handleIM(
            opcode: .subscribeRequest,
            payload: subReq1.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric
        )

        // Subscribe to light2 OnOff
        let subReq2 = SubscribeRequest(
            minIntervalFloor: 0,
            maxIntervalCeiling: 60,
            attributeRequests: [
                AttributePath(
                    endpointID: light2.endpointID,
                    clusterID: .onOff,
                    attributeID: OnOffCluster.Attribute.onOff
                )
            ]
        )
        _ = try await bridge.handleIM(
            opcode: .subscribeRequest,
            payload: subReq2.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric
        )

        bridge.store.clearDirty()

        // Change only light1
        await light1.setOnOff(true)

        // Only light1's subscription should have pending report
        let pending = await bridge.pendingReports()
        #expect(pending.count == 1)
    }
}
