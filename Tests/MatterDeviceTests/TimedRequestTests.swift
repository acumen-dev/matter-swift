// TimedRequestTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterModel
import MatterProtocol
@testable import MatterDevice

@Suite("Timed Request Enforcement")
struct TimedRequestTests {

    // MARK: - Helpers

    private func makeTestHandler(exchangeID: UInt16 = 1) -> (InteractionModelHandler, TimedRequestTracker, AttributeStore, EndpointManager) {
        let store = AttributeStore()
        let endpoints = EndpointManager(store: store)
        let subscriptions = SubscriptionManager()
        let tracker = TimedRequestTracker()

        // Root endpoint (0) with DoorLock cluster
        let doorLockEndpoint = EndpointConfig(
            endpointID: EndpointID(rawValue: 0),
            deviceTypes: [(.doorLock, 1)],
            clusterHandlers: [
                DoorLockHandler(),
                DescriptorHandler(deviceTypes: [(.doorLock, 1)], serverClusters: [.doorLock, .descriptor])
            ]
        )
        endpoints.addEndpoint(doorLockEndpoint)

        // Endpoint 2 with OnOff cluster (not timed-required)
        let onOffEndpoint = EndpointConfig(
            endpointID: EndpointID(rawValue: 2),
            deviceTypes: [(.onOffLight, 1)],
            clusterHandlers: [
                OnOffHandler(),
                DescriptorHandler(deviceTypes: [(.onOffLight, 1)], serverClusters: [.onOff, .descriptor])
            ]
        )
        endpoints.addEndpoint(onOffEndpoint)

        let handler = InteractionModelHandler(
            endpoints: endpoints,
            subscriptions: subscriptions,
            store: store,
            timedRequestTracker: tracker
        )
        return (handler, tracker, store, endpoints)
    }

    private let testFabric = FabricIndex(rawValue: 1)
    private let testSession: UInt16 = 1
    private let doorLockEndpoint = EndpointID(rawValue: 0)
    private let onOffEndpoint = EndpointID(rawValue: 2)
    private let testExchangeID: UInt16 = 42

    // MARK: - Test 1: DoorLock invoke with valid TimedRequest succeeds

    @Test("DoorLock invoke with valid TimedRequest succeeds with status 0x00")
    func doorLockInvokeWithValidTimedRequest() async throws {
        let (handler, _, store, _) = makeTestHandler()

        // Step 1: Send TimedRequest to establish the window (1000ms)
        let timedRequest = TimedRequest(timeoutMs: 1000)
        let timedResponses = try await handler.handleMessage(
            opcode: .timedRequest,
            payload: timedRequest.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric,
            exchangeID: testExchangeID
        ).allPairs

        // TimedRequest should return a success StatusResponse
        #expect(timedResponses.count == 1)
        #expect(timedResponses[0].0 == .statusResponse)
        let timedStatus = try IMStatusResponse.fromTLV(timedResponses[0].1)
        #expect(timedStatus.status == 0x00)

        // Step 2: Send InvokeRequest with timedRequest=true on the same exchange
        let cmd = CommandDataIB(
            commandPath: CommandPath(
                endpointID: doorLockEndpoint,
                clusterID: .doorLock,
                commandID: DoorLockCluster.Command.lockDoor
            )
        )
        let invokeRequest = InvokeRequest(timedRequest: true, invokeRequests: [cmd])

        let responses = try await handler.handleMessage(
            opcode: .invokeRequest,
            payload: invokeRequest.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric,
            exchangeID: testExchangeID
        ).allPairs

        #expect(responses.count == 1)
        #expect(responses[0].0 == .invokeResponse)

        let invokeResponse = try InvokeResponse.fromTLV(responses[0].1)
        #expect(invokeResponse.invokeResponses.count == 1)
        #expect(invokeResponse.invokeResponses[0].status?.status.status == 0x00)

        // Verify the lock state changed to Locked (1)
        let lockState = store.get(
            endpoint: doorLockEndpoint,
            cluster: .doorLock,
            attribute: DoorLockCluster.Attribute.lockState
        )
        #expect(lockState == .unsignedInt(1))
    }

    // MARK: - Test 2: DoorLock invoke without TimedRequest returns needsTimedInteraction (0xC6)

    @Test("DoorLock invoke without TimedRequest returns needsTimedInteraction 0xC6")
    func doorLockInvokeWithoutTimedRequest() async throws {
        let (handler, _, _, _) = makeTestHandler()

        // Send InvokeRequest with timedRequest=false (no preceding TimedRequest)
        let cmd = CommandDataIB(
            commandPath: CommandPath(
                endpointID: doorLockEndpoint,
                clusterID: .doorLock,
                commandID: DoorLockCluster.Command.unlockDoor
            )
        )
        let invokeRequest = InvokeRequest(timedRequest: false, invokeRequests: [cmd])

        let responses = try await handler.handleMessage(
            opcode: .invokeRequest,
            payload: invokeRequest.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric,
            exchangeID: testExchangeID
        ).allPairs

        #expect(responses.count == 1)
        #expect(responses[0].0 == .invokeResponse)

        let invokeResponse = try InvokeResponse.fromTLV(responses[0].1)
        #expect(invokeResponse.invokeResponses.count == 1)

        // Status should be needsTimedInteraction (0xC6)
        let statusCode = invokeResponse.invokeResponses[0].status?.status.status
        #expect(statusCode == IMStatusCode.needsTimedInteraction.rawValue)
    }

    // MARK: - Test 3: DoorLock invoke with timedRequest=true but no prior TimedRequest returns timedRequestMismatch (0xCB)

    @Test("DoorLock invoke with timedRequest=true but no prior TimedRequest returns timedRequestMismatch 0xCB")
    func doorLockInvokeTimedRequestTrueButNoWindow() async throws {
        let (handler, _, _, _) = makeTestHandler()

        // Send InvokeRequest with timedRequest=true but without a preceding TimedRequest
        let cmd = CommandDataIB(
            commandPath: CommandPath(
                endpointID: doorLockEndpoint,
                clusterID: .doorLock,
                commandID: DoorLockCluster.Command.lockDoor
            )
        )
        let invokeRequest = InvokeRequest(timedRequest: true, invokeRequests: [cmd])

        let responses = try await handler.handleMessage(
            opcode: .invokeRequest,
            payload: invokeRequest.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric,
            exchangeID: testExchangeID
        ).allPairs

        #expect(responses.count == 1)
        #expect(responses[0].0 == .invokeResponse)

        let invokeResponse = try InvokeResponse.fromTLV(responses[0].1)
        #expect(invokeResponse.invokeResponses.count == 1)

        // Status should be timedRequestMismatch (0xCB)
        let statusCode = invokeResponse.invokeResponses[0].status?.status.status
        #expect(statusCode == IMStatusCode.timedRequestMismatch.rawValue)
    }

    // MARK: - Test 4: DoorLock invoke after expired TimedRequest returns timedRequestMismatch (0xCB)

    @Test("DoorLock invoke after expired TimedRequest returns timedRequestMismatch 0xCB")
    func doorLockInvokeAfterExpiredTimedRequest() async throws {
        let (handler, tracker, _, _) = makeTestHandler()

        // Record a 1ms timed window directly via tracker
        await tracker.recordTimedRequest(exchangeID: testExchangeID, timeoutMs: 1)

        // Wait 50ms for the window to expire
        try await Task.sleep(for: .milliseconds(50))

        // Send InvokeRequest with timedRequest=true — window is expired
        let cmd = CommandDataIB(
            commandPath: CommandPath(
                endpointID: doorLockEndpoint,
                clusterID: .doorLock,
                commandID: DoorLockCluster.Command.lockDoor
            )
        )
        let invokeRequest = InvokeRequest(timedRequest: true, invokeRequests: [cmd])

        let responses = try await handler.handleMessage(
            opcode: .invokeRequest,
            payload: invokeRequest.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric,
            exchangeID: testExchangeID
        ).allPairs

        #expect(responses.count == 1)
        #expect(responses[0].0 == .invokeResponse)

        let invokeResponse = try InvokeResponse.fromTLV(responses[0].1)
        #expect(invokeResponse.invokeResponses.count == 1)

        // Status should be timedRequestMismatch (0xCB)
        let statusCode = invokeResponse.invokeResponses[0].status?.status.status
        #expect(statusCode == IMStatusCode.timedRequestMismatch.rawValue)
    }

    // MARK: - Test 5: OnOff invoke without TimedRequest succeeds (not timed-required)

    @Test("OnOff invoke without TimedRequest succeeds (not timed-required)")
    func onOffInvokeWithoutTimedRequest() async throws {
        let (handler, _, store, _) = makeTestHandler()

        // Send InvokeRequest with timedRequest=false for OnOff — should succeed
        let cmd = CommandDataIB(
            commandPath: CommandPath(
                endpointID: onOffEndpoint,
                clusterID: .onOff,
                commandID: OnOffCluster.Command.on
            )
        )
        let invokeRequest = InvokeRequest(timedRequest: false, invokeRequests: [cmd])

        let responses = try await handler.handleMessage(
            opcode: .invokeRequest,
            payload: invokeRequest.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric,
            exchangeID: testExchangeID
        ).allPairs

        #expect(responses.count == 1)
        #expect(responses[0].0 == .invokeResponse)

        let invokeResponse = try InvokeResponse.fromTLV(responses[0].1)
        #expect(invokeResponse.invokeResponses.count == 1)
        #expect(invokeResponse.invokeResponses[0].status?.status.status == 0x00)

        // Verify state changed to on
        let onOffValue = store.get(
            endpoint: onOffEndpoint,
            cluster: .onOff,
            attribute: OnOffCluster.Attribute.onOff
        )
        #expect(onOffValue == .bool(true))
    }
}
