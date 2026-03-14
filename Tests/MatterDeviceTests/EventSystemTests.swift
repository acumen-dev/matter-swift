// EventSystemTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterModel
import MatterProtocol
@testable import MatterDevice

@Suite("Event System Integration")
struct EventSystemTests {

    // MARK: - Helpers

    /// Build a test IM handler wired to an EventStore.
    private func makeHandler() -> (InteractionModelHandler, EndpointManager, AttributeStore, SubscriptionManager, EventStore) {
        let store = AttributeStore()
        let eventStore = EventStore()
        let endpoints = EndpointManager(store: store)
        endpoints.eventStore = eventStore
        let subscriptions = SubscriptionManager()

        // Root/aggregator endpoint
        let aggregator = EndpointConfig(
            endpointID: EndpointManager.aggregatorEndpoint,
            deviceTypes: [(.aggregator, 1)],
            clusterHandlers: [
                DescriptorHandler(deviceTypes: [(.aggregator, 1)], serverClusters: [.descriptor])
            ]
        )
        endpoints.addEndpoint(aggregator)

        // OnOff light on endpoint 3
        let light = EndpointConfig(
            endpointID: EndpointID(rawValue: 3),
            deviceTypes: [(.onOffLight, 1)],
            clusterHandlers: [
                OnOffHandler(),
                DescriptorHandler(deviceTypes: [(.onOffLight, 1)], serverClusters: [.onOff, .descriptor])
            ]
        )
        endpoints.addEndpoint(light)

        // Door lock on endpoint 4
        let doorLock = EndpointConfig(
            endpointID: EndpointID(rawValue: 4),
            deviceTypes: [(.doorLock, 1)],
            clusterHandlers: [
                DoorLockHandler(),
                DescriptorHandler(deviceTypes: [(.doorLock, 1)], serverClusters: [.doorLock, .descriptor])
            ]
        )
        endpoints.addEndpoint(doorLock)

        let handler = InteractionModelHandler(endpoints: endpoints, subscriptions: subscriptions, store: store)
        return (handler, endpoints, store, subscriptions, eventStore)
    }

    private let testFabric = FabricIndex(rawValue: 1)
    private let testSession: UInt16 = 1
    private let lightEndpoint = EndpointID(rawValue: 3)
    private let doorLockEndpoint = EndpointID(rawValue: 4)

    // MARK: - Test 1: OnOff command generates StateChange event

    @Test("OnOff 'on' command records StateChange event in EventStore")
    func onOffCommandGeneratesEvent() async throws {
        let (handler, _, _, _, eventStore) = makeHandler()

        let invokeRequest = InvokeRequest(invokeRequests: [
            CommandDataIB(
                commandPath: CommandPath(
                    endpointID: lightEndpoint,
                    clusterID: .onOff,
                    commandID: OnOffCluster.Command.on
                )
            )
        ])

        _ = try await handler.handleMessage(
            opcode: .invokeRequest,
            payload: invokeRequest.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric
        )

        // EventStore should contain the StateChange event
        let events = await eventStore.eventsSince(EventNumber(rawValue: 0))
        #expect(!events.isEmpty)

        let stateChangeEvents = events.filter { $0.eventID == OnOffCluster.Event.stateChange }
        #expect(stateChangeEvents.count == 1)
        #expect(stateChangeEvents[0].endpointID == lightEndpoint)
        #expect(stateChangeEvents[0].clusterID == .onOff)
        #expect(stateChangeEvents[0].priority == .info)
        #expect(!stateChangeEvents[0].isUrgent)
    }

    @Test("Multiple OnOff commands each generate a StateChange event")
    func multipleOnOffCommandsGenerateEvents() async throws {
        let (handler, _, _, _, eventStore) = makeHandler()

        for commandID in [OnOffCluster.Command.on, OnOffCluster.Command.off, OnOffCluster.Command.toggle] {
            let invokeRequest = InvokeRequest(invokeRequests: [
                CommandDataIB(
                    commandPath: CommandPath(endpointID: lightEndpoint, clusterID: .onOff, commandID: commandID)
                )
            ])
            _ = try await handler.handleMessage(
                opcode: .invokeRequest,
                payload: invokeRequest.tlvEncode(),
                sessionID: testSession,
                fabricIndex: testFabric
            )
        }

        let events = await eventStore.eventsSince(EventNumber(rawValue: 0))
        let stateChangeEvents = events.filter { $0.eventID == OnOffCluster.Event.stateChange }
        #expect(stateChangeEvents.count == 3)
    }

    // MARK: - Test 2: ReadRequest with eventRequests returns EventReportIB

    @Test("ReadRequest with eventRequests returns EventReportIB in ReportData")
    func readRequestWithEventsReturnsReports() async throws {
        let (handler, endpoints, _, _, eventStore) = makeHandler()

        // First record some events directly so we have something to read
        await eventStore.record(
            endpointID: lightEndpoint,
            clusterID: .onOff,
            eventID: OnOffCluster.Event.stateChange,
            priority: .info,
            data: .bool(true)
        )

        // Read the event via IM read request
        let readRequest = ReadRequest(
            eventRequests: [
                EventPath(endpointID: lightEndpoint, clusterID: .onOff, eventID: OnOffCluster.Event.stateChange)
            ]
        )

        let responses = try await handler.handleMessage(
            opcode: .readRequest,
            payload: readRequest.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric
        ).allPairs

        #expect(responses.count == 1)
        #expect(responses[0].0 == .reportData)

        let report = try ReportData.fromTLV(responses[0].1)
        #expect(!report.eventReports.isEmpty)
        #expect(report.eventReports.count == 1)
        #expect(report.eventReports[0].eventData?.path.clusterID == .onOff)
        #expect(report.eventReports[0].eventData?.priority == .info)
    }

    @Test("ReadRequest with eventFilters respects eventMin")
    func readRequestEventFilter() async throws {
        let (handler, _, _, _, eventStore) = makeHandler()

        // Record 3 events
        await eventStore.record(endpointID: lightEndpoint, clusterID: .onOff, eventID: OnOffCluster.Event.stateChange, priority: .info)  // 1
        await eventStore.record(endpointID: lightEndpoint, clusterID: .onOff, eventID: OnOffCluster.Event.stateChange, priority: .info)  // 2
        await eventStore.record(endpointID: lightEndpoint, clusterID: .onOff, eventID: OnOffCluster.Event.stateChange, priority: .info)  // 3

        // Read with eventMin = 2 (should only get events 2 and 3)
        let readRequest = ReadRequest(
            eventRequests: [
                EventPath(endpointID: lightEndpoint, clusterID: .onOff, eventID: OnOffCluster.Event.stateChange)
            ],
            eventFilters: [
                EventFilterIB(eventMin: EventNumber(rawValue: 2))
            ]
        )

        let responses = try await handler.handleMessage(
            opcode: .readRequest,
            payload: readRequest.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric
        ).allPairs

        let report = try ReportData.fromTLV(responses[0].1)
        #expect(report.eventReports.count == 2)
        let numbers = report.eventReports.compactMap { $0.eventData?.eventNumber.rawValue }
        #expect(numbers.allSatisfy { $0 >= 2 })
    }

    // MARK: - Test 3: DoorLock command triggers urgent event on subscription

    @Test("DoorLock lock command creates urgent event that marks subscription pending immediately")
    func doorLockCommandTriggersUrgentSubscription() async throws {
        let (handler, _, _, subscriptions, eventStore) = makeHandler()

        // Subscribe to door lock events
        let subscribeRequest = SubscribeRequest(
            minIntervalFloor: 60,  // 60 second min interval
            maxIntervalCeiling: 120,
            eventRequests: [
                EventPath(endpointID: doorLockEndpoint, clusterID: .doorLock)
            ]
        )

        _ = try await handler.handleMessage(
            opcode: .subscribeRequest,
            payload: subscribeRequest.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric
        )

        // Now send a lock command (which generates an urgent event)
        let timedRequest = TimedRequest(timeoutMs: 5000)
        _ = try await handler.handleMessage(
            opcode: .timedRequest,
            payload: timedRequest.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric,
            exchangeID: 42
        )

        let invokeRequest = InvokeRequest(
            timedRequest: true,
            invokeRequests: [
                CommandDataIB(
                    commandPath: CommandPath(
                        endpointID: doorLockEndpoint,
                        clusterID: .doorLock,
                        commandID: DoorLockCluster.Command.lockDoor
                    )
                )
            ]
        )

        _ = try await handler.handleMessage(
            opcode: .invokeRequest,
            payload: invokeRequest.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric,
            exchangeID: 42
        )

        // Verify the event was recorded as urgent
        let events = await eventStore.eventsSince(EventNumber(rawValue: 0))
        let lockEvents = events.filter { $0.eventID == DoorLockCluster.Event.lockOperation }
        #expect(lockEvents.count == 1)
        #expect(lockEvents[0].isUrgent)
        #expect(lockEvents[0].priority == .critical)

        // The subscription should be marked as urgentPending
        // (bypasses minInterval even though we just subscribed)
        let pending = await subscriptions.pendingReports(now: Date())
        let urgentPending = pending.filter { $0.reason == .urgentEvent }
        #expect(!urgentPending.isEmpty)
    }

    // MARK: - Event TLV Round-trip

    @Test("EventDataIB TLV encode/decode round-trips correctly")
    func eventDataIBRoundTrip() throws {
        let path = EventPath(endpointID: EndpointID(rawValue: 3), clusterID: .onOff, eventID: EventID(rawValue: 0x0000))
        let data = EventDataIB(
            path: path,
            eventNumber: EventNumber(rawValue: 42),
            priority: .critical,
            epochTimestampMs: 1_700_000_000_000,
            data: .bool(true)
        )

        let element = data.toTLVElement()
        let decoded = try EventDataIB.fromTLVElement(element)

        #expect(decoded == data)
        #expect(decoded.priority == .critical)
        #expect(decoded.epochTimestampMs == 1_700_000_000_000)
    }

    @Test("EventReportIB TLV encode/decode round-trips correctly")
    func eventReportIBRoundTrip() throws {
        let path = EventPath(endpointID: EndpointID(rawValue: 5), clusterID: .doorLock, eventID: EventID(rawValue: 0x0002))
        let data = EventDataIB(
            path: path,
            eventNumber: EventNumber(rawValue: 7),
            priority: .critical,
            data: .unsignedInt(1)
        )
        let report = EventReportIB(eventData: data)

        let element = report.toTLVElement()
        let decoded = try EventReportIB.fromTLVElement(element)

        #expect(decoded == report)
        #expect(decoded.eventData?.eventNumber.rawValue == 7)
    }

    @Test("EventFilterIB TLV encode/decode round-trips correctly")
    func eventFilterIBRoundTrip() throws {
        let filter = EventFilterIB(nodeID: NodeID(rawValue: 1234), eventMin: EventNumber(rawValue: 99))

        let element = filter.toTLVElement()
        let decoded = try EventFilterIB.fromTLVElement(element)

        #expect(decoded == filter)
        #expect(decoded.eventMin.rawValue == 99)
        #expect(decoded.nodeID?.rawValue == 1234)
    }

    @Test("EventPriority is Comparable and ordered correctly")
    func eventPriorityOrdering() {
        #expect(EventPriority.debug < EventPriority.info)
        #expect(EventPriority.info < EventPriority.critical)
        #expect(EventPriority.debug < EventPriority.critical)
        #expect(!(EventPriority.critical < EventPriority.info))
    }
}
