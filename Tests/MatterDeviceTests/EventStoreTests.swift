// EventStoreTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import MatterTypes
import MatterProtocol
@testable import MatterDevice

@Suite("EventStore")
struct EventStoreTests {

    // MARK: - Helpers

    private func makeStore(capacity: Int = 8) -> EventStore {
        EventStore(capacity: capacity)
    }

    private let ep1 = EndpointID(rawValue: 1)
    private let ep2 = EndpointID(rawValue: 2)
    private let clusterOnOff = ClusterID.onOff
    private let clusterDoorLock = ClusterID.doorLock
    private let eventID0 = EventID(rawValue: 0x0000)
    private let eventID1 = EventID(rawValue: 0x0001)

    // MARK: - Monotonic Numbering

    @Test("Record events assigns monotonically increasing event numbers starting at 1")
    func recordMonotonicNumbering() async {
        let store = makeStore()

        let n1 = await store.record(endpointID: ep1, clusterID: clusterOnOff, eventID: eventID0, priority: .info)
        let n2 = await store.record(endpointID: ep1, clusterID: clusterOnOff, eventID: eventID0, priority: .info)
        let n3 = await store.record(endpointID: ep1, clusterID: clusterOnOff, eventID: eventID0, priority: .info)

        #expect(n1.rawValue == 1)
        #expect(n2.rawValue == 2)
        #expect(n3.rawValue == 3)
        #expect(n1 < n2)
        #expect(n2 < n3)
    }

    @Test("latestEventNumber returns 0 when no events recorded")
    func latestEventNumberEmpty() async {
        let store = makeStore()
        let latest = await store.latestEventNumber
        #expect(latest.rawValue == 0)
    }

    @Test("latestEventNumber returns most recent event number")
    func latestEventNumberAfterRecording() async {
        let store = makeStore()
        await store.record(endpointID: ep1, clusterID: clusterOnOff, eventID: eventID0, priority: .info)
        await store.record(endpointID: ep1, clusterID: clusterOnOff, eventID: eventID0, priority: .info)
        let latest = await store.latestEventNumber
        #expect(latest.rawValue == 2)
    }

    // MARK: - Ring Buffer Eviction

    @Test("Ring buffer evicts oldest events when at capacity")
    func ringBufferEviction() async {
        let capacity = 4
        let store = makeStore(capacity: capacity)

        // Fill the buffer with capacity + 3 extra events
        for i in 0..<(capacity + 3) {
            await store.record(
                endpointID: ep1,
                clusterID: clusterOnOff,
                eventID: EventID(rawValue: UInt32(i)),
                priority: .info
            )
        }

        // Should only have 'capacity' events
        let allEvents = await store.eventsSince(EventNumber(rawValue: 0))
        #expect(allEvents.count == capacity)

        // The oldest event (number 1) should have been evicted
        let hasOldest = allEvents.contains { $0.eventNumber.rawValue == 1 }
        #expect(!hasOldest)

        // The newest events should be present
        let newest = await store.latestEventNumber
        #expect(newest.rawValue == UInt64(capacity + 3))
        let hasNewest = allEvents.contains { $0.eventNumber == newest }
        #expect(hasNewest)
    }

    // MARK: - eventsSince

    @Test("eventsSince returns only events at or after the given event number")
    func eventsSinceReturnsSubset() async {
        let store = makeStore()

        await store.record(endpointID: ep1, clusterID: clusterOnOff, eventID: eventID0, priority: .info)  // 1
        await store.record(endpointID: ep1, clusterID: clusterOnOff, eventID: eventID0, priority: .info)  // 2
        await store.record(endpointID: ep1, clusterID: clusterOnOff, eventID: eventID0, priority: .info)  // 3
        await store.record(endpointID: ep1, clusterID: clusterOnOff, eventID: eventID0, priority: .info)  // 4

        let events = await store.eventsSince(EventNumber(rawValue: 3))
        #expect(events.count == 2)
        #expect(events.allSatisfy { $0.eventNumber.rawValue >= 3 })
    }

    @Test("eventsSince returns all events when event number is 0")
    func eventsSinceZeroReturnsAll() async {
        let store = makeStore()

        await store.record(endpointID: ep1, clusterID: clusterOnOff, eventID: eventID0, priority: .info)
        await store.record(endpointID: ep1, clusterID: clusterOnOff, eventID: eventID0, priority: .info)

        let events = await store.eventsSince(EventNumber(rawValue: 0))
        #expect(events.count == 2)
    }

    @Test("eventsSince returns empty array when event number exceeds all recorded")
    func eventsSinceExceedsAll() async {
        let store = makeStore()

        await store.record(endpointID: ep1, clusterID: clusterOnOff, eventID: eventID0, priority: .info)

        let events = await store.eventsSince(EventNumber(rawValue: 999))
        #expect(events.isEmpty)
    }

    // MARK: - hasUrgentEventsSince

    @Test("hasUrgentEventsSince returns false when no urgent events present")
    func hasUrgentEventsSinceFalseWhenNoneUrgent() async {
        let store = makeStore()

        await store.record(endpointID: ep1, clusterID: clusterOnOff, eventID: eventID0, priority: .info, isUrgent: false)
        await store.record(endpointID: ep1, clusterID: clusterOnOff, eventID: eventID0, priority: .info, isUrgent: false)

        let hasUrgent = await store.hasUrgentEventsSince(EventNumber(rawValue: 1))
        #expect(!hasUrgent)
    }

    @Test("hasUrgentEventsSince returns true when urgent event is present")
    func hasUrgentEventsSinceTrueWhenUrgentPresent() async {
        let store = makeStore()

        await store.record(endpointID: ep1, clusterID: clusterOnOff, eventID: eventID0, priority: .info, isUrgent: false)
        await store.record(endpointID: ep1, clusterID: clusterDoorLock, eventID: eventID1, priority: .critical, isUrgent: true)

        let hasUrgent = await store.hasUrgentEventsSince(EventNumber(rawValue: 1))
        #expect(hasUrgent)
    }

    @Test("hasUrgentEventsSince returns false for urgent events before the given number")
    func hasUrgentEventsSinceIgnoresPastUrgent() async {
        let store = makeStore()

        await store.record(endpointID: ep1, clusterID: clusterDoorLock, eventID: eventID1, priority: .critical, isUrgent: true)  // 1
        await store.record(endpointID: ep1, clusterID: clusterOnOff, eventID: eventID0, priority: .info, isUrgent: false)          // 2

        // Ask about urgent events since event 2 — the urgent one (1) is before that
        let hasUrgent = await store.hasUrgentEventsSince(EventNumber(rawValue: 2))
        #expect(!hasUrgent)
    }

    // MARK: - Path Wildcard Query

    @Test("Query with nil endpoint matches all endpoints")
    func queryWildcardEndpoint() async {
        let store = makeStore()

        await store.record(endpointID: ep1, clusterID: clusterOnOff, eventID: eventID0, priority: .info)
        await store.record(endpointID: ep2, clusterID: clusterOnOff, eventID: eventID0, priority: .info)

        // Wildcard endpoint path
        let wildcardPath = EventPath(endpointID: nil, clusterID: clusterOnOff, eventID: eventID0)
        let events = await store.query(paths: [wildcardPath])

        #expect(events.count == 2)
        let endpoints = Set(events.map { $0.endpointID })
        #expect(endpoints.contains(ep1))
        #expect(endpoints.contains(ep2))
    }

    @Test("Query with specific endpoint only returns matching endpoint events")
    func querySpecificEndpoint() async {
        let store = makeStore()

        await store.record(endpointID: ep1, clusterID: clusterOnOff, eventID: eventID0, priority: .info)
        await store.record(endpointID: ep2, clusterID: clusterOnOff, eventID: eventID0, priority: .info)

        let specificPath = EventPath(endpointID: ep1, clusterID: clusterOnOff, eventID: eventID0)
        let events = await store.query(paths: [specificPath])

        #expect(events.count == 1)
        #expect(events[0].endpointID == ep1)
    }

    @Test("Query with nil clusterID matches all clusters")
    func queryWildcardCluster() async {
        let store = makeStore()

        await store.record(endpointID: ep1, clusterID: clusterOnOff, eventID: eventID0, priority: .info)
        await store.record(endpointID: ep1, clusterID: clusterDoorLock, eventID: eventID0, priority: .info)

        let wildcardPath = EventPath(endpointID: ep1, clusterID: nil, eventID: nil)
        let events = await store.query(paths: [wildcardPath])

        #expect(events.count == 2)
    }

    @Test("Query with eventMin filters out older events")
    func queryWithEventMin() async {
        let store = makeStore()

        await store.record(endpointID: ep1, clusterID: clusterOnOff, eventID: eventID0, priority: .info)  // 1
        await store.record(endpointID: ep1, clusterID: clusterOnOff, eventID: eventID0, priority: .info)  // 2
        await store.record(endpointID: ep1, clusterID: clusterOnOff, eventID: eventID0, priority: .info)  // 3

        let wildcardPath = EventPath(endpointID: nil, clusterID: nil, eventID: nil)
        let events = await store.query(paths: [wildcardPath], eventMin: EventNumber(rawValue: 2))

        #expect(events.count == 2)
        #expect(events.allSatisfy { $0.eventNumber.rawValue >= 2 })
    }

    @Test("Query with empty paths returns all events")
    func queryEmptyPathsReturnsAll() async {
        let store = makeStore()

        await store.record(endpointID: ep1, clusterID: clusterOnOff, eventID: eventID0, priority: .info)
        await store.record(endpointID: ep2, clusterID: clusterDoorLock, eventID: eventID1, priority: .critical, isUrgent: true)

        let events = await store.query(paths: [])
        #expect(events.count == 2)
    }
}
