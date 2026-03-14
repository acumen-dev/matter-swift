// EventStore.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterProtocol

/// A recorded event stored in the event ring buffer.
public struct StoredEvent: Sendable {
    public let endpointID: EndpointID
    public let clusterID: ClusterID
    public let eventID: EventID
    public let eventNumber: EventNumber
    public let priority: EventPriority
    public let timestampMs: UInt64
    public let data: TLVElement?
    public let isUrgent: Bool

    public init(
        endpointID: EndpointID,
        clusterID: ClusterID,
        eventID: EventID,
        eventNumber: EventNumber,
        priority: EventPriority,
        timestampMs: UInt64,
        data: TLVElement?,
        isUrgent: Bool
    ) {
        self.endpointID = endpointID
        self.clusterID = clusterID
        self.eventID = eventID
        self.eventNumber = eventNumber
        self.priority = priority
        self.timestampMs = timestampMs
        self.data = data
        self.isUrgent = isUrgent
    }
}

/// Actor that stores and queries Matter events using a fixed-capacity ring buffer.
///
/// Events are assigned monotonically increasing `EventNumber` values starting at 1.
/// When the buffer is full, the oldest events are evicted to make room for new ones.
///
/// ```swift
/// let store = EventStore()
/// let number = await store.record(
///     endpointID: EndpointID(rawValue: 2),
///     clusterID: .onOff,
///     eventID: EventID(rawValue: 0x0000),
///     priority: .info,
///     data: nil
/// )
/// let events = await store.eventsSince(EventNumber(rawValue: 0))
/// ```
public actor EventStore {

    // MARK: - Constants

    /// Default ring buffer capacity.
    public static let defaultCapacity = 64

    // MARK: - State

    private var buffer: [StoredEvent]
    private var head: Int = 0       // Index of the next write position
    private var count: Int = 0      // Number of valid entries
    private let capacity: Int
    private var nextEventNumber: UInt64 = 1

    public init(capacity: Int = EventStore.defaultCapacity) {
        self.capacity = capacity
        self.buffer = []
        self.buffer.reserveCapacity(capacity)
    }

    // MARK: - Recording

    /// Record a new event. Returns the assigned `EventNumber`.
    ///
    /// If the buffer is full, the oldest event is evicted.
    @discardableResult
    public func record(
        endpointID: EndpointID,
        clusterID: ClusterID,
        eventID: EventID,
        priority: EventPriority,
        timestampMs: UInt64 = 0,
        data: TLVElement? = nil,
        isUrgent: Bool = false
    ) -> EventNumber {
        let number = EventNumber(rawValue: nextEventNumber)
        nextEventNumber += 1

        let event = StoredEvent(
            endpointID: endpointID,
            clusterID: clusterID,
            eventID: eventID,
            eventNumber: number,
            priority: priority,
            timestampMs: timestampMs,
            data: data,
            isUrgent: isUrgent
        )

        if buffer.count < capacity {
            buffer.append(event)
        } else {
            buffer[head] = event
        }
        head = (head + 1) % capacity
        count = min(count + 1, capacity)

        return number
    }

    // MARK: - Queries

    /// Query events matching the given paths and optional minimum event number.
    ///
    /// Paths with nil fields act as wildcards:
    /// - `endpointID: nil` matches any endpoint
    /// - `clusterID: nil` matches any cluster
    /// - `eventID: nil` matches any event ID
    ///
    /// Results are returned in ascending event number order.
    public func query(
        paths: [EventPath],
        eventMin: EventNumber? = nil
    ) -> [StoredEvent] {
        let minNumber = eventMin?.rawValue ?? 0
        return orderedEvents().filter { event in
            guard event.eventNumber.rawValue >= minNumber else { return false }
            // If no paths specified, return all events
            if paths.isEmpty { return true }
            return paths.contains { path in
                eventMatchesPath(event: event, path: path)
            }
        }
    }

    /// Return all events with event number greater than or equal to the given number.
    public func eventsSince(_ eventNumber: EventNumber) -> [StoredEvent] {
        orderedEvents().filter { $0.eventNumber.rawValue >= eventNumber.rawValue }
    }

    /// Return `true` if there are any urgent events with event number >= the given number.
    public func hasUrgentEventsSince(_ eventNumber: EventNumber) -> Bool {
        orderedEvents().contains { $0.eventNumber.rawValue >= eventNumber.rawValue && $0.isUrgent }
    }

    /// The last assigned event number (0 if no events have been recorded).
    public var latestEventNumber: EventNumber {
        EventNumber(rawValue: nextEventNumber - 1)
    }

    // MARK: - Internal Helpers

    /// Return events in ascending event number order.
    private func orderedEvents() -> [StoredEvent] {
        guard count > 0 else { return [] }

        if buffer.count < capacity {
            // Buffer not yet wrapped
            return buffer
        }

        // Buffer has wrapped: reconstruct ordered sequence starting from head
        let startIndex = head % capacity
        if startIndex == 0 {
            return buffer
        }
        return Array(buffer[startIndex...]) + Array(buffer[..<startIndex])
    }

    /// Check if a stored event matches an event path (with wildcard support).
    private func eventMatchesPath(event: StoredEvent, path: EventPath) -> Bool {
        if let ep = path.endpointID, ep != event.endpointID { return false }
        if let cl = path.clusterID, cl != event.clusterID { return false }
        if let evID = path.eventID, evID != event.eventID { return false }
        return true
    }
}
