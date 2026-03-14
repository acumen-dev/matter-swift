// IMEventMessages.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

/// Event priority levels per the Matter specification.
///
/// Priority determines how an event is stored and when it triggers
/// immediate reporting (critical events are urgent by default).
public enum EventPriority: UInt8, Sendable, Comparable, CaseIterable {
    /// Debug priority — verbose diagnostics, typically not subscribed in production.
    case debug = 0
    /// Info priority — standard operational events.
    case info = 1
    /// Critical priority — high-severity events that may trigger immediate reports.
    case critical = 2

    public static func < (lhs: EventPriority, rhs: EventPriority) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

// MARK: - EventFilterIB

/// Filter to limit event reports to events at or after a minimum event number.
///
/// ```
/// Structure {
///   0: nodeID (unsigned int, optional)
///   1: eventMin (unsigned int)
/// }
/// ```
public struct EventFilterIB: Sendable, Equatable {

    private enum Tag {
        static let nodeID: UInt8 = 0
        static let eventMin: UInt8 = 1
    }

    public let nodeID: NodeID?
    public let eventMin: EventNumber

    public init(nodeID: NodeID? = nil, eventMin: EventNumber) {
        self.nodeID = nodeID
        self.eventMin = eventMin
    }

    public func toTLVElement() -> TLVElement {
        var fields: [TLVElement.TLVField] = []
        if let nodeID {
            fields.append(.init(tag: .contextSpecific(Tag.nodeID), value: .unsignedInt(nodeID.rawValue)))
        }
        fields.append(.init(tag: .contextSpecific(Tag.eventMin), value: .unsignedInt(eventMin.rawValue)))
        return .structure(fields)
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> EventFilterIB {
        guard case .structure(let fields) = element else {
            throw IMError.invalidMessage("EventFilterIB: expected structure")
        }
        let nodeID = fields.first(where: { $0.tag == .contextSpecific(Tag.nodeID) })?.value.uintValue.map { NodeID(rawValue: $0) }
        guard let minVal = fields.first(where: { $0.tag == .contextSpecific(Tag.eventMin) })?.value.uintValue else {
            throw IMError.invalidMessage("EventFilterIB: missing eventMin")
        }
        return EventFilterIB(nodeID: nodeID, eventMin: EventNumber(rawValue: minVal))
    }
}

// MARK: - EventDataIB

/// Event data within a report — carries the actual event payload.
///
/// ```
/// Structure {
///   0: path (EventPath)
///   1: eventNumber (unsigned int)
///   2: priority (unsigned int)
///   3: epochTimestamp (unsigned int, optional — ms since Unix epoch)
///   4: systemTimestamp (unsigned int, optional — ms since boot)
///   7: data (any TLV, optional — event-specific payload)
/// }
/// ```
public struct EventDataIB: Sendable, Equatable {

    private enum Tag {
        static let path: UInt8 = 0
        static let eventNumber: UInt8 = 1
        static let priority: UInt8 = 2
        static let epochTimestamp: UInt8 = 3
        static let systemTimestamp: UInt8 = 4
        static let data: UInt8 = 7
    }

    public let path: EventPath
    public let eventNumber: EventNumber
    public let priority: EventPriority
    /// Milliseconds since Unix epoch (January 1, 1970 UTC).
    public let epochTimestampMs: UInt64?
    /// Milliseconds since device boot.
    public let systemTimestampMs: UInt64?
    /// Event-specific payload, encoded as a TLV element.
    public let data: TLVElement?

    public init(
        path: EventPath,
        eventNumber: EventNumber,
        priority: EventPriority,
        epochTimestampMs: UInt64? = nil,
        systemTimestampMs: UInt64? = nil,
        data: TLVElement? = nil
    ) {
        self.path = path
        self.eventNumber = eventNumber
        self.priority = priority
        self.epochTimestampMs = epochTimestampMs
        self.systemTimestampMs = systemTimestampMs
        self.data = data
    }

    public func toTLVElement() -> TLVElement {
        var fields: [TLVElement.TLVField] = [
            .init(tag: .contextSpecific(Tag.path), value: path.toTLVElement()),
            .init(tag: .contextSpecific(Tag.eventNumber), value: .unsignedInt(eventNumber.rawValue)),
            .init(tag: .contextSpecific(Tag.priority), value: .unsignedInt(UInt64(priority.rawValue)))
        ]
        if let epochTs = epochTimestampMs {
            fields.append(.init(tag: .contextSpecific(Tag.epochTimestamp), value: .unsignedInt(epochTs)))
        }
        if let sysTs = systemTimestampMs {
            fields.append(.init(tag: .contextSpecific(Tag.systemTimestamp), value: .unsignedInt(sysTs)))
        }
        if let eventData = data {
            fields.append(.init(tag: .contextSpecific(Tag.data), value: eventData))
        }
        return .structure(fields)
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> EventDataIB {
        guard case .structure(let fields) = element else {
            throw IMError.invalidMessage("EventDataIB: expected structure")
        }

        guard let pathField = fields.first(where: { $0.tag == .contextSpecific(Tag.path) }) else {
            throw IMError.invalidMessage("EventDataIB: missing path")
        }
        guard let evNumVal = fields.first(where: { $0.tag == .contextSpecific(Tag.eventNumber) })?.value.uintValue else {
            throw IMError.invalidMessage("EventDataIB: missing eventNumber")
        }
        guard let priVal = fields.first(where: { $0.tag == .contextSpecific(Tag.priority) })?.value.uintValue else {
            throw IMError.invalidMessage("EventDataIB: missing priority")
        }
        guard let priority = EventPriority(rawValue: UInt8(priVal)) else {
            throw IMError.invalidMessage("EventDataIB: unknown priority value \(priVal)")
        }

        let epochTs = fields.first(where: { $0.tag == .contextSpecific(Tag.epochTimestamp) })?.value.uintValue
        let sysTs = fields.first(where: { $0.tag == .contextSpecific(Tag.systemTimestamp) })?.value.uintValue
        let eventData = fields.first(where: { $0.tag == .contextSpecific(Tag.data) })?.value

        return EventDataIB(
            path: try EventPath.fromTLVElement(pathField.value),
            eventNumber: EventNumber(rawValue: evNumVal),
            priority: priority,
            epochTimestampMs: epochTs,
            systemTimestampMs: sysTs,
            data: eventData
        )
    }
}

// MARK: - EventStatusIB

/// Event error status within a report — returned when an event cannot be reported.
///
/// ```
/// Structure {
///   0: path (EventPath)
///   1: status (StatusIB)
/// }
/// ```
public struct EventStatusIB: Sendable, Equatable {

    private enum Tag {
        static let path: UInt8 = 0
        static let status: UInt8 = 1
    }

    public let path: EventPath
    public let status: StatusIB

    public init(path: EventPath, status: StatusIB) {
        self.path = path
        self.status = status
    }

    public func toTLVElement() -> TLVElement {
        .structure([
            .init(tag: .contextSpecific(Tag.path), value: path.toTLVElement()),
            .init(tag: .contextSpecific(Tag.status), value: status.toTLVElement())
        ])
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> EventStatusIB {
        guard case .structure(let fields) = element else {
            throw IMError.invalidMessage("EventStatusIB: expected structure")
        }
        guard let pathField = fields.first(where: { $0.tag == .contextSpecific(Tag.path) }) else {
            throw IMError.invalidMessage("EventStatusIB: missing path")
        }
        guard let statusField = fields.first(where: { $0.tag == .contextSpecific(Tag.status) }) else {
            throw IMError.invalidMessage("EventStatusIB: missing status")
        }
        return EventStatusIB(
            path: try EventPath.fromTLVElement(pathField.value),
            status: try StatusIB.fromTLVElement(statusField.value)
        )
    }
}

// MARK: - EventReportIB

/// An individual event report within a ReportData message.
///
/// Contains either event data (on success) or an event status (on error).
///
/// ```
/// Structure {
///   0: eventStatus (EventStatusIB, optional — on error)
///   1: eventData (EventDataIB, optional — on success)
/// }
/// ```
public struct EventReportIB: Sendable, Equatable {

    private enum Tag {
        static let eventStatus: UInt8 = 0
        static let eventData: UInt8 = 1
    }

    public let eventData: EventDataIB?
    public let eventStatus: EventStatusIB?

    /// Create a successful event report.
    public init(eventData: EventDataIB) {
        self.eventData = eventData
        self.eventStatus = nil
    }

    /// Create an error event report.
    public init(eventStatus: EventStatusIB) {
        self.eventData = nil
        self.eventStatus = eventStatus
    }

    public func toTLVElement() -> TLVElement {
        var fields: [TLVElement.TLVField] = []
        if let status = eventStatus {
            fields.append(.init(tag: .contextSpecific(Tag.eventStatus), value: status.toTLVElement()))
        }
        if let data = eventData {
            fields.append(.init(tag: .contextSpecific(Tag.eventData), value: data.toTLVElement()))
        }
        return .structure(fields)
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> EventReportIB {
        guard case .structure(let fields) = element else {
            throw IMError.invalidMessage("EventReportIB: expected structure")
        }

        if let dataField = fields.first(where: { $0.tag == .contextSpecific(Tag.eventData) }) {
            return EventReportIB(eventData: try EventDataIB.fromTLVElement(dataField.value))
        }

        if let statusField = fields.first(where: { $0.tag == .contextSpecific(Tag.eventStatus) }) {
            return EventReportIB(eventStatus: try EventStatusIB.fromTLVElement(statusField.value))
        }

        throw IMError.invalidMessage("EventReportIB: neither data nor status present")
    }
}
