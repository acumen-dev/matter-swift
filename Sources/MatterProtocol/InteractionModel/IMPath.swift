// IMPath.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

// MARK: - List Index

/// Three-state list index for attribute paths.
///
/// Per Matter spec, the `listIndex` field in an AttributePath has three semantic states:
/// - absent (`nil` on `AttributePath.listIndex`): normal attribute, or REPLACE-ALL for arrays
/// - null (`.null`): APPEND to list (used when chunking array elements across messages)
/// - index (`.index(n)`): specific list element
public enum ListIndex: Sendable, Equatable {
    /// TLV null at tag 5 — append to list.
    case null
    /// TLV unsigned int at tag 5 — specific element index.
    case index(UInt16)
}

/// An attribute path in the Interaction Model.
///
/// Identifies a specific attribute on a specific cluster instance.
/// Any field can be nil for wildcard matching.
///
/// ```
/// List {
///   0: enableTagCompression (bool, optional)
///   1: nodeID (unsigned int, optional)
///   2: endpointID (unsigned int, optional)
///   3: clusterID (unsigned int, optional)
///   4: attributeID (unsigned int, optional)
///   5: listIndex (unsigned int or null, optional)
/// }
/// ```
public struct AttributePath: Sendable, Equatable {

    private enum Tag {
        static let enableTagCompression: UInt8 = 0
        static let nodeID: UInt8 = 1
        static let endpointID: UInt8 = 2
        static let clusterID: UInt8 = 3
        static let attributeID: UInt8 = 4
        static let listIndex: UInt8 = 5
    }

    public let endpointID: EndpointID?
    public let clusterID: ClusterID?
    public let attributeID: AttributeID?
    public let nodeID: NodeID?
    public let listIndex: ListIndex?

    public init(
        endpointID: EndpointID? = nil,
        clusterID: ClusterID? = nil,
        attributeID: AttributeID? = nil,
        nodeID: NodeID? = nil,
        listIndex: ListIndex? = nil
    ) {
        self.endpointID = endpointID
        self.clusterID = clusterID
        self.attributeID = attributeID
        self.nodeID = nodeID
        self.listIndex = listIndex
    }

    public func toTLVElement() -> TLVElement {
        var fields: [TLVElement.TLVField] = []
        if let nodeID { fields.append(.init(tag: .contextSpecific(Tag.nodeID), value: .unsignedInt(nodeID.rawValue))) }
        if let endpointID { fields.append(.init(tag: .contextSpecific(Tag.endpointID), value: .unsignedInt(UInt64(endpointID.rawValue)))) }
        if let clusterID { fields.append(.init(tag: .contextSpecific(Tag.clusterID), value: .unsignedInt(UInt64(clusterID.rawValue)))) }
        if let attributeID { fields.append(.init(tag: .contextSpecific(Tag.attributeID), value: .unsignedInt(UInt64(attributeID.rawValue)))) }
        switch listIndex {
        case .none:
            break
        case .null:
            fields.append(.init(tag: .contextSpecific(Tag.listIndex), value: .null))
        case .index(let idx):
            fields.append(.init(tag: .contextSpecific(Tag.listIndex), value: .unsignedInt(UInt64(idx))))
        }
        return .list(fields)
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> AttributePath {
        guard case .list(let fields) = element else {
            throw IMError.invalidPath("AttributePath: expected list")
        }

        let listIndex: ListIndex?
        if let listField = fields.first(where: { $0.tag == .contextSpecific(Tag.listIndex) }) {
            switch listField.value {
            case .null:
                listIndex = .null
            default:
                if let v = listField.value.uintValue {
                    listIndex = .index(try IMError.narrow(v, "AttributePath.listIndex"))
                } else {
                    listIndex = nil
                }
            }
        } else {
            listIndex = nil
        }

        return AttributePath(
            endpointID: try fields.first(where: { $0.tag == .contextSpecific(Tag.endpointID) })?.value.uintValue.map { EndpointID(rawValue: try IMError.narrow($0, "AttributePath.endpointID")) },
            clusterID: try fields.first(where: { $0.tag == .contextSpecific(Tag.clusterID) })?.value.uintValue.map { ClusterID(rawValue: try IMError.narrow($0, "AttributePath.clusterID")) },
            attributeID: try fields.first(where: { $0.tag == .contextSpecific(Tag.attributeID) })?.value.uintValue.map { AttributeID(rawValue: try IMError.narrow($0, "AttributePath.attributeID")) },
            nodeID: fields.first(where: { $0.tag == .contextSpecific(Tag.nodeID) })?.value.uintValue.map { NodeID(rawValue: $0) },
            listIndex: listIndex
        )
    }
}

/// A command path in the Interaction Model.
///
/// ```
/// List {
///   0: endpointID (unsigned int)
///   1: clusterID (unsigned int)
///   2: commandID (unsigned int)
/// }
/// ```
public struct CommandPath: Sendable, Equatable {

    private enum Tag {
        static let endpointID: UInt8 = 0
        static let clusterID: UInt8 = 1
        static let commandID: UInt8 = 2
    }

    public let endpointID: EndpointID
    public let clusterID: ClusterID
    public let commandID: CommandID

    public init(endpointID: EndpointID, clusterID: ClusterID, commandID: CommandID) {
        self.endpointID = endpointID
        self.clusterID = clusterID
        self.commandID = commandID
    }

    public func toTLVElement() -> TLVElement {
        .list([
            .init(tag: .contextSpecific(Tag.endpointID), value: .unsignedInt(UInt64(endpointID.rawValue))),
            .init(tag: .contextSpecific(Tag.clusterID), value: .unsignedInt(UInt64(clusterID.rawValue))),
            .init(tag: .contextSpecific(Tag.commandID), value: .unsignedInt(UInt64(commandID.rawValue)))
        ])
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> CommandPath {
        guard case .list(let fields) = element else {
            throw IMError.invalidPath("CommandPath: expected list")
        }

        guard let ep = fields.first(where: { $0.tag == .contextSpecific(Tag.endpointID) })?.value.uintValue,
              let cl = fields.first(where: { $0.tag == .contextSpecific(Tag.clusterID) })?.value.uintValue,
              let cmd = fields.first(where: { $0.tag == .contextSpecific(Tag.commandID) })?.value.uintValue else {
            throw IMError.invalidPath("CommandPath: missing required fields")
        }

        return CommandPath(
            endpointID: EndpointID(rawValue: try IMError.narrow(ep, "CommandPath.endpointID")),
            clusterID: ClusterID(rawValue: try IMError.narrow(cl, "CommandPath.clusterID")),
            commandID: CommandID(rawValue: try IMError.narrow(cmd, "CommandPath.commandID"))
        )
    }
}

/// An event path in the Interaction Model.
///
/// ```
/// List {
///   0: nodeID (unsigned int, optional)
///   1: endpointID (unsigned int, optional)
///   2: clusterID (unsigned int, optional)
///   3: eventID (unsigned int, optional)
///   4: isUrgent (bool, optional)
/// }
/// ```
public struct EventPath: Sendable, Equatable {

    private enum Tag {
        static let nodeID: UInt8 = 0
        static let endpointID: UInt8 = 1
        static let clusterID: UInt8 = 2
        static let eventID: UInt8 = 3
        static let isUrgent: UInt8 = 4
    }

    public let endpointID: EndpointID?
    public let clusterID: ClusterID?
    public let eventID: EventID?
    public let nodeID: NodeID?
    public let isUrgent: Bool?

    public init(
        endpointID: EndpointID? = nil,
        clusterID: ClusterID? = nil,
        eventID: EventID? = nil,
        nodeID: NodeID? = nil,
        isUrgent: Bool? = nil
    ) {
        self.endpointID = endpointID
        self.clusterID = clusterID
        self.eventID = eventID
        self.nodeID = nodeID
        self.isUrgent = isUrgent
    }

    public func toTLVElement() -> TLVElement {
        var fields: [TLVElement.TLVField] = []
        if let nodeID { fields.append(.init(tag: .contextSpecific(Tag.nodeID), value: .unsignedInt(nodeID.rawValue))) }
        if let endpointID { fields.append(.init(tag: .contextSpecific(Tag.endpointID), value: .unsignedInt(UInt64(endpointID.rawValue)))) }
        if let clusterID { fields.append(.init(tag: .contextSpecific(Tag.clusterID), value: .unsignedInt(UInt64(clusterID.rawValue)))) }
        if let eventID { fields.append(.init(tag: .contextSpecific(Tag.eventID), value: .unsignedInt(UInt64(eventID.rawValue)))) }
        if let isUrgent { fields.append(.init(tag: .contextSpecific(Tag.isUrgent), value: .bool(isUrgent))) }
        return .list(fields)
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> EventPath {
        guard case .list(let fields) = element else {
            throw IMError.invalidPath("EventPath: expected list")
        }
        return EventPath(
            endpointID: try fields.first(where: { $0.tag == .contextSpecific(Tag.endpointID) })?.value.uintValue.map { EndpointID(rawValue: try IMError.narrow($0, "EventPath.endpointID")) },
            clusterID: try fields.first(where: { $0.tag == .contextSpecific(Tag.clusterID) })?.value.uintValue.map { ClusterID(rawValue: try IMError.narrow($0, "EventPath.clusterID")) },
            eventID: try fields.first(where: { $0.tag == .contextSpecific(Tag.eventID) })?.value.uintValue.map { EventID(rawValue: try IMError.narrow($0, "EventPath.eventID")) },
            nodeID: fields.first(where: { $0.tag == .contextSpecific(Tag.nodeID) })?.value.uintValue.map { NodeID(rawValue: $0) },
            isUrgent: fields.first(where: { $0.tag == .contextSpecific(Tag.isUrgent) })?.value.boolValue
        )
    }
}

// MARK: - IM Errors

/// Interaction Model errors.
public enum IMError: Error, Sendable, Equatable {
    case invalidPath(String)
    case invalidMessage(String)
    case invalidStatus(String)
    /// The device answered a read with an `AttributeStatusIB` instead of data.
    case attributeStatus(path: AttributePath, status: UInt8, clusterStatus: UInt8?)
    /// The device answered an invoke with a non-success `CommandStatusIB`.
    case commandStatus(path: CommandPath, status: UInt8, clusterStatus: UInt8?)
}

extension IMError {
    /// The IM status of an `attributeStatus` / `commandStatus` error, when it is a known code.
    public var statusCode: IMStatusCode? {
        switch self {
        case .attributeStatus(_, let status, _), .commandStatus(_, let status, _):
            return IMStatusCode(rawValue: status)
        default:
            return nil
        }
    }
}

extension IMError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .invalidPath(let m): return "Invalid path: \(m)"
        case .invalidMessage(let m): return "Invalid message: \(m)"
        case .invalidStatus(let m): return "Invalid status: \(m)"
        case .attributeStatus(let path, let status, let cs):
            return "Attribute error: \(Self.describe(status, cs)) at \(Self.describe(path))"
        case .commandStatus(let path, let status, let cs):
            return "Command error: \(Self.describe(status, cs)) at \(Self.describe(path))"
        }
    }

    private static func hex<T: BinaryInteger>(_ v: T) -> String { "0x" + String(v, radix: 16, uppercase: true) }

    private static func describe(_ status: UInt8, _ clusterStatus: UInt8?) -> String {
        var out = "status \(hex(status))"
        if let code = IMStatusCode(rawValue: status) { out += " (\(code))" }
        if let clusterStatus { out += ", cluster status \(hex(clusterStatus))" }
        return out
    }

    private static func describe(_ p: AttributePath) -> String {
        "endpoint \(p.endpointID.map { hex($0.rawValue) } ?? "*") cluster \(p.clusterID.map { hex($0.rawValue) } ?? "*") attribute \(p.attributeID.map { hex($0.rawValue) } ?? "*")"
    }

    private static func describe(_ p: CommandPath) -> String {
        "endpoint \(hex(p.endpointID.rawValue)) cluster \(hex(p.clusterID.rawValue)) command \(hex(p.commandID.rawValue))"
    }
}

extension IMError {
    /// A peer-supplied TLV unsigned integer narrowed to `T`. Out of range is
    /// an invalid message, never a trap.
    static func narrow<T: FixedWidthInteger & UnsignedInteger>(_ value: UInt64, _ field: String) throws -> T {
        guard let narrowed = T(exactly: value) else {
            throw IMError.invalidMessage("\(field): \(value) out of range for \(T.self)")
        }
        return narrowed
    }
}
