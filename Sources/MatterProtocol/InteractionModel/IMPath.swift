// IMPath.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

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
    public let listIndex: UInt16?

    public init(
        endpointID: EndpointID? = nil,
        clusterID: ClusterID? = nil,
        attributeID: AttributeID? = nil,
        nodeID: NodeID? = nil,
        listIndex: UInt16? = nil
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
        if let listIndex { fields.append(.init(tag: .contextSpecific(Tag.listIndex), value: .unsignedInt(UInt64(listIndex)))) }
        return .list(fields)
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> AttributePath {
        guard case .list(let fields) = element else {
            throw IMError.invalidPath("AttributePath: expected list")
        }

        return AttributePath(
            endpointID: fields.first(where: { $0.tag == .contextSpecific(Tag.endpointID) })?.value.uintValue.map { EndpointID(rawValue: UInt16($0)) },
            clusterID: fields.first(where: { $0.tag == .contextSpecific(Tag.clusterID) })?.value.uintValue.map { ClusterID(rawValue: UInt32($0)) },
            attributeID: fields.first(where: { $0.tag == .contextSpecific(Tag.attributeID) })?.value.uintValue.map { AttributeID(rawValue: UInt32($0)) },
            nodeID: fields.first(where: { $0.tag == .contextSpecific(Tag.nodeID) })?.value.uintValue.map { NodeID(rawValue: $0) },
            listIndex: fields.first(where: { $0.tag == .contextSpecific(Tag.listIndex) })?.value.uintValue.map { UInt16($0) }
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
            endpointID: EndpointID(rawValue: UInt16(ep)),
            clusterID: ClusterID(rawValue: UInt32(cl)),
            commandID: CommandID(rawValue: UInt32(cmd))
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
            endpointID: fields.first(where: { $0.tag == .contextSpecific(Tag.endpointID) })?.value.uintValue.map { EndpointID(rawValue: UInt16($0)) },
            clusterID: fields.first(where: { $0.tag == .contextSpecific(Tag.clusterID) })?.value.uintValue.map { ClusterID(rawValue: UInt32($0)) },
            eventID: fields.first(where: { $0.tag == .contextSpecific(Tag.eventID) })?.value.uintValue.map { EventID(rawValue: UInt32($0)) },
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
}
