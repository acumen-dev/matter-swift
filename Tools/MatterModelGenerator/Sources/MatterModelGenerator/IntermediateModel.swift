// IntermediateModel.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

/// A parsed Matter cluster definition.
struct ClusterDefinition {
    let id: UInt32
    let name: String
    let revision: Int
    let classification: String
    let features: [FeatureDefinition]
    let attributes: [AttributeDefinition]
    let commands: [CommandDefinition]
    let events: [EventDefinition]
    let enums: [EnumDefinition]
    let bitmaps: [BitmapDefinition]
    let structs: [StructDefinition]
}

/// A cluster feature flag.
struct FeatureDefinition {
    let bit: Int
    let code: String
    let name: String
    let summary: String
    let conformance: Conformance
}

/// An attribute within a cluster.
struct AttributeDefinition {
    let id: UInt32
    let name: String
    let type: String
    let isReadable: Bool
    let isWritable: Bool
    let readPrivilege: String?
    let writePrivilege: String?
    let isNullable: Bool
    let isScene: Bool
    let persistence: String?
    let conformance: Conformance
    let defaultValue: String?
}

/// A command within a cluster.
struct CommandDefinition {
    let id: UInt32
    let name: String
    let direction: String  // "commandToServer" or "commandToClient"
    let response: String?
    let invokePrivilege: String?
    let conformance: Conformance
    let fields: [FieldDefinition]
    let isFabricScoped: Bool
    let isTimedInvoke: Bool
}

/// An event within a cluster.
struct EventDefinition {
    let id: UInt32
    let name: String
    let priority: String  // "critical", "info", "debug"
    let conformance: Conformance
    let fields: [FieldDefinition]
}

/// An enum datatype.
struct EnumDefinition {
    let name: String
    let items: [EnumItem]
}

/// A single enum value.
struct EnumItem {
    let value: UInt32
    let name: String
    let summary: String
    let conformance: Conformance
}

/// A bitmap datatype.
struct BitmapDefinition {
    let name: String
    let bitfields: [BitfieldItem]
}

/// A single bitmap bitfield.
struct BitfieldItem {
    let bit: Int
    let name: String
    let summary: String
    let conformance: Conformance
}

/// A struct datatype (Phase 2 — parsed but not generated yet).
struct StructDefinition {
    let name: String
    let fields: [FieldDefinition]
    let isFabricScoped: Bool
}

/// A field within a command, event, or struct.
struct FieldDefinition {
    let id: UInt32
    let name: String
    let type: String?
    let isNullable: Bool
    let isOptional: Bool
    let conformance: Conformance
    /// For `list` typed fields, the element type from the `<entry type="..."/>` child element.
    let listElementType: String?
}

/// A parsed device type definition.
struct DeviceTypeDefinition {
    let id: UInt32
    let name: String
    let revision: Int
    let classification: String
    let requiredClusters: [DeviceTypeCluster]
}

/// A cluster requirement in a device type.
struct DeviceTypeCluster {
    let id: UInt32
    let name: String
    let side: String  // "server" or "client"
    let conformance: Conformance
}
