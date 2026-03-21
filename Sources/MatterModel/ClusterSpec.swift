// ClusterSpec.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes

// MARK: - Cluster Specification Metadata

/// Runtime-queryable cluster specification metadata.
///
/// Contains the list of attributes and commands defined by the Matter spec
/// for a cluster, each with their conformance rules. Used by `ClusterValidator`
/// to verify that cluster handlers declare all mandatory attributes and commands.
public struct ClusterSpec: Sendable {

    /// The cluster ID this spec describes.
    public let clusterID: ClusterID

    /// The spec revision for this cluster.
    public let revision: UInt16

    /// All spec-defined attributes (excluding global attributes 0xFFF8–0xFFFD).
    public let attributes: [AttributeSpec]

    /// All spec-defined server commands (commandToServer direction).
    public let commands: [CommandSpec]

    public init(
        clusterID: ClusterID,
        revision: UInt16,
        attributes: [AttributeSpec],
        commands: [CommandSpec]
    ) {
        self.clusterID = clusterID
        self.revision = revision
        self.attributes = attributes
        self.commands = commands
    }
}

// MARK: - Attribute Type

/// The TLV-compatible type category of a Matter attribute.
///
/// Used for runtime type checking of attribute values against the spec.
/// Named enum/bitmap types (e.g., `StartUpOnOffEnum`) are resolved to their
/// underlying integer width at code-generation time.
public enum MatterAttributeType: Sendable, Equatable {
    case bool
    case uint8
    case uint16
    case uint24
    case uint32
    case uint64
    case int8
    case int16
    case int32
    case int64
    case single
    case double
    /// UTF-8 string.
    case string
    /// Octet string (raw bytes).
    case octstr
    /// Structure (tagged fields).
    case structure
    /// Array/list of elements.
    case list
    /// Named type that could not be resolved to a primitive. Type checking is skipped.
    case unknown

    /// Returns `true` if the given TLV element is compatible with this type.
    ///
    /// Compatibility is checked by TLV category — all unsigned integer widths map
    /// to `.unsignedInt`, all signed widths to `.signedInt`, etc. Nullability is
    /// handled separately by the caller.
    public func isCompatible(with element: TLVElement) -> Bool {
        switch self {
        case .bool:
            if case .bool = element { return true }
            return false
        case .uint8, .uint16, .uint24, .uint32, .uint64:
            if case .unsignedInt = element { return true }
            return false
        case .int8, .int16, .int32, .int64:
            if case .signedInt = element { return true }
            return false
        case .single:
            if case .float = element { return true }
            return false
        case .double:
            if case .double = element { return true }
            return false
        case .string:
            if case .utf8String = element { return true }
            return false
        case .octstr:
            if case .octetString = element { return true }
            return false
        case .structure:
            if case .structure = element { return true }
            return false
        case .list:
            if case .array = element { return true }
            return false
        case .unknown:
            return true
        }
    }
}

// MARK: - Attribute Specification

/// Spec metadata for a single cluster attribute.
public struct AttributeSpec: Sendable {

    /// The attribute ID.
    public let id: AttributeID

    /// Human-readable attribute name from the spec.
    public let name: String

    /// The conformance rule for this attribute.
    public let conformance: SpecConformance

    /// The TLV-compatible type of this attribute's value.
    public let type: MatterAttributeType

    /// Whether this attribute accepts a null value.
    public let isNullable: Bool

    public init(
        id: AttributeID,
        name: String,
        conformance: SpecConformance,
        type: MatterAttributeType = .unknown,
        isNullable: Bool = false
    ) {
        self.id = id
        self.name = name
        self.conformance = conformance
        self.type = type
        self.isNullable = isNullable
    }
}

// MARK: - Command Specification

/// Spec metadata for a single cluster command.
public struct CommandSpec: Sendable {

    /// The command ID.
    public let id: CommandID

    /// Human-readable command name from the spec.
    public let name: String

    /// The conformance rule for this command.
    public let conformance: SpecConformance

    public init(id: CommandID, name: String, conformance: SpecConformance) {
        self.id = id
        self.name = name
        self.conformance = conformance
    }
}

// MARK: - Spec Conformance

/// A runtime-evaluable conformance rule from the Matter specification.
///
/// Conformance determines whether an attribute or command is mandatory, optional,
/// or conditionally mandatory based on the cluster's enabled features.
public enum SpecConformance: Sendable {
    case mandatory
    case optional
    case mandatoryIf(SpecCondition)
    case optionalIf(SpecCondition)
    case deprecated
    case disallowed

    /// Evaluate whether this conformance resolves to mandatory given a feature map.
    ///
    /// - Parameter featureMap: The feature map bitmask from the cluster handler.
    /// - Returns: `true` if this attribute/command is mandatory for the given features.
    public func isMandatory(featureMap: UInt32) -> Bool {
        switch self {
        case .mandatory:
            return true
        case .optional, .deprecated, .disallowed:
            return false
        case .mandatoryIf(let condition):
            return condition.evaluate(featureMap: featureMap)
        case .optionalIf:
            return false
        }
    }
}

// MARK: - Spec Condition

/// A boolean condition over feature flags, evaluated at runtime.
///
/// Feature conditions use bit masks — `feature(1 << 0)` tests whether
/// bit 0 is set in the handler's feature map.
public indirect enum SpecCondition: Sendable {
    /// True if `(featureMap & mask) != 0`.
    case feature(UInt32)
    /// Logical NOT.
    case not(SpecCondition)
    /// Logical OR — true if any sub-condition is true.
    case or([SpecCondition])
    /// Logical AND — true if all sub-conditions are true.
    case and([SpecCondition])

    /// Evaluate this condition against a feature map.
    public func evaluate(featureMap: UInt32) -> Bool {
        switch self {
        case .feature(let mask):
            return (featureMap & mask) != 0
        case .not(let inner):
            return !inner.evaluate(featureMap: featureMap)
        case .or(let conditions):
            return conditions.contains { $0.evaluate(featureMap: featureMap) }
        case .and(let conditions):
            return conditions.allSatisfy { $0.evaluate(featureMap: featureMap) }
        }
    }
}
