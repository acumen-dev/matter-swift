// ClusterValidator.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes
import MatterModel

// MARK: - Cluster Validator

/// Validates cluster handlers against the Matter specification metadata.
///
/// At endpoint registration time, checks that handlers declare all mandatory
/// attributes and commands required by the spec for their cluster and feature set.
/// Produces warnings (not errors) — validation does not prevent registration.
public enum ClusterValidator {

    /// The result of validating a cluster handler against its spec.
    public struct ValidationResult: Sendable {

        /// The cluster ID that was validated.
        public let clusterID: ClusterID

        /// Spec-compliance errors (missing mandatory attributes/commands).
        public let errors: [String]

        /// Non-fatal warnings (missing optional-but-common items).
        public let warnings: [String]

        /// `true` if no mandatory items are missing.
        public var isValid: Bool { errors.isEmpty }
    }

    /// Validate a handler against its cluster's spec metadata.
    ///
    /// Looks up the cluster's `ClusterSpec` from the generated registry and checks
    /// that all mandatory attributes and commands (after evaluating feature-conditional
    /// conformance) are present in the handler's declarations.
    ///
    /// - Parameter handler: The cluster handler to validate.
    /// - Returns: A `ValidationResult` with any errors or warnings found.
    public static func validate(handler: any ClusterHandler) -> ValidationResult {
        let clusterID = handler.clusterID

        guard let spec = ClusterSpecRegistry.spec(for: clusterID) else {
            // Unknown cluster (vendor-specific or not in registry) — skip silently
            return ValidationResult(clusterID: clusterID, errors: [], warnings: [])
        }

        let featureMap = handler.featureMap
        let initialAttrs = handler.initialAttributes()
        let providedAttributes = Set(initialAttrs.map { $0.0 })
        let providedValues = Dictionary(initialAttrs.map { ($0.0, $0.1) }, uniquingKeysWith: { first, _ in first })
        let providedCommands = Set(handler.acceptedCommands())

        var errors: [String] = []
        var warnings: [String] = []

        // Check attributes: presence and type
        for attrSpec in spec.attributes {
            // Skip global attributes — they are auto-populated by EndpointManager
            if attrSpec.id.rawValue >= 0xFFF8 { continue }

            if attrSpec.conformance.isMandatory(featureMap: featureMap) {
                if !providedAttributes.contains(attrSpec.id) {
                    errors.append(
                        "Cluster 0x\(hex(clusterID.rawValue)) missing mandatory attribute " +
                        "\"\(attrSpec.name)\" (0x\(hex(attrSpec.id.rawValue)))"
                    )
                }
            }

            // Type check the value if provided
            guard attrSpec.type != .unknown, let value = providedValues[attrSpec.id] else { continue }

            if case .null = value {
                if !attrSpec.isNullable {
                    errors.append(
                        "Cluster 0x\(hex(clusterID.rawValue)) attribute \"\(attrSpec.name)\" " +
                        "(0x\(hex(attrSpec.id.rawValue))) is non-nullable but has null value"
                    )
                }
            } else if !attrSpec.type.isCompatible(with: value) {
                errors.append(
                    "Cluster 0x\(hex(clusterID.rawValue)) attribute \"\(attrSpec.name)\" " +
                    "(0x\(hex(attrSpec.id.rawValue))) type mismatch: expected \(attrSpec.type)"
                )
            }
        }

        // Check commands
        for cmdSpec in spec.commands {
            if cmdSpec.conformance.isMandatory(featureMap: featureMap) {
                if !providedCommands.contains(cmdSpec.id) {
                    errors.append(
                        "Cluster 0x\(hex(clusterID.rawValue)) missing mandatory command " +
                        "\"\(cmdSpec.name)\" (0x\(hex(cmdSpec.id.rawValue)))"
                    )
                }
            }
        }

        return ValidationResult(clusterID: clusterID, errors: errors, warnings: warnings)
    }

    // MARK: - Private

    private static func hex(_ value: UInt32) -> String {
        String(format: "%04X", value)
    }

    private static func hex(_ value: UInt16) -> String {
        String(format: "%04X", value)
    }
}
