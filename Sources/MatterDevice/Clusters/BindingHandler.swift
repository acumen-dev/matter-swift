// BindingHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Cluster handler for the Binding cluster (0x001E).
///
/// Manages fabric-scoped target bindings for an endpoint. Used by switches and
/// buttons for direct device-to-device control without a controller.
/// The `binding` attribute is a fabric-scoped list of target structures.
public struct BindingHandler: ClusterHandler {

    public let clusterID = ClusterID(rawValue: 0x001E)

    public init() {}

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        [
            (BindingCluster.Attribute.binding, .array([])),
        ]
    }

    public func validateWrite(attributeID: AttributeID, value: TLVElement) -> WriteValidation {
        switch attributeID {
        case BindingCluster.Attribute.binding:
            guard case .array = value else { return .constraintError }
            // TODO: Fabric index stamping on write is pending.
            // Each binding entry should have its fabricIndex field (context tag 0xFE) set to the
            // invoking fabric's index before being stored. This requires passing fabricIndex through
            // the write path (validateWrite currently has no access to it). Known limitation.
            return .allowed
        default:
            return .unsupportedWrite
        }
    }

    // MARK: - Fabric Scoping

    /// The binding attribute is fabric-scoped.
    public func isFabricScoped(attributeID: AttributeID) -> Bool {
        attributeID == BindingCluster.Attribute.binding
    }

    /// Filter binding list to only include entries for the given fabric.
    ///
    /// Each binding entry carries a fabricIndex field at context tag `0xFE`.
    /// Entries whose fabricIndex does not match the requesting fabric are excluded.
    public func filterFabricScopedAttribute(
        attributeID: AttributeID,
        value: TLVElement,
        fabricIndex: FabricIndex
    ) -> TLVElement {
        guard isFabricScoped(attributeID: attributeID),
              case .array(let elements) = value else {
            return value
        }

        let filtered = elements.filter { element in
            guard case .structure(let fields) = element,
                  let fiValue = fields.first(where: { $0.tag == .contextSpecific(0xFE) })?.value.uintValue else {
                return false
            }
            return UInt8(fiValue) == fabricIndex.rawValue
        }

        return .array(filtered)
    }
}
