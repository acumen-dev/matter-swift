// AccessControlHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Cluster handler for the Access Control cluster (0x001F).
///
/// Manages ACL entries that determine which nodes can perform operations.
/// During commissioning, the controller writes an admin ACE via the IM write path.
/// ACL entries are staged in `CommissioningState` until `CommissioningComplete`.
public struct AccessControlHandler: ClusterHandler, @unchecked Sendable {

    public let clusterID = ClusterID.accessControl

    /// Shared commissioning state for staging ACLs.
    public let commissioningState: CommissioningState

    public init(commissioningState: CommissioningState) {
        self.commissioningState = commissioningState
    }

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        [
            (AccessControlCluster.Attribute.acl, .array([])),
            (AccessControlCluster.Attribute.subjectsPerAccessControlEntry, .unsignedInt(4)),
            (AccessControlCluster.Attribute.targetsPerAccessControlEntry, .unsignedInt(3)),
            (AccessControlCluster.Attribute.accessControlEntriesPerFabric, .unsignedInt(4)),
        ]
    }

    public func validateWrite(attributeID: AttributeID, value: TLVElement) -> WriteValidation {
        switch attributeID {
        case AccessControlCluster.Attribute.acl:
            // Parse the ACL array and stage the entries for CommissioningComplete
            guard case .array(let elements) = value else {
                return .constraintError
            }

            var entries: [AccessControlCluster.AccessControlEntry] = []
            for element in elements {
                do {
                    let ace = try AccessControlCluster.AccessControlEntry.fromTLVElement(element)
                    entries.append(ace)
                } catch {
                    return .constraintError
                }
            }

            commissioningState.stagedACLs = entries
            return .allowed
        default:
            return .unsupportedWrite
        }
    }

    public func handleCommand(
        commandID: CommandID,
        fields: TLVElement?,
        store: AttributeStore,
        endpointID: EndpointID
    ) throws -> TLVElement? {
        // ACL cluster has no commands — all operations are via attribute writes
        nil
    }

    // MARK: - Fabric Scoping

    /// The ACL attribute is fabric-scoped — each fabric's entries must be kept separate.
    public func isFabricScoped(attributeID: AttributeID) -> Bool {
        attributeID == AccessControlCluster.Attribute.acl
    }

    /// Filter the ACL array to only include entries belonging to the requesting fabric.
    ///
    /// ACL entries carry a fabricIndex field at context tag `0xFE`. Entries whose
    /// fabricIndex does not match the requesting fabric are removed from the result.
    public func filterFabricScopedAttribute(attributeID: AttributeID, value: TLVElement, fabricIndex: FabricIndex) -> TLVElement {
        guard attributeID == AccessControlCluster.Attribute.acl,
              case .array(let elements) = value else {
            return value
        }

        let filtered = elements.filter { element in
            guard case .structure(let fields) = element,
                  let fiValue = fields.first(where: { $0.tag == .contextSpecific(0xFE) })?.value.uintValue else {
                // If we can't read the fabricIndex, exclude the entry
                return false
            }
            return UInt8(fiValue) == fabricIndex.rawValue
        }

        return .array(filtered)
    }
}
