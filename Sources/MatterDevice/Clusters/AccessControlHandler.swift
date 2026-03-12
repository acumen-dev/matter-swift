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
            // ACL writes are accepted — the list is an array of ACE structures
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
}
