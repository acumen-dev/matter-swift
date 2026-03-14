// GroupsHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Cluster handler for the Groups cluster (0x0004).
///
/// Manages group membership for an endpoint, keyed by fabric index.
/// Group membership is stored in a shared `GroupMembershipTable` so that the
/// `MatterDeviceServer` can route group-addressed messages to member endpoints.
///
/// Commands:
/// - **AddGroup** (0x00): Add this endpoint to a group on the invoking fabric.
/// - **ViewGroup** (0x01): Return group info if this endpoint is a member.
/// - **GetGroupMembership** (0x02): Return all groups (or a filtered subset) for this endpoint.
/// - **RemoveGroup** (0x03): Remove this endpoint from a group.
/// - **RemoveAllGroups** (0x04): Remove this endpoint from all groups on the invoking fabric.
/// - **AddGroupIfIdentifying** (0x05): Add to group only if endpoint is currently identifying.
///
/// Group operations are fabric-scoped. The fabric index is obtained from
/// `CommissioningState.invokingFabricIndex` (set by `MatterDeviceServer` before each command),
/// matching the pattern used by `GroupKeyManagementHandler`.
///
/// The `nameSupport` attribute is 0 — group names are not stored by this implementation.
public struct GroupsHandler: ClusterHandler, @unchecked Sendable {

    public let clusterID = ClusterID.groups

    /// Per-fabric group membership table shared across all endpoint handlers.
    private let groupMembershipTable: GroupMembershipTable

    /// Commissioning state used to obtain the invoking fabric index.
    private let commissioningState: CommissioningState

    public init(
        groupMembershipTable: GroupMembershipTable,
        commissioningState: CommissioningState
    ) {
        self.groupMembershipTable = groupMembershipTable
        self.commissioningState = commissioningState
    }

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        [
            // nameSupport bit 7 = 0: group names NOT supported (simplest compliant implementation).
            (GroupsCluster.Attribute.nameSupport, .unsignedInt(0)),
        ]
    }

    public func handleCommand(
        commandID: CommandID,
        fields: TLVElement?,
        store: AttributeStore,
        endpointID: EndpointID
    ) throws -> TLVElement? {
        // Group operations are fabric-scoped. Use invokingFabricIndex set by MatterDeviceServer,
        // falling back to fabric 1 if not available (e.g., in unit tests).
        let fabricIndex = commissioningState.invokingFabricIndex?.rawValue ?? 1
        let epID = endpointID.rawValue

        switch commandID {

        // MARK: AddGroup (0x00)
        case GroupsCluster.Command.addGroup:
            guard let fields,
                  case .structure(let structFields) = fields,
                  let gidValue = structFields.first(where: { $0.tag == .contextSpecific(0) })?.value.uintValue else {
                // Missing required groupID — return failure response
                return addGroupResponse(status: .invalidInState, groupID: 0)
            }
            let groupID = UInt16(gidValue)

            // Per Matter spec §1.3.7.1, AddGroup is idempotent: re-adding an existing group
            // returns SUCCESS (not DUPLICATE). Check capacity only for new group additions.
            let existingGroups = groupMembershipTable.groups(fabricIndex: fabricIndex, endpointID: epID)
            if !existingGroups.contains(groupID) {
                // New group — enforce maxGroupsPerFabric limit (spec minimum: 4)
                let maxGroups = 4  // Matter spec minimum; see GroupKeyManagement.maxGroupsPerFabric
                if existingGroups.count >= maxGroups {
                    // Return RESOURCE_EXHAUSTED (0x89) via cluster-specific status
                    return addGroupResponse(status: .resourceExhausted, groupID: groupID)
                }
                groupMembershipTable.addMember(fabricIndex: fabricIndex, groupID: groupID, endpointID: epID)
            }
            return addGroupResponse(status: .success, groupID: groupID)

        // MARK: ViewGroup (0x01)
        case GroupsCluster.Command.viewGroup:
            guard let fields,
                  case .structure(let structFields) = fields,
                  let gidValue = structFields.first(where: { $0.tag == .contextSpecific(0) })?.value.uintValue else {
                return viewGroupResponse(status: .notFound, groupID: 0)
            }
            let groupID = UInt16(gidValue)

            let existingGroups = groupMembershipTable.groups(fabricIndex: fabricIndex, endpointID: epID)
            if existingGroups.contains(groupID) {
                return viewGroupResponse(status: .success, groupID: groupID)
            } else {
                return viewGroupResponse(status: .notFound, groupID: groupID)
            }

        // MARK: GetGroupMembership (0x02)
        case GroupsCluster.Command.getGroupMembership:
            let requestedGroups: [UInt16]
            if let fields,
               case .structure(let structFields) = fields,
               let listField = structFields.first(where: { $0.tag == .contextSpecific(0) }),
               case .array(let elements) = listField.value,
               !elements.isEmpty {
                // Caller provided a filter list — return only those groups this endpoint belongs to
                requestedGroups = elements.compactMap { $0.uintValue.map { UInt16($0) } }
            } else {
                // Empty or absent filter list — return all groups for this endpoint
                requestedGroups = []
            }

            let allGroups = groupMembershipTable.groups(fabricIndex: fabricIndex, endpointID: epID)
            let resultGroups: [UInt16]
            if requestedGroups.isEmpty {
                resultGroups = allGroups
            } else {
                resultGroups = requestedGroups.filter { allGroups.contains($0) }
            }

            // capacity: null (we don't track a fixed capacity limit)
            return .structure([
                TLVElement.TLVField(tag: .contextSpecific(0), value: .null),
                TLVElement.TLVField(
                    tag: .contextSpecific(1),
                    value: .array(resultGroups.map { .unsignedInt(UInt64($0)) })
                ),
            ])

        // MARK: RemoveGroup (0x03)
        case GroupsCluster.Command.removeGroup:
            guard let fields,
                  case .structure(let structFields) = fields,
                  let gidValue = structFields.first(where: { $0.tag == .contextSpecific(0) })?.value.uintValue else {
                return removeGroupResponse(status: .notFound, groupID: 0)
            }
            let groupID = UInt16(gidValue)

            let existingGroups = groupMembershipTable.groups(fabricIndex: fabricIndex, endpointID: epID)
            if existingGroups.contains(groupID) {
                groupMembershipTable.removeMember(fabricIndex: fabricIndex, groupID: groupID, endpointID: epID)
                return removeGroupResponse(status: .success, groupID: groupID)
            } else {
                return removeGroupResponse(status: .notFound, groupID: groupID)
            }

        // MARK: RemoveAllGroups (0x04)
        case GroupsCluster.Command.removeAllGroups:
            groupMembershipTable.removeAllGroupsForEndpoint(fabricIndex: fabricIndex, endpointID: epID)
            return nil  // No response payload per spec

        // MARK: AddGroupIfIdentifying (0x05)
        case GroupsCluster.Command.addGroupIfIdentifying:
            guard let fields,
                  case .structure(let structFields) = fields,
                  let gidValue = structFields.first(where: { $0.tag == .contextSpecific(0) })?.value.uintValue else {
                return nil
            }
            let groupID = UInt16(gidValue)

            // Check identifyTime from the Identify cluster on this endpoint (if present).
            // If identifyTime > 0, the endpoint is currently identifying.
            let identifyTime = store.get(
                endpoint: endpointID,
                cluster: ClusterID(rawValue: 0x0003),  // Identify cluster
                attribute: AttributeID(rawValue: 0x0000)  // identifyTime
            )
            let isIdentifying: Bool
            if let val = identifyTime, let t = val.uintValue {
                isIdentifying = t > 0
            } else {
                // No Identify cluster on this endpoint — skip silently per spec
                isIdentifying = false
            }

            if isIdentifying {
                groupMembershipTable.addMember(fabricIndex: fabricIndex, groupID: groupID, endpointID: epID)
            }
            return nil  // No response payload per spec

        default:
            return nil
        }
    }

    // MARK: - Private Response Builders

    private func addGroupResponse(status: GroupsCluster.GroupStatus, groupID: UInt16) -> TLVElement {
        .structure([
            TLVElement.TLVField(tag: .contextSpecific(0), value: .unsignedInt(UInt64(status.rawValue))),
            TLVElement.TLVField(tag: .contextSpecific(1), value: .unsignedInt(UInt64(groupID))),
        ])
    }

    private func viewGroupResponse(status: GroupsCluster.GroupStatus, groupID: UInt16) -> TLVElement {
        .structure([
            TLVElement.TLVField(tag: .contextSpecific(0), value: .unsignedInt(UInt64(status.rawValue))),
            TLVElement.TLVField(tag: .contextSpecific(1), value: .unsignedInt(UInt64(groupID))),
            TLVElement.TLVField(tag: .contextSpecific(2), value: .utf8String("")),  // groupName (empty — names not supported)
        ])
    }

    private func removeGroupResponse(status: GroupsCluster.GroupStatus, groupID: UInt16) -> TLVElement {
        .structure([
            TLVElement.TLVField(tag: .contextSpecific(0), value: .unsignedInt(UInt64(status.rawValue))),
            TLVElement.TLVField(tag: .contextSpecific(1), value: .unsignedInt(UInt64(groupID))),
        ])
    }
}
