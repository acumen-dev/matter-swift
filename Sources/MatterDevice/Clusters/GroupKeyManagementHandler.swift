// GroupKeyManagementHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Cluster handler for the Group Key Management cluster (0x003F).
///
/// Manages group key sets used for group communication. Key sets are stored in
/// `GroupKeySetStorage` keyed by fabric index and group key set ID.
///
/// Commands:
/// - **KeySetWrite** (0x00): Store a group key set for the invoking fabric.
/// - **KeySetRead** (0x01): Read a key set with epoch keys redacted.
/// - **KeySetRemove** (0x03): Remove a group key set.
/// - **KeySetReadAllIndices** (0x04): Return all key set IDs for the invoking fabric.
///
/// The `groupKeyMap` and `groupTable` attributes are fabric-scoped — their arrays
/// are filtered to only include entries for the requesting fabric on reads.
public struct GroupKeyManagementHandler: ClusterHandler, @unchecked Sendable {

    public let clusterID = ClusterID.groupKeyManagement

    /// Storage backend for group key sets.
    public let keySetStorage: GroupKeySetStorage

    /// Commissioning state — used to retrieve the invoking fabric index.
    public let commissioningState: CommissioningState

    /// Optional group membership table for syncing group table attribute.
    public let groupMembershipTable: GroupMembershipTable?

    public init(commissioningState: CommissioningState, keySetStorage: GroupKeySetStorage) {
        self.commissioningState = commissioningState
        self.keySetStorage = keySetStorage
        self.groupMembershipTable = nil
    }

    public init(
        commissioningState: CommissioningState,
        keySetStorage: GroupKeySetStorage,
        groupMembershipTable: GroupMembershipTable
    ) {
        self.commissioningState = commissioningState
        self.keySetStorage = keySetStorage
        self.groupMembershipTable = groupMembershipTable
    }

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        [
            (GroupKeyManagementCluster.Attribute.groupKeyMap,           .array([])),
            (GroupKeyManagementCluster.Attribute.groupTable,            .array([])),
            (GroupKeyManagementCluster.Attribute.maxGroupsPerFabric,    .unsignedInt(4)),
            (GroupKeyManagementCluster.Attribute.maxGroupKeysPerFabric, .unsignedInt(3)),
        ]
    }

    public func acceptedCommands() -> [CommandID] {
        [
            GroupKeyManagementCluster.Command.keySetWrite,
            GroupKeyManagementCluster.Command.keySetRead,
            GroupKeyManagementCluster.Command.keySetRemove,
            GroupKeyManagementCluster.Command.keySetReadAllIndices,
        ]
    }

    public func generatedCommands() -> [CommandID] {
        [
            GroupKeyManagementCluster.Command.keySetReadResponse,
            GroupKeyManagementCluster.Command.keySetReadAllIndicesResponse,
        ]
    }

    // MARK: - Response Command IDs

    /// Maps request command IDs to their response command IDs per the Matter spec.
    ///
    /// Per spec §11.2.8, KeySetRead responds with KeySetReadResponse (0x02) and
    /// KeySetReadAllIndices responds with KeySetReadAllIndicesResponse (0x05).
    public func responseCommandID(for requestCommandID: CommandID) -> CommandID? {
        switch requestCommandID {
        case GroupKeyManagementCluster.Command.keySetRead:
            return GroupKeyManagementCluster.Command.keySetReadResponse
        case GroupKeyManagementCluster.Command.keySetReadAllIndices:
            return GroupKeyManagementCluster.Command.keySetReadAllIndicesResponse
        default:
            return nil
        }
    }

    public func handleCommand(
        commandID: CommandID,
        fields: TLVElement?,
        store: AttributeStore,
        endpointID: EndpointID
    ) throws -> TLVElement? {
        switch commandID {

        // MARK: KeySetWrite (0x00)
        case GroupKeyManagementCluster.Command.keySetWrite:
            guard let fields else { return nil }
            let keySet = try GroupKeyManagementCluster.GroupKeySetStruct.fromTLVElement(fields)
            let fabricIndex = commissioningState.invokingFabricIndex?.rawValue ?? 1
            keySetStorage.store(keySet: keySet, fabricIndex: fabricIndex)
            return nil  // success, no response payload

        // MARK: KeySetRead (0x01)
        case GroupKeyManagementCluster.Command.keySetRead:
            guard let fields,
                  case .structure(let structFields) = fields,
                  let idValue = structFields.first(where: { $0.tag == .contextSpecific(0) })?.value.uintValue else {
                throw GroupKeyManagementCluster.GroupKeyManagementError.missingField
            }
            let keySetID = UInt16(idValue)
            let fabricIndex = commissioningState.invokingFabricIndex?.rawValue ?? 1
            guard let keySet = keySetStorage.get(keySetID: keySetID, fabricIndex: fabricIndex) else {
                throw GroupKeyManagementCluster.GroupKeyManagementError.keySetNotFound
            }
            // Return KeySetReadResponse payload — keys are redacted per spec §11.2.8.2
            return .structure([
                .init(
                    tag: .contextSpecific(0),
                    value: keySet.toTLVElement(redactKeys: true)
                )
            ])

        // MARK: KeySetRemove (0x03)
        case GroupKeyManagementCluster.Command.keySetRemove:
            guard let fields,
                  case .structure(let structFields) = fields,
                  let idValue = structFields.first(where: { $0.tag == .contextSpecific(0) })?.value.uintValue else {
                throw GroupKeyManagementCluster.GroupKeyManagementError.missingField
            }
            let keySetID = UInt16(idValue)
            let fabricIndex = commissioningState.invokingFabricIndex?.rawValue ?? 1
            keySetStorage.remove(keySetID: keySetID, fabricIndex: fabricIndex)
            return nil  // success, no response payload

        // MARK: KeySetReadAllIndices (0x04)
        case GroupKeyManagementCluster.Command.keySetReadAllIndices:
            let fabricIndex = commissioningState.invokingFabricIndex?.rawValue ?? 1
            let ids = keySetStorage.allKeySetIDs(fabricIndex: fabricIndex)
            // Return KeySetReadAllIndicesResponse payload — array of UInt16 key set IDs at context tag 0
            return .structure([
                .init(
                    tag: .contextSpecific(0),
                    value: .array(ids.map { .unsignedInt(UInt64($0)) })
                )
            ])

        default:
            return nil
        }
    }

    public func validateWrite(attributeID: AttributeID, value: TLVElement) -> WriteValidation {
        switch attributeID {
        case GroupKeyManagementCluster.Attribute.groupKeyMap:
            // Validate that the value is an array of valid GroupKeyMapStruct entries
            guard case .array(let elements) = value else {
                return .constraintError
            }
            for element in elements {
                guard (try? GroupKeyManagementCluster.GroupKeyMapStruct.fromTLVElement(element)) != nil else {
                    return .constraintError
                }
            }
            return .allowed

        default:
            return .unsupportedWrite
        }
    }

    // MARK: - Fabric Scoping

    /// GroupKeyMap and GroupTable are fabric-scoped.
    public func isFabricScoped(attributeID: AttributeID) -> Bool {
        attributeID == GroupKeyManagementCluster.Attribute.groupKeyMap
            || attributeID == GroupKeyManagementCluster.Attribute.groupTable
    }

    /// Filter fabric-scoped attributes to only include entries for the requesting fabric.
    ///
    /// Entries in `groupKeyMap` and `groupTable` carry a fabricIndex field at context tag `0xFE`.
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

    // MARK: - Group Table Sync

    /// Sync the groupTable attribute from the group membership table for a given fabric.
    ///
    /// Reads all group-to-endpoint mappings from `groupMembershipTable` for the specified fabric
    /// and writes them to the `groupTable` attribute in the store.
    ///
    /// Each `GroupInfoMapStruct` entry encodes:
    /// - tag 0x00: groupId (UInt16)
    /// - tag 0x01: endpoints (Array of UInt16)
    /// - tag 0x02: groupName (String, optional — empty string if not set)
    /// - tag 0xFE: fabricIndex (UInt8)
    public func syncGroupTable(store: AttributeStore, endpointID: EndpointID, fabricIndex: UInt8) {
        guard let table = groupMembershipTable else { return }
        let groups = table.allGroupsForFabric(fabricIndex)
        let entries = groups.map { group in
            TLVElement.structure([
                TLVElement.TLVField(tag: .contextSpecific(0x00), value: .unsignedInt(UInt64(group.groupID))),
                TLVElement.TLVField(tag: .contextSpecific(0x01), value: .array(group.endpoints.map { .unsignedInt(UInt64($0)) })),
                TLVElement.TLVField(tag: .contextSpecific(0x02), value: .utf8String("")),
                TLVElement.TLVField(tag: .contextSpecific(0xFE), value: .unsignedInt(UInt64(fabricIndex))),
            ])
        }
        // Merge existing entries from other fabrics with the new entries for this fabric
        let existing = store.get(endpoint: endpointID, cluster: clusterID, attribute: GroupKeyManagementCluster.Attribute.groupTable)
        var otherFabricEntries: [TLVElement] = []
        if case .array(let existingArray) = existing {
            otherFabricEntries = existingArray.filter { element in
                guard case .structure(let fields) = element,
                      let fiValue = fields.first(where: { $0.tag == .contextSpecific(0xFE) })?.value.uintValue else {
                    return false
                }
                return UInt8(fiValue) != fabricIndex
            }
        }
        store.set(
            endpoint: endpointID,
            cluster: clusterID,
            attribute: GroupKeyManagementCluster.Attribute.groupTable,
            value: .array(otherFabricEntries + entries)
        )
    }
}
