// GroupKeyManagementTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterModel
@testable import MatterDevice

@Suite("GroupKeyManagement")
struct GroupKeyManagementTests {

    // MARK: - Helpers

    private let endpoint = EndpointID(rawValue: 0)
    private let fabric1 = FabricIndex(rawValue: 1)
    private let fabric2 = FabricIndex(rawValue: 2)

    private func makeHandler(fabricIndex: FabricIndex = FabricIndex(rawValue: 1)) -> (GroupKeyManagementHandler, GroupKeySetStorage, AttributeStore) {
        let storage = GroupKeySetStorage()
        let state = CommissioningState()
        state.invokingFabricIndex = fabricIndex
        let handler = GroupKeyManagementHandler(commissioningState: state, keySetStorage: storage)
        let store = AttributeStore()
        for (attr, value) in handler.initialAttributes() {
            store.set(endpoint: endpoint, cluster: handler.clusterID, attribute: attr, value: value)
        }
        return (handler, storage, store)
    }

    private func makeKeySet(id: UInt16, fabricIndex: FabricIndex) -> GroupKeyManagementCluster.GroupKeySetStruct {
        GroupKeyManagementCluster.GroupKeySetStruct(
            groupKeySetID: id,
            groupKeySecurityPolicy: .trustFirst,
            epochKey0: Data(repeating: 0xAB, count: 16),
            epochStartTime0: 1_000_000,
            epochKey1: nil,
            epochStartTime1: nil,
            epochKey2: nil,
            epochStartTime2: nil
        )
    }

    // MARK: - Test 1: KeySetWrite + KeySetRead — verify redacted keys in response

    @Test("KeySetWrite stores key set and KeySetRead returns it with redacted epoch keys")
    func keySetWriteThenRead() throws {
        let (handler, _, store) = makeHandler()
        let keySet = makeKeySet(id: 1, fabricIndex: fabric1)

        // Write the key set
        let writeFields = keySet.toTLVElement()
        let writeResult = try handler.handleCommand(
            commandID: GroupKeyManagementCluster.Command.keySetWrite,
            fields: writeFields,
            store: store,
            endpointID: endpoint
        )
        #expect(writeResult == nil)  // success, no response payload

        // Read the key set back
        let readFields = TLVElement.structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(1))
        ])
        let readResult = try handler.handleCommand(
            commandID: GroupKeyManagementCluster.Command.keySetRead,
            fields: readFields,
            store: store,
            endpointID: endpoint
        )

        // Response should be a structure containing the key set at context tag 0
        guard case .structure(let outerFields) = readResult,
              let keySetField = outerFields.first(where: { $0.tag == .contextSpecific(0) }) else {
            Issue.record("Expected structure response with key set at tag 0")
            return
        }

        let returned = try GroupKeyManagementCluster.GroupKeySetStruct.fromTLVElement(keySetField.value)

        // Key set ID and policy should match
        #expect(returned.groupKeySetID == 1)
        #expect(returned.groupKeySecurityPolicy == .trustFirst)

        // Epoch keys must be redacted (nil after decode from null)
        #expect(returned.epochKey0 == nil)

        // Epoch start times should still be present
        #expect(returned.epochStartTime0 == 1_000_000)
    }

    // MARK: - Test 2: KeySetReadAllIndices — write 2 key sets, verify both IDs returned

    @Test("KeySetReadAllIndices returns all key set IDs for the invoking fabric")
    func keySetReadAllIndices() throws {
        let (handler, _, store) = makeHandler()

        // Write two key sets
        for id: UInt16 in [1, 2] {
            let keySet = makeKeySet(id: id, fabricIndex: fabric1)
            _ = try handler.handleCommand(
                commandID: GroupKeyManagementCluster.Command.keySetWrite,
                fields: keySet.toTLVElement(),
                store: store,
                endpointID: endpoint
            )
        }

        // Read all indices
        let result = try handler.handleCommand(
            commandID: GroupKeyManagementCluster.Command.keySetReadAllIndices,
            fields: nil,
            store: store,
            endpointID: endpoint
        )

        guard case .structure(let outerFields) = result,
              let indicesField = outerFields.first(where: { $0.tag == .contextSpecific(0) }),
              case .array(let idElements) = indicesField.value else {
            Issue.record("Expected structure response with array at tag 0")
            return
        }

        let ids = idElements.compactMap { $0.uintValue.map { UInt16($0) } }.sorted()
        #expect(ids == [1, 2])
    }

    // MARK: - Test 3: KeySetRemove — write then remove, verify gone

    @Test("KeySetRemove removes the key set so subsequent reads return nothing")
    func keySetRemove() throws {
        let (handler, storage, store) = makeHandler()
        let keySet = makeKeySet(id: 42, fabricIndex: fabric1)

        // Write
        _ = try handler.handleCommand(
            commandID: GroupKeyManagementCluster.Command.keySetWrite,
            fields: keySet.toTLVElement(),
            store: store,
            endpointID: endpoint
        )
        #expect(storage.get(keySetID: 42, fabricIndex: fabric1.rawValue) != nil)

        // Remove
        let removeFields = TLVElement.structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(42))
        ])
        let removeResult = try handler.handleCommand(
            commandID: GroupKeyManagementCluster.Command.keySetRemove,
            fields: removeFields,
            store: store,
            endpointID: endpoint
        )
        #expect(removeResult == nil)  // success, no response payload

        // Verify gone
        #expect(storage.get(keySetID: 42, fabricIndex: fabric1.rawValue) == nil)
    }

    // MARK: - Test 4: Fabric filtering — GroupKeyMapStruct entries filtered by fabricIndex tag 0xFE

    @Test("Fabric-scoped groupKeyMap attribute filters entries by fabricIndex")
    func fabricFiltering() throws {
        let (handler, _, store) = makeHandler()

        // Create two GroupKeyMapStruct entries, one per fabric
        let entry1 = GroupKeyManagementCluster.GroupKeyMapStruct(
            groupID: 0x0001, groupKeySetID: 1, fabricIndex: fabric1.rawValue
        )
        let entry2 = GroupKeyManagementCluster.GroupKeyMapStruct(
            groupID: 0x0002, groupKeySetID: 2, fabricIndex: fabric2.rawValue
        )

        // Store both entries in groupKeyMap attribute
        store.set(
            endpoint: endpoint,
            cluster: handler.clusterID,
            attribute: GroupKeyManagementCluster.Attribute.groupKeyMap,
            value: .array([entry1.toTLVElement(), entry2.toTLVElement()])
        )

        // Verify isFabricScoped returns true for groupKeyMap
        #expect(handler.isFabricScoped(attributeID: GroupKeyManagementCluster.Attribute.groupKeyMap) == true)
        #expect(handler.isFabricScoped(attributeID: GroupKeyManagementCluster.Attribute.groupTable) == true)
        #expect(handler.isFabricScoped(attributeID: GroupKeyManagementCluster.Attribute.maxGroupsPerFabric) == false)

        // Filter for fabric1 — should only get entry1
        let filtered = handler.filterFabricScopedAttribute(
            attributeID: GroupKeyManagementCluster.Attribute.groupKeyMap,
            value: .array([entry1.toTLVElement(), entry2.toTLVElement()]),
            fabricIndex: fabric1
        )

        guard case .array(let elements) = filtered else {
            Issue.record("Expected array")
            return
        }
        #expect(elements.count == 1)

        let decoded = try GroupKeyManagementCluster.GroupKeyMapStruct.fromTLVElement(elements[0])
        #expect(decoded.groupID == 0x0001)
        #expect(decoded.fabricIndex == fabric1.rawValue)
    }

    // MARK: - Test 5: Initial attributes — verify maxGroupsPerFabric=4, maxGroupKeysPerFabric=3, empty lists

    @Test("Initial attributes have correct defaults")
    func initialAttributes() throws {
        let (handler, _, store) = makeHandler()

        let groupKeyMap = store.get(
            endpoint: endpoint,
            cluster: handler.clusterID,
            attribute: GroupKeyManagementCluster.Attribute.groupKeyMap
        )
        #expect(groupKeyMap == .array([]))

        let groupTable = store.get(
            endpoint: endpoint,
            cluster: handler.clusterID,
            attribute: GroupKeyManagementCluster.Attribute.groupTable
        )
        #expect(groupTable == .array([]))

        let maxGroupsPerFabric = store.get(
            endpoint: endpoint,
            cluster: handler.clusterID,
            attribute: GroupKeyManagementCluster.Attribute.maxGroupsPerFabric
        )
        #expect(maxGroupsPerFabric == .unsignedInt(4))

        let maxGroupKeysPerFabric = store.get(
            endpoint: endpoint,
            cluster: handler.clusterID,
            attribute: GroupKeyManagementCluster.Attribute.maxGroupKeysPerFabric
        )
        #expect(maxGroupKeysPerFabric == .unsignedInt(3))
    }
}
