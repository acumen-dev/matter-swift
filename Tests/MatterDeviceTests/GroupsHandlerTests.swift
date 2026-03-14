// GroupsHandlerTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import MatterTypes
import MatterModel
@testable import MatterDevice

// MARK: - Helpers

private func makeHandler() -> (GroupsHandler, GroupMembershipTable, CommissioningState) {
    let table = GroupMembershipTable()
    let state = CommissioningState()
    state.invokingFabricIndex = FabricIndex(rawValue: 1)
    let handler = GroupsHandler(groupMembershipTable: table, commissioningState: state)
    return (handler, table, state)
}

private func populateStore(_ store: AttributeStore, handler: some ClusterHandler, endpoint: EndpointID) {
    for (attr, value) in handler.initialAttributes() {
        store.set(endpoint: endpoint, cluster: handler.clusterID, attribute: attr, value: value)
    }
}

private func addGroupFields(groupID: UInt16, groupName: String = "") -> TLVElement {
    .structure([
        TLVElement.TLVField(tag: .contextSpecific(0), value: .unsignedInt(UInt64(groupID))),
        TLVElement.TLVField(tag: .contextSpecific(1), value: .utf8String(groupName)),
    ])
}

private func viewGroupFields(groupID: UInt16) -> TLVElement {
    .structure([
        TLVElement.TLVField(tag: .contextSpecific(0), value: .unsignedInt(UInt64(groupID))),
    ])
}

private func removeGroupFields(groupID: UInt16) -> TLVElement {
    .structure([
        TLVElement.TLVField(tag: .contextSpecific(0), value: .unsignedInt(UInt64(groupID))),
    ])
}

private func getMembershipFields(groupList: [UInt16]) -> TLVElement {
    .structure([
        TLVElement.TLVField(
            tag: .contextSpecific(0),
            value: .array(groupList.map { .unsignedInt(UInt64($0)) })
        ),
    ])
}

// MARK: - Test Suite

@Suite("GroupsHandler")
struct GroupsHandlerTests {

    let endpoint = EndpointID(rawValue: 2)

    // MARK: - Attributes

    @Test("nameSupport attribute defaults to 0")
    func nameSupportDefault() {
        let (handler, _, _) = makeHandler()
        let attrs = Dictionary(uniqueKeysWithValues: handler.initialAttributes())
        #expect(attrs[GroupsCluster.Attribute.nameSupport] == .unsignedInt(0))
    }

    @Test("clusterID is Groups (0x0004)")
    func clusterID() {
        let (handler, _, _) = makeHandler()
        #expect(handler.clusterID == .groups)
    }

    // MARK: - AddGroup

    @Test("AddGroup adds endpoint to membership table and returns success")
    func addGroup() throws {
        let (handler, table, _) = makeHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        let response = try handler.handleCommand(
            commandID: GroupsCluster.Command.addGroup,
            fields: addGroupFields(groupID: 0x0001),
            store: store,
            endpointID: endpoint
        )

        // Should return AddGroupResponse with status=success (0x00) and groupID=1
        guard case .structure(let fields) = response else {
            Issue.record("Expected structure response")
            return
        }
        let status = fields.first(where: { $0.tag == .contextSpecific(0) })?.value.uintValue
        let groupID = fields.first(where: { $0.tag == .contextSpecific(1) })?.value.uintValue
        #expect(status == UInt64(GroupsCluster.GroupStatus.success.rawValue))
        #expect(groupID == 1)

        // Verify table was updated
        #expect(table.endpoints(fabricIndex: 1, groupID: 0x0001).contains(endpoint.rawValue))
    }

    @Test("AddGroup is idempotent — re-adding an existing group returns success (spec §1.3.7.1)")
    func addGroupDuplicate() throws {
        let (handler, table, _) = makeHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        // First add
        table.addMember(fabricIndex: 1, groupID: 0x0001, endpointID: endpoint.rawValue)

        // Second add should return SUCCESS, not DUPLICATE (per Matter spec §1.3.7.1)
        let response = try handler.handleCommand(
            commandID: GroupsCluster.Command.addGroup,
            fields: addGroupFields(groupID: 0x0001),
            store: store,
            endpointID: endpoint
        )

        guard case .structure(let fields) = response else {
            Issue.record("Expected structure response")
            return
        }
        let status = fields.first(where: { $0.tag == .contextSpecific(0) })?.value.uintValue
        #expect(status == UInt64(GroupsCluster.GroupStatus.success.rawValue))
    }

    // MARK: - ViewGroup

    @Test("ViewGroup returns success and groupID for member endpoint")
    func viewGroupMember() throws {
        let (handler, table, _) = makeHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        table.addMember(fabricIndex: 1, groupID: 0x0002, endpointID: endpoint.rawValue)

        let response = try handler.handleCommand(
            commandID: GroupsCluster.Command.viewGroup,
            fields: viewGroupFields(groupID: 0x0002),
            store: store,
            endpointID: endpoint
        )

        guard case .structure(let fields) = response else {
            Issue.record("Expected structure response")
            return
        }
        let status = fields.first(where: { $0.tag == .contextSpecific(0) })?.value.uintValue
        let groupID = fields.first(where: { $0.tag == .contextSpecific(1) })?.value.uintValue
        #expect(status == UInt64(GroupsCluster.GroupStatus.success.rawValue))
        #expect(groupID == 0x0002)
    }

    @Test("ViewGroup returns notFound for non-member endpoint")
    func viewGroupNotFound() throws {
        let (handler, _, _) = makeHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        let response = try handler.handleCommand(
            commandID: GroupsCluster.Command.viewGroup,
            fields: viewGroupFields(groupID: 0x0099),
            store: store,
            endpointID: endpoint
        )

        guard case .structure(let fields) = response else {
            Issue.record("Expected structure response")
            return
        }
        let status = fields.first(where: { $0.tag == .contextSpecific(0) })?.value.uintValue
        #expect(status == UInt64(GroupsCluster.GroupStatus.notFound.rawValue))
    }

    // MARK: - GetGroupMembership

    @Test("GetGroupMembership with empty list returns all groups")
    func getMembershipAll() throws {
        let (handler, table, _) = makeHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        table.addMember(fabricIndex: 1, groupID: 0x0001, endpointID: endpoint.rawValue)
        table.addMember(fabricIndex: 1, groupID: 0x0003, endpointID: endpoint.rawValue)

        let response = try handler.handleCommand(
            commandID: GroupsCluster.Command.getGroupMembership,
            fields: getMembershipFields(groupList: []),
            store: store,
            endpointID: endpoint
        )

        guard case .structure(let fields) = response,
              let listField = fields.first(where: { $0.tag == .contextSpecific(1) }),
              case .array(let elements) = listField.value else {
            Issue.record("Expected structure response with array field")
            return
        }
        let groups = elements.compactMap { $0.uintValue.map { UInt16($0) } }.sorted()
        #expect(groups == [0x0001, 0x0003])
    }

    @Test("GetGroupMembership with filter returns matching groups only")
    func getMembershipFiltered() throws {
        let (handler, table, _) = makeHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        table.addMember(fabricIndex: 1, groupID: 0x0001, endpointID: endpoint.rawValue)
        table.addMember(fabricIndex: 1, groupID: 0x0003, endpointID: endpoint.rawValue)

        // Ask for groups 1, 2, 3 — endpoint is in 1 and 3 only
        let response = try handler.handleCommand(
            commandID: GroupsCluster.Command.getGroupMembership,
            fields: getMembershipFields(groupList: [0x0001, 0x0002, 0x0003]),
            store: store,
            endpointID: endpoint
        )

        guard case .structure(let fields) = response,
              let listField = fields.first(where: { $0.tag == .contextSpecific(1) }),
              case .array(let elements) = listField.value else {
            Issue.record("Expected structure response with array field")
            return
        }
        let groups = elements.compactMap { $0.uintValue.map { UInt16($0) } }.sorted()
        #expect(groups == [0x0001, 0x0003])
    }

    @Test("GetGroupMembership response has null capacity field")
    func getMembershipCapacity() throws {
        let (handler, _, _) = makeHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        let response = try handler.handleCommand(
            commandID: GroupsCluster.Command.getGroupMembership,
            fields: getMembershipFields(groupList: []),
            store: store,
            endpointID: endpoint
        )

        guard case .structure(let fields) = response,
              let capacityField = fields.first(where: { $0.tag == .contextSpecific(0) }) else {
            Issue.record("Expected structure response with capacity field")
            return
        }
        if case .null = capacityField.value {
            // Expected: capacity is null (we don't track a fixed limit)
        } else {
            Issue.record("Expected null capacity")
        }
    }

    // MARK: - RemoveGroup

    @Test("RemoveGroup removes endpoint from table and returns success")
    func removeGroup() throws {
        let (handler, table, _) = makeHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        table.addMember(fabricIndex: 1, groupID: 0x0005, endpointID: endpoint.rawValue)

        let response = try handler.handleCommand(
            commandID: GroupsCluster.Command.removeGroup,
            fields: removeGroupFields(groupID: 0x0005),
            store: store,
            endpointID: endpoint
        )

        guard case .structure(let fields) = response else {
            Issue.record("Expected structure response")
            return
        }
        let status = fields.first(where: { $0.tag == .contextSpecific(0) })?.value.uintValue
        #expect(status == UInt64(GroupsCluster.GroupStatus.success.rawValue))
        #expect(!table.endpoints(fabricIndex: 1, groupID: 0x0005).contains(endpoint.rawValue))
    }

    @Test("RemoveGroup returns notFound for non-member group")
    func removeGroupNotFound() throws {
        let (handler, _, _) = makeHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        let response = try handler.handleCommand(
            commandID: GroupsCluster.Command.removeGroup,
            fields: removeGroupFields(groupID: 0x0099),
            store: store,
            endpointID: endpoint
        )

        guard case .structure(let fields) = response else {
            Issue.record("Expected structure response")
            return
        }
        let status = fields.first(where: { $0.tag == .contextSpecific(0) })?.value.uintValue
        #expect(status == UInt64(GroupsCluster.GroupStatus.notFound.rawValue))
    }

    // MARK: - RemoveAllGroups

    @Test("RemoveAllGroups clears all groups for endpoint and returns nil")
    func removeAllGroups() throws {
        let (handler, table, _) = makeHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        table.addMember(fabricIndex: 1, groupID: 0x0001, endpointID: endpoint.rawValue)
        table.addMember(fabricIndex: 1, groupID: 0x0002, endpointID: endpoint.rawValue)

        let response = try handler.handleCommand(
            commandID: GroupsCluster.Command.removeAllGroups,
            fields: nil,
            store: store,
            endpointID: endpoint
        )

        #expect(response == nil)
        #expect(table.groups(fabricIndex: 1, endpointID: endpoint.rawValue).isEmpty)
    }

    // MARK: - Fabric Isolation

    @Test("AddGroup is fabric-scoped — different fabrics have separate membership")
    func fabricIsolation() throws {
        let table = GroupMembershipTable()
        let state = CommissioningState()
        let handler = GroupsHandler(groupMembershipTable: table, commissioningState: state)
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        // Fabric 1 adds to group 1
        state.invokingFabricIndex = FabricIndex(rawValue: 1)
        _ = try handler.handleCommand(
            commandID: GroupsCluster.Command.addGroup,
            fields: addGroupFields(groupID: 0x0001),
            store: store,
            endpointID: endpoint
        )

        // Fabric 2 adds to group 1
        state.invokingFabricIndex = FabricIndex(rawValue: 2)
        _ = try handler.handleCommand(
            commandID: GroupsCluster.Command.addGroup,
            fields: addGroupFields(groupID: 0x0001),
            store: store,
            endpointID: endpoint
        )

        // Both fabrics should have the endpoint in group 1
        #expect(table.endpoints(fabricIndex: 1, groupID: 0x0001).contains(endpoint.rawValue))
        #expect(table.endpoints(fabricIndex: 2, groupID: 0x0001).contains(endpoint.rawValue))

        // Removing from fabric 1 should not affect fabric 2
        state.invokingFabricIndex = FabricIndex(rawValue: 1)
        _ = try handler.handleCommand(
            commandID: GroupsCluster.Command.removeGroup,
            fields: removeGroupFields(groupID: 0x0001),
            store: store,
            endpointID: endpoint
        )
        #expect(!table.endpoints(fabricIndex: 1, groupID: 0x0001).contains(endpoint.rawValue))
        #expect(table.endpoints(fabricIndex: 2, groupID: 0x0001).contains(endpoint.rawValue))
    }

    // MARK: - AddGroupIfIdentifying

    @Test("AddGroupIfIdentifying adds endpoint when identifyTime > 0")
    func addGroupIfIdentifying_identifying() throws {
        let (handler, table, _) = makeHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        // Simulate an active identify session on this endpoint
        store.set(
            endpoint: endpoint,
            cluster: ClusterID(rawValue: 0x0003),  // Identify cluster
            attribute: AttributeID(rawValue: 0x0000),  // identifyTime
            value: .unsignedInt(30)
        )

        let response = try handler.handleCommand(
            commandID: GroupsCluster.Command.addGroupIfIdentifying,
            fields: addGroupFields(groupID: 0x000A),
            store: store,
            endpointID: endpoint
        )

        #expect(response == nil)  // No response payload per spec
        #expect(table.endpoints(fabricIndex: 1, groupID: 0x000A).contains(endpoint.rawValue))
    }

    @Test("AddGroupIfIdentifying does not add when identifyTime is 0")
    func addGroupIfIdentifying_notIdentifying() throws {
        let (handler, table, _) = makeHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        // identifyTime = 0 — not currently identifying
        store.set(
            endpoint: endpoint,
            cluster: ClusterID(rawValue: 0x0003),
            attribute: AttributeID(rawValue: 0x0000),
            value: .unsignedInt(0)
        )

        _ = try handler.handleCommand(
            commandID: GroupsCluster.Command.addGroupIfIdentifying,
            fields: addGroupFields(groupID: 0x000B),
            store: store,
            endpointID: endpoint
        )

        #expect(!table.endpoints(fabricIndex: 1, groupID: 0x000B).contains(endpoint.rawValue))
    }

    @Test("AddGroupIfIdentifying is silent when no Identify cluster present")
    func addGroupIfIdentifying_noIdentifyCluster() throws {
        let (handler, table, _) = makeHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)
        // No identifyTime attribute in store — no Identify cluster

        _ = try handler.handleCommand(
            commandID: GroupsCluster.Command.addGroupIfIdentifying,
            fields: addGroupFields(groupID: 0x000C),
            store: store,
            endpointID: endpoint
        )

        // Should silently skip — no group membership added
        #expect(!table.endpoints(fabricIndex: 1, groupID: 0x000C).contains(endpoint.rawValue))
    }
}
