// GroupMembershipTableTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
@testable import MatterDevice

@Suite("GroupMembershipTable")
struct GroupMembershipTableTests {

    @Test("addMember and query returns the endpoint")
    func addAndQuery() {
        let table = GroupMembershipTable()
        table.addMember(fabricIndex: 1, groupID: 0x0001, endpointID: 2)
        #expect(table.endpoints(fabricIndex: 1, groupID: 0x0001) == [2])
    }

    @Test("removeMember removes the endpoint")
    func removeMember() {
        let table = GroupMembershipTable()
        table.addMember(fabricIndex: 1, groupID: 0x0001, endpointID: 2)
        table.removeMember(fabricIndex: 1, groupID: 0x0001, endpointID: 2)
        #expect(table.endpoints(fabricIndex: 1, groupID: 0x0001).isEmpty)
    }

    @Test("removeAllGroupsForEndpoint clears all groups")
    func removeAllGroups() {
        let table = GroupMembershipTable()
        table.addMember(fabricIndex: 1, groupID: 0x0001, endpointID: 2)
        table.addMember(fabricIndex: 1, groupID: 0x0002, endpointID: 2)
        table.removeAllGroupsForEndpoint(fabricIndex: 1, endpointID: 2)
        #expect(table.groups(fabricIndex: 1, endpointID: 2).isEmpty)
    }

    @Test("fabric isolation keeps groups separate")
    func fabricIsolation() {
        let table = GroupMembershipTable()
        table.addMember(fabricIndex: 1, groupID: 0x0001, endpointID: 2)
        table.addMember(fabricIndex: 2, groupID: 0x0001, endpointID: 3)
        #expect(table.endpoints(fabricIndex: 1, groupID: 0x0001) == [2])
        #expect(table.endpoints(fabricIndex: 2, groupID: 0x0001) == [3])
    }

    @Test("removeFabric clears all membership for that fabric")
    func removeFabric() {
        let table = GroupMembershipTable()
        table.addMember(fabricIndex: 1, groupID: 0x0001, endpointID: 2)
        table.addMember(fabricIndex: 1, groupID: 0x0002, endpointID: 3)
        table.removeFabric(1)
        #expect(table.endpoints(fabricIndex: 1, groupID: 0x0001).isEmpty)
        #expect(table.endpoints(fabricIndex: 1, groupID: 0x0002).isEmpty)
    }

    @Test("allGroupsForFabric returns all group mappings")
    func allGroupsForFabric() {
        let table = GroupMembershipTable()
        table.addMember(fabricIndex: 1, groupID: 0x0001, endpointID: 2)
        table.addMember(fabricIndex: 1, groupID: 0x0001, endpointID: 3)
        table.addMember(fabricIndex: 1, groupID: 0x0002, endpointID: 4)
        let all = table.allGroupsForFabric(1)
        #expect(all.count == 2)
        let group1 = all.first { $0.groupID == 0x0001 }
        #expect(group1?.endpoints.sorted() == [2, 3])
    }

    @Test("groups query returns all groups for an endpoint")
    func groupsQuery() {
        let table = GroupMembershipTable()
        table.addMember(fabricIndex: 1, groupID: 0x0001, endpointID: 5)
        table.addMember(fabricIndex: 1, groupID: 0x0003, endpointID: 5)
        table.addMember(fabricIndex: 1, groupID: 0x0002, endpointID: 6)
        let groups = table.groups(fabricIndex: 1, endpointID: 5)
        #expect(groups == [0x0001, 0x0003])
    }

    @Test("multiple members in same group")
    func multipleMembers() {
        let table = GroupMembershipTable()
        table.addMember(fabricIndex: 1, groupID: 0x0010, endpointID: 2)
        table.addMember(fabricIndex: 1, groupID: 0x0010, endpointID: 3)
        table.addMember(fabricIndex: 1, groupID: 0x0010, endpointID: 4)
        #expect(table.endpoints(fabricIndex: 1, groupID: 0x0010) == [2, 3, 4])
    }

    @Test("removeMember on non-existent member is a no-op")
    func removeMemberNoOp() {
        let table = GroupMembershipTable()
        // Should not crash
        table.removeMember(fabricIndex: 1, groupID: 0x0001, endpointID: 99)
        #expect(table.endpoints(fabricIndex: 1, groupID: 0x0001).isEmpty)
    }
}
