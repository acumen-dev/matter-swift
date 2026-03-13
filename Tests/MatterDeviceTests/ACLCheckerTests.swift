// ACLCheckerTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterModel

@Suite("ACL Checker")
struct ACLCheckerTests {

    private let fabric1 = FabricIndex(rawValue: 1)
    private let fabric2 = FabricIndex(rawValue: 2)
    private let endpoint0 = EndpointID(rawValue: 0)
    private let endpoint1 = EndpointID(rawValue: 1)
    private let onOffCluster = ClusterID(rawValue: 0x0006)
    private let levelCluster = ClusterID(rawValue: 0x0008)
    private let aclCluster = ClusterID(rawValue: 0x001F)

    // MARK: - PASE Bypass

    @Test("PASE session bypasses ACLs with implicit Administer")
    func paseBypass() {
        let context = ACLChecker.RequestContext(isPASE: true, subjectNodeID: 0, fabricIndex: fabric1)

        // No ACLs at all — PASE still allowed
        let decision = ACLChecker.check(
            requiredPrivilege: .administer,
            endpointID: endpoint0,
            clusterID: aclCluster,
            context: context,
            acls: []
        )
        #expect(decision == .allowed)
    }

    // MARK: - No ACLs

    @Test("CASE session with no ACLs is denied")
    func noACLsDenied() {
        let context = ACLChecker.RequestContext(isPASE: false, subjectNodeID: 42, fabricIndex: fabric1)

        let decision = ACLChecker.check(
            requiredPrivilege: .view,
            endpointID: endpoint1,
            clusterID: onOffCluster,
            context: context,
            acls: []
        )
        #expect(decision == .denied)
    }

    // MARK: - Basic Privilege Grant

    @Test("Operate ACE grants View access")
    func operateGrantsView() {
        let context = ACLChecker.RequestContext(isPASE: false, subjectNodeID: 42, fabricIndex: fabric1)
        let acl = AccessControlCluster.AccessControlEntry(
            privilege: .operate,
            authMode: .case,
            subjects: [42],
            fabricIndex: fabric1
        )

        let decision = ACLChecker.check(
            requiredPrivilege: .view,
            endpointID: endpoint1,
            clusterID: onOffCluster,
            context: context,
            acls: [acl]
        )
        #expect(decision == .allowed)
    }

    @Test("Administer ACE grants Operate access")
    func administerGrantsOperate() {
        let context = ACLChecker.RequestContext(isPASE: false, subjectNodeID: 42, fabricIndex: fabric1)
        let acl = AccessControlCluster.AccessControlEntry(
            privilege: .administer,
            authMode: .case,
            subjects: [42],
            fabricIndex: fabric1
        )

        let decision = ACLChecker.check(
            requiredPrivilege: .operate,
            endpointID: endpoint1,
            clusterID: onOffCluster,
            context: context,
            acls: [acl]
        )
        #expect(decision == .allowed)
    }

    // MARK: - Insufficient Privilege

    @Test("View ACE denies Operate access")
    func viewDeniesOperate() {
        let context = ACLChecker.RequestContext(isPASE: false, subjectNodeID: 42, fabricIndex: fabric1)
        let acl = AccessControlCluster.AccessControlEntry(
            privilege: .view,
            authMode: .case,
            subjects: [42],
            fabricIndex: fabric1
        )

        let decision = ACLChecker.check(
            requiredPrivilege: .operate,
            endpointID: endpoint1,
            clusterID: onOffCluster,
            context: context,
            acls: [acl]
        )
        #expect(decision == .denied)
    }

    @Test("Operate ACE denies Administer access")
    func operateDeniesAdminister() {
        let context = ACLChecker.RequestContext(isPASE: false, subjectNodeID: 42, fabricIndex: fabric1)
        let acl = AccessControlCluster.AccessControlEntry(
            privilege: .operate,
            authMode: .case,
            subjects: [42],
            fabricIndex: fabric1
        )

        let decision = ACLChecker.check(
            requiredPrivilege: .administer,
            endpointID: endpoint0,
            clusterID: aclCluster,
            context: context,
            acls: [acl]
        )
        #expect(decision == .denied)
    }

    // MARK: - Subject Matching

    @Test("Empty subjects matches any node on the fabric")
    func emptySubjectsMatchesAny() {
        let context = ACLChecker.RequestContext(isPASE: false, subjectNodeID: 99, fabricIndex: fabric1)
        let acl = AccessControlCluster.AccessControlEntry(
            privilege: .operate,
            authMode: .case,
            subjects: [],  // any authenticated node
            fabricIndex: fabric1
        )

        let decision = ACLChecker.check(
            requiredPrivilege: .operate,
            endpointID: endpoint1,
            clusterID: onOffCluster,
            context: context,
            acls: [acl]
        )
        #expect(decision == .allowed)
    }

    @Test("Specific subjects must match the session node ID")
    func specificSubjectMustMatch() {
        let context = ACLChecker.RequestContext(isPASE: false, subjectNodeID: 99, fabricIndex: fabric1)
        let acl = AccessControlCluster.AccessControlEntry(
            privilege: .operate,
            authMode: .case,
            subjects: [42, 43],  // node 99 is not in the list
            fabricIndex: fabric1
        )

        let decision = ACLChecker.check(
            requiredPrivilege: .operate,
            endpointID: endpoint1,
            clusterID: onOffCluster,
            context: context,
            acls: [acl]
        )
        #expect(decision == .denied)
    }

    @Test("Subject in list is matched")
    func subjectInListMatched() {
        let context = ACLChecker.RequestContext(isPASE: false, subjectNodeID: 43, fabricIndex: fabric1)
        let acl = AccessControlCluster.AccessControlEntry(
            privilege: .operate,
            authMode: .case,
            subjects: [42, 43],
            fabricIndex: fabric1
        )

        let decision = ACLChecker.check(
            requiredPrivilege: .operate,
            endpointID: endpoint1,
            clusterID: onOffCluster,
            context: context,
            acls: [acl]
        )
        #expect(decision == .allowed)
    }

    // MARK: - Target Matching

    @Test("Nil targets matches all endpoints and clusters")
    func nilTargetsMatchesAll() {
        let context = ACLChecker.RequestContext(isPASE: false, subjectNodeID: 42, fabricIndex: fabric1)
        let acl = AccessControlCluster.AccessControlEntry(
            privilege: .operate,
            authMode: .case,
            subjects: [42],
            targets: nil,
            fabricIndex: fabric1
        )

        let decision = ACLChecker.check(
            requiredPrivilege: .operate,
            endpointID: endpoint1,
            clusterID: onOffCluster,
            context: context,
            acls: [acl]
        )
        #expect(decision == .allowed)
    }

    @Test("Specific endpoint target must match")
    func specificEndpointTarget() {
        let context = ACLChecker.RequestContext(isPASE: false, subjectNodeID: 42, fabricIndex: fabric1)
        let acl = AccessControlCluster.AccessControlEntry(
            privilege: .operate,
            authMode: .case,
            subjects: [42],
            targets: [.init(endpoint: endpoint1)],  // only endpoint 1
            fabricIndex: fabric1
        )

        // Endpoint 1 — allowed
        let d1 = ACLChecker.check(
            requiredPrivilege: .operate,
            endpointID: endpoint1,
            clusterID: onOffCluster,
            context: context,
            acls: [acl]
        )
        #expect(d1 == .allowed)

        // Endpoint 0 — denied
        let d2 = ACLChecker.check(
            requiredPrivilege: .operate,
            endpointID: endpoint0,
            clusterID: onOffCluster,
            context: context,
            acls: [acl]
        )
        #expect(d2 == .denied)
    }

    @Test("Specific cluster target must match")
    func specificClusterTarget() {
        let context = ACLChecker.RequestContext(isPASE: false, subjectNodeID: 42, fabricIndex: fabric1)
        let acl = AccessControlCluster.AccessControlEntry(
            privilege: .operate,
            authMode: .case,
            subjects: [42],
            targets: [.init(cluster: onOffCluster)],  // only OnOff cluster
            fabricIndex: fabric1
        )

        // OnOff — allowed
        let d1 = ACLChecker.check(
            requiredPrivilege: .operate,
            endpointID: endpoint1,
            clusterID: onOffCluster,
            context: context,
            acls: [acl]
        )
        #expect(d1 == .allowed)

        // LevelControl — denied
        let d2 = ACLChecker.check(
            requiredPrivilege: .operate,
            endpointID: endpoint1,
            clusterID: levelCluster,
            context: context,
            acls: [acl]
        )
        #expect(d2 == .denied)
    }

    @Test("Endpoint and cluster target both must match")
    func endpointAndClusterTarget() {
        let context = ACLChecker.RequestContext(isPASE: false, subjectNodeID: 42, fabricIndex: fabric1)
        let acl = AccessControlCluster.AccessControlEntry(
            privilege: .operate,
            authMode: .case,
            subjects: [42],
            targets: [.init(cluster: onOffCluster, endpoint: endpoint1)],
            fabricIndex: fabric1
        )

        // Correct endpoint + cluster — allowed
        let d1 = ACLChecker.check(
            requiredPrivilege: .operate,
            endpointID: endpoint1,
            clusterID: onOffCluster,
            context: context,
            acls: [acl]
        )
        #expect(d1 == .allowed)

        // Correct cluster, wrong endpoint — denied
        let d2 = ACLChecker.check(
            requiredPrivilege: .operate,
            endpointID: endpoint0,
            clusterID: onOffCluster,
            context: context,
            acls: [acl]
        )
        #expect(d2 == .denied)

        // Correct endpoint, wrong cluster — denied
        let d3 = ACLChecker.check(
            requiredPrivilege: .operate,
            endpointID: endpoint1,
            clusterID: levelCluster,
            context: context,
            acls: [acl]
        )
        #expect(d3 == .denied)
    }

    // MARK: - Multiple ACEs

    @Test("First sufficient ACE grants access")
    func firstSufficientACE() {
        let context = ACLChecker.RequestContext(isPASE: false, subjectNodeID: 42, fabricIndex: fabric1)
        let viewACL = AccessControlCluster.AccessControlEntry(
            privilege: .view,
            authMode: .case,
            subjects: [42],
            fabricIndex: fabric1
        )
        let operateACL = AccessControlCluster.AccessControlEntry(
            privilege: .operate,
            authMode: .case,
            subjects: [42],
            fabricIndex: fabric1
        )

        // View is insufficient for operate, but operate ACE grants it
        let decision = ACLChecker.check(
            requiredPrivilege: .operate,
            endpointID: endpoint1,
            clusterID: onOffCluster,
            context: context,
            acls: [viewACL, operateACL]
        )
        #expect(decision == .allowed)
    }

    // MARK: - Auth Mode Filtering

    @Test("PASE auth mode ACEs are ignored for CASE sessions")
    func paseAuthModeIgnoredForCASE() {
        let context = ACLChecker.RequestContext(isPASE: false, subjectNodeID: 42, fabricIndex: fabric1)
        let acl = AccessControlCluster.AccessControlEntry(
            privilege: .administer,
            authMode: .pase,  // PASE auth mode
            subjects: [42],
            fabricIndex: fabric1
        )

        let decision = ACLChecker.check(
            requiredPrivilege: .view,
            endpointID: endpoint1,
            clusterID: onOffCluster,
            context: context,
            acls: [acl]
        )
        #expect(decision == .denied)
    }

    @Test("Group auth mode ACEs are ignored for CASE sessions")
    func groupAuthModeIgnoredForCASE() {
        let context = ACLChecker.RequestContext(isPASE: false, subjectNodeID: 42, fabricIndex: fabric1)
        let acl = AccessControlCluster.AccessControlEntry(
            privilege: .administer,
            authMode: .group,
            subjects: [],
            fabricIndex: fabric1
        )

        let decision = ACLChecker.check(
            requiredPrivilege: .view,
            endpointID: endpoint1,
            clusterID: onOffCluster,
            context: context,
            acls: [acl]
        )
        #expect(decision == .denied)
    }

    // MARK: - Privilege Comparable

    @Test("Privilege ordering is correct")
    func privilegeOrdering() {
        #expect(AccessControlCluster.Privilege.view < .proxied)
        #expect(AccessControlCluster.Privilege.proxied < .operate)
        #expect(AccessControlCluster.Privilege.operate < .manage)
        #expect(AccessControlCluster.Privilege.manage < .administer)
        #expect(AccessControlCluster.Privilege.view < .administer)
        #expect(AccessControlCluster.Privilege.administer >= .administer)
        #expect(AccessControlCluster.Privilege.operate >= .view)
    }

    // MARK: - Admin ACE Convenience

    @Test("adminACE convenience creates correct entry")
    func adminACEConvenience() {
        let context = ACLChecker.RequestContext(isPASE: false, subjectNodeID: 42, fabricIndex: fabric1)
        let acl = AccessControlCluster.AccessControlEntry.adminACE(
            subjectNodeID: 42,
            fabricIndex: fabric1
        )

        // Should grant administer on any endpoint/cluster
        let decision = ACLChecker.check(
            requiredPrivilege: .administer,
            endpointID: endpoint0,
            clusterID: aclCluster,
            context: context,
            acls: [acl]
        )
        #expect(decision == .allowed)
    }
}
