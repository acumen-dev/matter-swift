// ACLChecker.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

/// Pure stateless ACL checker.
///
/// Evaluates access control entries (ACLs) against a request context to determine
/// whether an operation is allowed. No actor dependencies — fully testable in isolation.
///
/// ```swift
/// let decision = ACLChecker.check(
///     requiredPrivilege: .view,
///     endpointID: EndpointID(rawValue: 1),
///     clusterID: ClusterID(rawValue: 0x0006),
///     context: .init(isPASE: false, subjectNodeID: 42, fabricIndex: FabricIndex(rawValue: 1)),
///     acls: fabricACLs
/// )
/// ```
public struct ACLChecker: Sendable {

    /// Result of an ACL check.
    public enum Decision: Sendable, Equatable {
        case allowed
        case denied
    }

    /// Session context for ACL evaluation.
    public struct RequestContext: Sendable {
        /// Whether this session was established via PASE (commissioning).
        public let isPASE: Bool
        /// The peer node ID of the session subject.
        public let subjectNodeID: UInt64
        /// The fabric index of the session.
        public let fabricIndex: FabricIndex
        /// Whether this request arrived via a group-addressed message.
        public let isGroupMessage: Bool
        /// The group ID, present when `isGroupMessage` is `true`.
        public let groupID: UInt16?

        public init(
            isPASE: Bool,
            subjectNodeID: UInt64,
            fabricIndex: FabricIndex,
            isGroupMessage: Bool = false,
            groupID: UInt16? = nil
        ) {
            self.isPASE = isPASE
            self.subjectNodeID = subjectNodeID
            self.fabricIndex = fabricIndex
            self.isGroupMessage = isGroupMessage
            self.groupID = groupID
        }
    }

    /// Check whether an operation is allowed by the given ACLs.
    ///
    /// Rules (per Matter Core Spec §6.6.5.1):
    /// 1. PASE sessions get implicit Administer privilege (bypass ACLs).
    /// 2. For CASE sessions, iterate ACLs filtering to `authMode == .case`.
    /// 3. For each ACE: check subject match, target match, and privilege level.
    /// 4. First sufficient match → `.allowed`. No match → `.denied`.
    ///
    /// - Parameters:
    ///   - requiredPrivilege: The minimum privilege required for the operation.
    ///   - endpointID: The endpoint being accessed.
    ///   - clusterID: The cluster being accessed.
    ///   - context: Session identity context.
    ///   - acls: The ACL entries for the session's fabric.
    /// - Returns: `.allowed` if the operation is permitted, `.denied` otherwise.
    public static func check(
        requiredPrivilege: AccessControlCluster.Privilege,
        endpointID: EndpointID,
        clusterID: ClusterID,
        context: RequestContext,
        acls: [AccessControlCluster.AccessControlEntry]
    ) -> Decision {
        // Rule 1: PASE sessions bypass ACLs with implicit Administer
        if context.isPASE {
            return .allowed
        }

        // Group message ACL evaluation: use group-mode ACEs only
        if context.isGroupMessage, let groupID = context.groupID {
            for ace in acls {
                guard ace.authMode == .group else { continue }
                guard ace.privilege >= requiredPrivilege else { continue }
                if !ace.subjects.isEmpty {
                    // subjects contains group IDs for group-mode ACEs
                    guard ace.subjects.contains(UInt64(groupID)) else { continue }
                }
                if let targets = ace.targets, !targets.isEmpty {
                    let matched = targets.contains { matchesTarget($0, endpointID: endpointID, clusterID: clusterID) }
                    guard matched else { continue }
                }
                return .allowed
            }
            return .denied
        }

        // Rule 2-4: Evaluate ACLs for CASE sessions
        for ace in acls {
            // Only consider CASE auth mode for CASE sessions
            guard ace.authMode == .case else { continue }

            // Check privilege level — ACE must grant at least the required privilege
            guard ace.privilege >= requiredPrivilege else { continue }

            // Check subject match — empty subjects means "any authenticated node on this fabric"
            if !ace.subjects.isEmpty {
                guard ace.subjects.contains(context.subjectNodeID) else { continue }
            }

            // Check target match — nil targets means "all endpoints and clusters"
            if let targets = ace.targets {
                let targetMatch = targets.contains { target in
                    matchesTarget(target, endpointID: endpointID, clusterID: clusterID)
                }
                guard targetMatch else { continue }
            }

            // All checks passed — this ACE grants access
            return .allowed
        }

        // No matching ACE found
        return .denied
    }

    /// Check whether a target matches the given endpoint and cluster.
    ///
    /// Per the spec, nil fields in a target act as wildcards:
    /// - `endpoint: nil` matches any endpoint
    /// - `cluster: nil` matches any cluster
    /// - Both nil matches everything
    private static func matchesTarget(
        _ target: AccessControlCluster.Target,
        endpointID: EndpointID,
        clusterID: ClusterID
    ) -> Bool {
        // Endpoint match: nil = wildcard (any endpoint)
        if let targetEndpoint = target.endpoint {
            guard targetEndpoint == endpointID else { return false }
        }

        // Cluster match: nil = wildcard (any cluster)
        if let targetCluster = target.cluster {
            guard targetCluster == clusterID else { return false }
        }

        return true
    }
}
