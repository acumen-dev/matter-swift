// IMRequestContext.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Session context for ACL enforcement in the Interaction Model handler.
///
/// Carries the session identity and the applicable ACL entries so the IM handler
/// can check permissions without depending on `CommissioningState` or `SecureSession`.
///
/// Built by `MatterDeviceServer` from `SecureSession` + `CommissioningState.committedACLs`.
/// Tests can construct instances directly with any ACL configuration.
///
/// ```swift
/// let context = IMRequestContext(
///     checkerContext: ACLChecker.RequestContext(
///         isPASE: false,
///         subjectNodeID: 42,
///         fabricIndex: FabricIndex(rawValue: 1)
///     ),
///     acls: [AccessControlCluster.AccessControlEntry.adminACE(
///         subjectNodeID: 42,
///         fabricIndex: FabricIndex(rawValue: 1)
///     )]
/// )
/// ```
public struct IMRequestContext: Sendable {

    /// Session identity for ACL evaluation.
    public let checkerContext: ACLChecker.RequestContext

    /// ACL entries for the session's fabric.
    public let acls: [AccessControlCluster.AccessControlEntry]

    /// Whether fabric-scoped attributes should be filtered to only the session's fabric.
    ///
    /// When `true` (the default), fabric-scoped attributes such as ACLs, NOCs, and the
    /// fabrics list are filtered to return only entries belonging to the requesting fabric.
    /// When `false`, all entries are returned (e.g. for diagnostic or administrative reads).
    public let isFabricFiltered: Bool

    /// Whether this request arrived via a group-addressed message.
    ///
    /// When `true`, the request was addressed to a group ID rather than a specific node.
    /// Per the Matter spec, no response is sent for group-cast messages.
    public let isGroupMessage: Bool

    public init(
        checkerContext: ACLChecker.RequestContext,
        acls: [AccessControlCluster.AccessControlEntry],
        isFabricFiltered: Bool = true,
        isGroupMessage: Bool = false
    ) {
        self.checkerContext = checkerContext
        self.acls = acls
        self.isFabricFiltered = isFabricFiltered
        self.isGroupMessage = isGroupMessage
    }
}
