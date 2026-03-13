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

    public init(
        checkerContext: ACLChecker.RequestContext,
        acls: [AccessControlCluster.AccessControlEntry]
    ) {
        self.checkerContext = checkerContext
        self.acls = acls
    }
}
