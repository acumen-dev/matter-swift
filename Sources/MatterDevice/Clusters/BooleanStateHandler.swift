// BooleanStateHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Cluster handler for the Boolean State cluster (0x0045).
///
/// Read-only sensor cluster — provides initial attribute values only.
/// Typically used for contact sensors (door/window open/closed).
public struct BooleanStateHandler: ClusterHandler {

    public let clusterID = ClusterID.booleanState

    public init() {}

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        [
            (BooleanStateCluster.Attribute.stateValue, .bool(false)),
        ]
    }
}
