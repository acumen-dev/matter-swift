// DeviceTypeSpec.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes

// MARK: - Device Type Specification

/// Runtime-queryable device type specification metadata.
///
/// Contains the required and optional server clusters for a device type
/// as defined by the Matter specification. Used for validation and discovery.
public struct DeviceTypeSpec: Sendable {

    /// The device type ID.
    public let id: DeviceTypeID

    /// Human-readable device type name from the spec.
    public let name: String

    /// The spec revision for this device type.
    public let revision: Int

    /// Server cluster IDs that are mandatory for this device type.
    public let requiredServerClusters: [ClusterID]

    /// Server cluster IDs that are optional for this device type.
    public let optionalServerClusters: [ClusterID]

    public init(
        id: DeviceTypeID,
        name: String,
        revision: Int = 1,
        requiredServerClusters: [ClusterID],
        optionalServerClusters: [ClusterID] = []
    ) {
        self.id = id
        self.name = name
        self.revision = revision
        self.requiredServerClusters = requiredServerClusters
        self.optionalServerClusters = optionalServerClusters
    }
}
