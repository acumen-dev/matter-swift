// Endpoint.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

/// Configuration for a Matter endpoint.
///
/// Groups a device type declaration with its cluster handlers, forming
/// a complete endpoint that can be registered with `EndpointManager`.
public struct EndpointConfig: Sendable {

    /// The endpoint ID.
    public let endpointID: EndpointID

    /// Device types on this endpoint — (type, revision) pairs.
    ///
    /// Most endpoints declare a single device type, but the Matter spec
    /// allows multiple (e.g., a device that is both a light and a switch).
    public let deviceTypes: [(DeviceTypeID, UInt16)]

    /// Cluster handlers for this endpoint.
    ///
    /// Each handler manages one cluster (OnOff, LevelControl, Descriptor, etc.).
    /// The endpoint manager writes each handler's `initialAttributes()` to the
    /// attribute store when the endpoint is registered.
    public let clusterHandlers: [any ClusterHandler]

    public init(
        endpointID: EndpointID,
        deviceTypes: [(DeviceTypeID, UInt16)],
        clusterHandlers: [any ClusterHandler]
    ) {
        self.endpointID = endpointID
        self.deviceTypes = deviceTypes
        self.clusterHandlers = clusterHandlers
    }
}
