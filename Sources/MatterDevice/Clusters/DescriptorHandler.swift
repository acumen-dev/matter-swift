// DescriptorHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Cluster handler for the Descriptor cluster (0x001D).
///
/// All Descriptor attributes are read-only. Initial values are built from
/// the endpoint's configuration (device types, server clusters, parts list).
public struct DescriptorHandler: ClusterHandler {

    public let clusterID = ClusterID.descriptor

    private let deviceTypes: [(DeviceTypeID, UInt16)]
    private let serverClusters: [ClusterID]
    private let partsList: [EndpointID]

    /// Create a Descriptor handler.
    ///
    /// - Parameters:
    ///   - deviceTypes: Device type / revision pairs for this endpoint.
    ///   - serverClusters: Cluster IDs of all server clusters on this endpoint.
    ///   - partsList: Child endpoint IDs (for aggregator endpoints).
    public init(
        deviceTypes: [(DeviceTypeID, UInt16)],
        serverClusters: [ClusterID],
        partsList: [EndpointID] = []
    ) {
        self.deviceTypes = deviceTypes
        self.serverClusters = serverClusters
        self.partsList = partsList
    }

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        // deviceTypeList: array of DeviceTypeStruct
        let deviceTypeElements = deviceTypes.map { dt in
            DescriptorCluster.DeviceTypeStruct(deviceType: dt.0, revision: dt.1).toTLVElement()
        }

        // serverList: array of uint32 (cluster IDs)
        let serverElements = serverClusters.map { TLVElement.unsignedInt(UInt64($0.rawValue)) }

        // clientList: empty array
        let clientElements: [TLVElement] = []

        // partsList: array of uint16 (endpoint IDs)
        let partsElements = partsList.map { TLVElement.unsignedInt(UInt64($0.rawValue)) }

        return [
            (DescriptorCluster.Attribute.deviceTypeList, .array(deviceTypeElements)),
            (DescriptorCluster.Attribute.serverList, .array(serverElements)),
            (DescriptorCluster.Attribute.clientList, .array(clientElements)),
            (DescriptorCluster.Attribute.partsList, .array(partsElements)),
        ]
    }

    // All writes rejected — Descriptor is entirely read-only.
    // Uses default validateWrite implementation (.unsupportedWrite).
}
