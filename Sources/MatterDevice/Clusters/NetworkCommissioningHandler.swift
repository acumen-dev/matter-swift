// NetworkCommissioningHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Cluster handler for the Network Commissioning cluster (0x0031).
///
/// Exposes a single Ethernet interface as a read-only network configuration.
/// For bridges running over Ethernet, this satisfies the spec requirement for
/// a network commissioning cluster on the root endpoint.
///
/// All attributes are read-only except `interfaceEnabled` (writable per spec).
public struct NetworkCommissioningHandler: ClusterHandler {

    public let clusterID: ClusterID

    private let networkName: String
    private let connected: Bool

    public init(networkName: String = "en0", connected: Bool = true) {
        self.clusterID = NetworkCommissioningCluster.id
        self.networkName = networkName
        self.connected = connected
    }

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        let networkID = Data(networkName.utf8)
        let networkEntry = NetworkCommissioningCluster.NetworkInfoStruct(
            networkID: networkID,
            connected: connected
        ).toTLVElement()

        return [
            (NetworkCommissioningCluster.Attribute.maxNetworks, .unsignedInt(1)),
            (NetworkCommissioningCluster.Attribute.networks, .array([networkEntry])),
            (NetworkCommissioningCluster.Attribute.interfaceEnabled, .bool(true)),
            (NetworkCommissioningCluster.Attribute.lastNetworkingStatus, .null),
            (NetworkCommissioningCluster.Attribute.lastNetworkID, .null),
            (NetworkCommissioningCluster.Attribute.lastConnectErrorValue, .null),
            (NetworkCommissioningCluster.Attribute.featureMap, .unsignedInt(UInt64(NetworkCommissioningCluster.Feature.ethernet))),
            (NetworkCommissioningCluster.Attribute.clusterRevision, .unsignedInt(1)),
        ]
    }

    public func validateWrite(attributeID: AttributeID, value: TLVElement) -> WriteValidation {
        switch attributeID {
        case NetworkCommissioningCluster.Attribute.interfaceEnabled:
            guard value.boolValue != nil else { return .constraintError }
            return .allowed
        default:
            return .unsupportedWrite
        }
    }
}
