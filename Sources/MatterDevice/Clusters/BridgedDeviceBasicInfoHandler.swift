// BridgedDeviceBasicInfoHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Cluster handler for the Bridged Device Basic Information cluster (0x0039).
///
/// Provides basic information about a bridged device. Most attributes are
/// read-only; `nodeLabel` is the only writable attribute.
public struct BridgedDeviceBasicInfoHandler: ClusterHandler {

    public let clusterID = ClusterID.bridgedDeviceBasicInformation

    /// Vendor name (optional, max 32 chars).
    public let vendorName: String

    /// Product name (optional, max 32 chars).
    public let productName: String

    /// User-visible label for this device.
    public let nodeLabel: String

    /// Whether the bridged device is currently reachable.
    public let reachable: Bool

    public init(
        vendorName: String = "",
        productName: String = "",
        nodeLabel: String,
        reachable: Bool = true
    ) {
        self.vendorName = vendorName
        self.productName = productName
        self.nodeLabel = nodeLabel
        self.reachable = reachable
    }

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        var attrs: [(AttributeID, TLVElement)] = [
            (BridgedDeviceBasicInfoCluster.Attribute.reachable, .bool(reachable)),
            (BridgedDeviceBasicInfoCluster.Attribute.nodeLabel, .utf8String(nodeLabel)),
        ]
        if !vendorName.isEmpty {
            attrs.append((BridgedDeviceBasicInfoCluster.Attribute.vendorName, .utf8String(vendorName)))
        }
        if !productName.isEmpty {
            attrs.append((BridgedDeviceBasicInfoCluster.Attribute.productName, .utf8String(productName)))
        }
        return attrs
    }

    public func validateWrite(attributeID: AttributeID, value: TLVElement) -> WriteValidation {
        // nodeLabel is writable (string only), everything else is read-only
        if attributeID == BridgedDeviceBasicInfoCluster.Attribute.nodeLabel, value.stringValue != nil {
            return .allowed
        }
        return .unsupportedWrite
    }
}
