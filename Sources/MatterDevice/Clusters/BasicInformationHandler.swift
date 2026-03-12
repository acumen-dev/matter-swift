// BasicInformationHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Cluster handler for the Basic Information cluster (0x0028).
///
/// Provides core identity and versioning attributes for the node.
/// Required on endpoint 0. All attributes are read-only except `nodeLabel`
/// and `location`.
public struct BasicInformationHandler: ClusterHandler {

    public let clusterID = ClusterID.basicInformation

    private let vendorName: String
    private let vendorID: UInt16
    private let productName: String
    private let productID: UInt16
    private let softwareVersion: UInt32
    private let softwareVersionString: String
    private let serialNumber: String
    private let uniqueID: String

    public init(
        vendorName: String = "SwiftMatter",
        vendorID: UInt16 = 0xFFF1,
        productName: String = "Bridge",
        productID: UInt16 = 0x8000,
        softwareVersion: UInt32 = 1,
        softwareVersionString: String = "1.0.0",
        serialNumber: String = "SM-0001",
        uniqueID: String = "swift-matter-001"
    ) {
        self.vendorName = vendorName
        self.vendorID = vendorID
        self.productName = productName
        self.productID = productID
        self.softwareVersion = softwareVersion
        self.softwareVersionString = softwareVersionString
        self.serialNumber = serialNumber
        self.uniqueID = uniqueID
    }

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        let capMinima = BasicInformationCluster.CapabilityMinima()
        return [
            (BasicInformationCluster.Attribute.dataModelRevision, .unsignedInt(17)),
            (BasicInformationCluster.Attribute.vendorName, .utf8String(vendorName)),
            (BasicInformationCluster.Attribute.vendorID, .unsignedInt(UInt64(vendorID))),
            (BasicInformationCluster.Attribute.productName, .utf8String(productName)),
            (BasicInformationCluster.Attribute.productID, .unsignedInt(UInt64(productID))),
            (BasicInformationCluster.Attribute.nodeLabel, .utf8String("")),
            (BasicInformationCluster.Attribute.location, .utf8String("XX")),
            (BasicInformationCluster.Attribute.hardwareVersion, .unsignedInt(0)),
            (BasicInformationCluster.Attribute.hardwareVersionString, .utf8String("1.0")),
            (BasicInformationCluster.Attribute.softwareVersion, .unsignedInt(UInt64(softwareVersion))),
            (BasicInformationCluster.Attribute.softwareVersionString, .utf8String(softwareVersionString)),
            (BasicInformationCluster.Attribute.serialNumber, .utf8String(serialNumber)),
            (BasicInformationCluster.Attribute.uniqueID, .utf8String(uniqueID)),
            (BasicInformationCluster.Attribute.capabilityMinima, capMinima.toTLVElement()),
        ]
    }

    public func validateWrite(attributeID: AttributeID, value: TLVElement) -> WriteValidation {
        switch attributeID {
        case BasicInformationCluster.Attribute.nodeLabel:
            guard let str = value.stringValue, str.count <= 32 else { return .constraintError }
            return .allowed
        case BasicInformationCluster.Attribute.location:
            guard let str = value.stringValue, str.count == 2 else { return .constraintError }
            return .allowed
        default:
            return .unsupportedWrite
        }
    }
}
