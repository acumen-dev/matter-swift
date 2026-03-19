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

    // MARK: - Debug: Binary Search Filter
    //
    // Temporarily limit which attributes are reported to isolate "End of TLV" in Apple Home.
    // Set to nil to report all attributes (normal behavior).
    // Set to a range like 0x0000...0x0009 to report only attributes in that range.
    // Global attributes (0xFFF8+) are always included regardless of this filter.
    public nonisolated(unsafe) static var debugAttributeFilter: ClosedRange<UInt32>? = nil

    private let vendorName: String
    private let vendorID: UInt16
    private let productName: String
    private let productID: UInt16
    private let softwareVersion: UInt32
    private let softwareVersionString: String
    private let serialNumber: String
    private let uniqueID: String
    private let manufacturingDate: String
    private let partNumber: String
    private let productURL: String
    private let productLabel: String

    public init(
        vendorName: String = "SwiftMatter",
        vendorID: UInt16 = 0xFFF1,
        productName: String = "Bridge",
        productID: UInt16 = 0x8000,
        softwareVersion: UInt32 = 1,
        softwareVersionString: String = "1.0.0",
        serialNumber: String = "SM-0001",
        uniqueID: String = "swift-matter-001",
        manufacturingDate: String = "",
        partNumber: String = "",
        productURL: String = "",
        productLabel: String = ""
    ) {
        self.vendorName = vendorName
        self.vendorID = vendorID
        self.productName = productName
        self.productID = productID
        self.softwareVersion = softwareVersion
        self.softwareVersionString = softwareVersionString
        self.serialNumber = serialNumber
        self.uniqueID = uniqueID
        self.manufacturingDate = manufacturingDate
        self.partNumber = partNumber
        self.productURL = productURL
        self.productLabel = productLabel
    }

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        let capMinima = BasicInformationCluster.CapabilityMinima()
        var attrs: [(AttributeID, TLVElement)] = [
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
        // Optional attributes — only include if non-empty
        if !manufacturingDate.isEmpty {
            attrs.append((BasicInformationCluster.Attribute.manufacturingDate, .utf8String(manufacturingDate)))
        }
        if !partNumber.isEmpty {
            attrs.append((BasicInformationCluster.Attribute.partNumber, .utf8String(partNumber)))
        }
        if !productURL.isEmpty {
            attrs.append((BasicInformationCluster.Attribute.productURL, .utf8String(productURL)))
        }
        if !productLabel.isEmpty {
            attrs.append((BasicInformationCluster.Attribute.productLabel, .utf8String(productLabel)))
        }

        // Debug: filter attributes for binary search
        if let filter = Self.debugAttributeFilter {
            attrs = attrs.filter { attrID, _ in
                let raw = attrID.rawValue
                // Always include global attributes (0xFFF8+)
                return raw >= 0xFFF8 || filter.contains(raw)
            }
        }

        return attrs
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

    // MARK: - Event Factories

    /// Create a StartUp event for this node.
    ///
    /// Emitted on device boot with the software version that just started.
    public func startUpEvent(softwareVersion: UInt32) -> ClusterEvent {
        ClusterEvent(
            eventID: BasicInformationCluster.Event.startUp,
            priority: .critical,
            data: .structure([
                TLVElement.TLVField(tag: .contextSpecific(0), value: .unsignedInt(UInt64(softwareVersion)))
            ]),
            isUrgent: false
        )
    }

    /// Create a ShutDown event for this node.
    ///
    /// Emitted on graceful device shutdown.
    public func shutDownEvent() -> ClusterEvent {
        ClusterEvent(
            eventID: BasicInformationCluster.Event.shutDown,
            priority: .critical,
            data: nil,
            isUrgent: false
        )
    }

    /// Create a Leave event for this node.
    ///
    /// Emitted when a fabric is removed from the device.
    public func leaveEvent(fabricIndex: UInt8) -> ClusterEvent {
        ClusterEvent(
            eventID: BasicInformationCluster.Event.leave,
            priority: .info,
            data: .structure([
                TLVElement.TLVField(tag: .contextSpecific(0), value: .unsignedInt(UInt64(fabricIndex)))
            ]),
            isUrgent: false
        )
    }
}
