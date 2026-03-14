// FixedLabelHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Cluster handler for the Fixed Label cluster (0x0040).
///
/// Provides a read-only list of string label pairs for an endpoint.
/// Used on bridged endpoints for metadata such as room or zone assignments.
public struct FixedLabelHandler: ClusterHandler {

    public let clusterID = ClusterID(rawValue: 0x0040)

    /// The static label pairs for this endpoint.
    public let labels: [(label: String, value: String)]

    public init(labels: [(label: String, value: String)] = []) {
        self.labels = labels
    }

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        let labelElements = labels.map { entry in
            TLVElement.structure([
                TLVElement.TLVField(tag: .contextSpecific(0), value: .utf8String(entry.label)),
                TLVElement.TLVField(tag: .contextSpecific(1), value: .utf8String(entry.value)),
            ])
        }
        return [
            (FixedLabelCluster.Attribute.labelList, .array(labelElements)),
        ]
    }

    /// Fixed Label cluster is entirely read-only.
    public func validateWrite(attributeID: AttributeID, value: TLVElement) -> WriteValidation {
        .unsupportedWrite
    }
}
