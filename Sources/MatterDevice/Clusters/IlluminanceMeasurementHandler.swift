// IlluminanceMeasurementHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Cluster handler for the Illuminance Measurement cluster (0x0400).
///
/// Read-only sensor cluster — provides initial attribute values only.
public struct IlluminanceMeasurementHandler: ClusterHandler {

    public let clusterID = ClusterID.illuminanceMeasurement

    public init() {}

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        [
            (IlluminanceMeasurementCluster.Attribute.measuredValue, .unsignedInt(0)),
            (IlluminanceMeasurementCluster.Attribute.minMeasuredValue, .unsignedInt(1)),
            (IlluminanceMeasurementCluster.Attribute.maxMeasuredValue, .unsignedInt(0xFFFE)),
        ]
    }
}
