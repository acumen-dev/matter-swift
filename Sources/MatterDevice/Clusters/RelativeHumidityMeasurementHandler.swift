// RelativeHumidityMeasurementHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Cluster handler for the Relative Humidity Measurement cluster (0x0405).
///
/// Read-only sensor cluster — provides initial attribute values only.
/// Humidity values are in 0.01% units (e.g., 5000 = 50.00%).
public struct RelativeHumidityMeasurementHandler: ClusterHandler {

    public let clusterID = ClusterID.relativeHumidityMeasurement

    public init() {}

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        [
            (RelativeHumidityMeasurementCluster.Attribute.measuredValue, .unsignedInt(0)),
            (RelativeHumidityMeasurementCluster.Attribute.minMeasuredValue, .unsignedInt(0)),
            (RelativeHumidityMeasurementCluster.Attribute.maxMeasuredValue, .unsignedInt(10000)),
        ]
    }
}
