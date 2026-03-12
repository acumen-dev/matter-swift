// TemperatureMeasurementHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Cluster handler for the Temperature Measurement cluster (0x0402).
///
/// Read-only sensor cluster — provides initial attribute values only.
/// Temperature values are in 0.01°C units (e.g., 2200 = 22.00°C).
public struct TemperatureMeasurementHandler: ClusterHandler {

    public let clusterID = ClusterID.temperatureMeasurement

    public init() {}

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        [
            (TemperatureMeasurementCluster.Attribute.measuredValue, .signedInt(0)),
            (TemperatureMeasurementCluster.Attribute.minMeasuredValue, .signedInt(-27315)),
            (TemperatureMeasurementCluster.Attribute.maxMeasuredValue, .signedInt(32767)),
        ]
    }
}
