// OccupancySensingHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Cluster handler for the Occupancy Sensing cluster (0x0406).
///
/// Read-only sensor cluster — provides initial attribute values only.
/// The sensor type is configurable at init (default 0 = PIR).
public struct OccupancySensingHandler: ClusterHandler {

    public let clusterID = ClusterID.occupancySensing

    /// Occupancy sensor type (0 = PIR, 1 = Ultrasonic, 2 = PIR+Ultrasonic, 3 = Physical Contact).
    public let sensorType: UInt8

    public init(sensorType: UInt8 = 0) {
        self.sensorType = sensorType
    }

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        [
            (OccupancySensingCluster.Attribute.occupancy, .unsignedInt(0)),
            (OccupancySensingCluster.Attribute.occupancySensorType, .unsignedInt(UInt64(sensorType))),
        ]
    }
}
