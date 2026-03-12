// OccupancySensing.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes

/// Occupancy Sensing cluster (0x0406).
///
/// Reports whether a space is occupied. The occupancy attribute is a bitmap
/// where bit 0 indicates occupancy (1 = occupied, 0 = unoccupied). The sensor
/// type describes the detection technology used (PIR, ultrasonic, etc.).
public enum OccupancySensingCluster {

    // MARK: - Attribute IDs

    public enum Attribute {
        /// Occupancy state bitmap. Bitmap8 (bit 0 = occupied).
        public static let occupancy           = AttributeID(rawValue: 0x0000)
        /// Type of occupancy sensor. Enum8 (0 = PIR, 1 = Ultrasonic, 2 = PIR+Ultrasonic, 3 = Physical Contact).
        public static let occupancySensorType = AttributeID(rawValue: 0x0001)
    }
}
