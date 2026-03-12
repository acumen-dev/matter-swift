// IlluminanceMeasurement.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes

/// Illuminance Measurement cluster (0x0400).
///
/// Reports ambient light level. The measured value is 10,000 × log10(lux) + 1,
/// where 0 indicates a value of 0 lux and 0xFFFE indicates the maximum.
public enum IlluminanceMeasurementCluster {

    // MARK: - Attribute IDs

    public enum Attribute {
        /// Measured illuminance value. UInt16 (nullable).
        public static let measuredValue    = AttributeID(rawValue: 0x0000)
        /// Minimum measurable illuminance. UInt16.
        public static let minMeasuredValue = AttributeID(rawValue: 0x0001)
        /// Maximum measurable illuminance. UInt16.
        public static let maxMeasuredValue = AttributeID(rawValue: 0x0002)
    }
}
