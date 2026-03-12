// TemperatureMeasurement.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes

/// Temperature Measurement cluster (0x0402).
///
/// Reports ambient temperature in units of 0.01°C. The measured value is a
/// signed 16-bit integer, so −27315 represents −273.15°C (absolute zero)
/// and 32767 represents 327.67°C.
public enum TemperatureMeasurementCluster {

    // MARK: - Attribute IDs

    public enum Attribute {
        /// Measured temperature in 0.01°C units. Int16 (nullable).
        public static let measuredValue    = AttributeID(rawValue: 0x0000)
        /// Minimum measurable temperature. Int16.
        public static let minMeasuredValue = AttributeID(rawValue: 0x0001)
        /// Maximum measurable temperature. Int16.
        public static let maxMeasuredValue = AttributeID(rawValue: 0x0002)
    }
}
