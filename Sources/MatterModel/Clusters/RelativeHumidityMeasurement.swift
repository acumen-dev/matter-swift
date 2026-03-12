// RelativeHumidityMeasurement.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes

/// Relative Humidity Measurement cluster (0x0405).
///
/// Reports relative humidity in units of 0.01%. The measured value is an
/// unsigned 16-bit integer, so 0 represents 0.00% and 10000 represents 100.00%.
public enum RelativeHumidityMeasurementCluster {

    // MARK: - Attribute IDs

    public enum Attribute {
        /// Measured relative humidity in 0.01% units. UInt16 (nullable).
        public static let measuredValue    = AttributeID(rawValue: 0x0000)
        /// Minimum measurable humidity. UInt16.
        public static let minMeasuredValue = AttributeID(rawValue: 0x0001)
        /// Maximum measurable humidity. UInt16.
        public static let maxMeasuredValue = AttributeID(rawValue: 0x0002)
    }
}
