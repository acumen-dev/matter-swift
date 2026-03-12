// BridgedDeviceBasicInformation.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes

/// Bridged Device Basic Information cluster (0x0039).
///
/// Provides basic information about a bridged device (one that is not a native
/// Matter device but is exposed via a bridge). Present on each bridged endpoint.
public enum BridgedDeviceBasicInfoCluster {

    // MARK: - Attribute IDs

    public enum Attribute {
        /// Vendor name. String (max 32 chars).
        public static let vendorName       = AttributeID(rawValue: 0x0001)
        /// Vendor ID. UInt16.
        public static let vendorID         = AttributeID(rawValue: 0x0002)
        /// Product name. String (max 32 chars).
        public static let productName      = AttributeID(rawValue: 0x0003)
        /// User-settable label. String (max 32 chars, writable).
        public static let nodeLabel        = AttributeID(rawValue: 0x0005)
        /// Hardware version. UInt16.
        public static let hardwareVersion  = AttributeID(rawValue: 0x0007)
        /// Software version. UInt32.
        public static let softwareVersion  = AttributeID(rawValue: 0x0009)
        /// Serial number. String (max 32 chars).
        public static let serialNumber     = AttributeID(rawValue: 0x000F)
        /// Whether the bridged device is reachable. Bool.
        public static let reachable        = AttributeID(rawValue: 0x0011)
        /// Unique ID. String (max 32 chars).
        public static let uniqueID         = AttributeID(rawValue: 0x0012)
    }
}
