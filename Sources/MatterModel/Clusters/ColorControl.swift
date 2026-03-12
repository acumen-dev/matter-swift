// ColorControl.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes

/// Color Control cluster (0x0300).
///
/// Provides color management for lighting devices, supporting hue/saturation,
/// CIE x,y color coordinates, and color temperature (mireds) modes.
public enum ColorControlCluster {

    // MARK: - Attribute IDs

    public enum Attribute {
        /// Current hue. UInt8 (0–254).
        public static let currentHue                 = AttributeID(rawValue: 0x0000)
        /// Current saturation. UInt8 (0–254).
        public static let currentSaturation          = AttributeID(rawValue: 0x0001)
        /// Current CIE x color coordinate. UInt16.
        public static let currentX                   = AttributeID(rawValue: 0x0003)
        /// Current CIE y color coordinate. UInt16.
        public static let currentY                   = AttributeID(rawValue: 0x0004)
        /// Color temperature in mireds. UInt16.
        public static let colorTemperatureMireds     = AttributeID(rawValue: 0x0007)
        /// Current color mode (0=HS, 1=XY, 2=CT). Enum8.
        public static let colorMode                  = AttributeID(rawValue: 0x0008)
        /// Enhanced color mode. Enum8.
        public static let enhancedColorMode          = AttributeID(rawValue: 0x4001)
        /// Physical minimum color temperature in mireds. UInt16.
        public static let colorTempPhysicalMinMireds = AttributeID(rawValue: 0x400B)
        /// Physical maximum color temperature in mireds. UInt16.
        public static let colorTempPhysicalMaxMireds = AttributeID(rawValue: 0x400C)
    }

    // MARK: - Command IDs

    public enum Command {
        /// Move to a specific hue.
        public static let moveToHue              = CommandID(rawValue: 0x00)
        /// Move to a specific saturation.
        public static let moveToSaturation       = CommandID(rawValue: 0x03)
        /// Move to a specific CIE x,y color.
        public static let moveToColor            = CommandID(rawValue: 0x07)
        /// Move to a specific color temperature.
        public static let moveToColorTemperature = CommandID(rawValue: 0x0A)
    }
}
