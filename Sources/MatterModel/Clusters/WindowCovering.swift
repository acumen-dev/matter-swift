// WindowCovering.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes

/// Window Covering cluster (0x0102).
///
/// Provides an interface for controlling window coverings (blinds, shades,
/// curtains). Position values are in units of 0.01% (0 = fully open,
/// 10000 = fully closed).
public enum WindowCoveringCluster {

    // MARK: - Attribute IDs

    public enum Attribute {
        /// Window covering type. Enum8.
        public static let type                                 = AttributeID(rawValue: 0x0000)
        /// Operational status bitmap. Bitmap8.
        public static let operationalStatus                    = AttributeID(rawValue: 0x000A)
        /// Target lift position in 0.01% units. UInt16.
        public static let targetPositionLiftPercent100ths      = AttributeID(rawValue: 0x000B)
        /// Current lift position in 0.01% units. UInt16 (nullable).
        public static let currentPositionLiftPercent100ths     = AttributeID(rawValue: 0x000E)
    }

    // MARK: - Command IDs

    public enum Command {
        /// Move to fully open position.
        public static let upOrOpen          = CommandID(rawValue: 0x00)
        /// Move to fully closed position.
        public static let downOrClose       = CommandID(rawValue: 0x01)
        /// Stop any in-progress motion.
        public static let stopMotion        = CommandID(rawValue: 0x02)
        /// Move to a specific lift percentage.
        public static let goToLiftPercentage = CommandID(rawValue: 0x05)
    }
}
