// LevelControl.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes

/// Level Control cluster (0x0008).
///
/// Provides an interface for controlling a characteristic of a device that
/// can be set to a level — most commonly brightness for lights.
public enum LevelControlCluster {

    // MARK: - Attribute IDs

    public enum Attribute {
        /// Current level. UInt8 (0–254, nullable).
        public static let currentLevel = AttributeID(rawValue: 0x0000)
        /// Minimum supported level. UInt8.
        public static let minLevel     = AttributeID(rawValue: 0x0002)
        /// Maximum supported level. UInt8.
        public static let maxLevel     = AttributeID(rawValue: 0x0003)
    }

    // MARK: - Command IDs

    public enum Command {
        /// Move to a specific level.
        public static let moveToLevel          = CommandID(rawValue: 0x00)
        /// Start moving up or down continuously.
        public static let move                 = CommandID(rawValue: 0x01)
        /// Step up or down by a delta.
        public static let step                 = CommandID(rawValue: 0x02)
        /// Stop any in-progress move/step.
        public static let stop                 = CommandID(rawValue: 0x03)
        /// Move to level with coupled On/Off behaviour.
        public static let moveToLevelWithOnOff = CommandID(rawValue: 0x04)
    }
}
