// OnOff.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes

/// On/Off cluster (0x0006).
///
/// Provides the ability to switch a device on or off. This is one of the most
/// commonly used application clusters in Matter, present on lights, switches,
/// outlets, and many other device types.
public enum OnOffCluster {

    // MARK: - Attribute IDs

    public enum Attribute {
        /// Whether the device is on or off. Bool.
        public static let onOff              = AttributeID(rawValue: 0x0000)
        /// Global scene control. Bool.
        public static let globalSceneControl = AttributeID(rawValue: 0x4000)
        /// On time (1/10ths of a second). UInt16.
        public static let onTime             = AttributeID(rawValue: 0x4001)
        /// Off wait time (1/10ths of a second). UInt16.
        public static let offWaitTime        = AttributeID(rawValue: 0x4002)
        /// Startup on/off behaviour. Enum8 (nullable).
        public static let startUpOnOff       = AttributeID(rawValue: 0x4003)
    }

    // MARK: - Command IDs

    public enum Command {
        /// Turn the device off.
        public static let off    = CommandID(rawValue: 0x00)
        /// Turn the device on.
        public static let on     = CommandID(rawValue: 0x01)
        /// Toggle the device on/off state.
        public static let toggle = CommandID(rawValue: 0x02)
    }
}
