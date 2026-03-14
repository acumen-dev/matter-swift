// DoorLock.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes

/// Door Lock cluster (0x0101).
///
/// Provides an interface for controlling a door lock. Lock state values:
/// 0 = Not Fully Locked, 1 = Locked, 2 = Unlocked, 3 = Unlatched.
public enum DoorLockCluster {

    // MARK: - Attribute IDs

    public enum Attribute {
        /// Current lock state. Enum8 (nullable).
        public static let lockState       = AttributeID(rawValue: 0x0000)
        /// Lock type. Enum8.
        public static let lockType        = AttributeID(rawValue: 0x0001)
        /// Whether the actuator is enabled. Bool.
        public static let actuatorEnabled = AttributeID(rawValue: 0x0002)
    }

    // MARK: - Command IDs

    public enum Command {
        /// Lock the door.
        public static let lockDoor   = CommandID(rawValue: 0x00)
        /// Unlock the door.
        public static let unlockDoor = CommandID(rawValue: 0x01)
    }

    // MARK: - Event IDs

    public enum Event {
        /// DoorLockAlarm event — emitted when a door lock alarm condition is detected.
        ///
        /// Payload: Structure { 0: alarmCode (UInt8) }
        public static let doorLockAlarm = EventID(rawValue: 0x0000)
        /// LockOperation event — emitted when the lock state changes due to a lock/unlock command.
        ///
        /// Payload: Structure { 0: lockState (UInt8): 1 = Locked, 2 = Unlocked }
        public static let lockOperation = EventID(rawValue: 0x0002)
    }
}
