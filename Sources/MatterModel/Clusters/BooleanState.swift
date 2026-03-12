// BooleanState.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes

/// Boolean State cluster (0x0045).
///
/// Reports a simple boolean state, typically used by contact sensors
/// (door/window open/closed). The state value is `true` when the
/// monitored condition is detected (e.g., contact open).
public enum BooleanStateCluster {

    // MARK: - Attribute IDs

    public enum Attribute {
        /// Current boolean state. Bool.
        public static let stateValue = AttributeID(rawValue: 0x0000)
    }
}
