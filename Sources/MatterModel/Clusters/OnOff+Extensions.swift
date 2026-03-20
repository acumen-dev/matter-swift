// OnOff+Extensions.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes

extension OnOffCluster {

    // MARK: - Custom Events (implementation-defined)

    public enum Event {
        /// StateChange — custom event emitted when OnOff state changes
        public static let stateChange = EventID(rawValue: 0x0000)
    }
}
