// Identify.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes

public enum IdentifyCluster {
    public static let id = ClusterID(rawValue: 0x0003)

    public enum Attribute {
        public static let identifyTime = AttributeID(rawValue: 0x0000)  // UInt16, writable
        public static let identifyType = AttributeID(rawValue: 0x0001)  // UInt8, read-only
    }

    public enum Command {
        public static let identify      = CommandID(rawValue: 0x00)
        public static let identifyQuery = CommandID(rawValue: 0x01)
    }

    public enum ResponseCommand {
        public static let identifyQueryResponse = CommandID(rawValue: 0x00)
    }
}
