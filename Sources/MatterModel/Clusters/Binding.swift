// Binding.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes

public enum BindingCluster {
    public static let id = ClusterID(rawValue: 0x001E)

    public enum Attribute {
        public static let binding = AttributeID(rawValue: 0x0000)  // list of TargetStruct, fabric-scoped, writable
    }
}
