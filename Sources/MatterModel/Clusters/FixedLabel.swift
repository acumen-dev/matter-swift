// FixedLabel.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes

public enum FixedLabelCluster {
    public static let id = ClusterID(rawValue: 0x0040)

    public enum Attribute {
        public static let labelList = AttributeID(rawValue: 0x0000)  // list of LabelStruct, read-only
    }
}
