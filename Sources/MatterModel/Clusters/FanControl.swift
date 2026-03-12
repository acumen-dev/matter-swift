// FanControl.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes

/// Fan Control cluster (0x0202).
///
/// Provides an interface for controlling fans via writable attributes.
/// Fan mode values: 0=Off, 1=Low, 2=Medium, 3=High, 4=On, 5=Auto, 6=Smart.
/// No commands — all control is via attribute writes.
public enum FanControlCluster {

    // MARK: - Attribute IDs

    public enum Attribute {
        /// Fan mode. Enum8 (0=Off, 1=Low, 2=Medium, 3=High, 4=On, 5=Auto).
        public static let fanMode      = AttributeID(rawValue: 0x0000)
        /// Percent setting. UInt8 (0–100, writable).
        public static let percentSetting = AttributeID(rawValue: 0x0002)
        /// Current percent. UInt8 (0–100, read-only).
        public static let percentCurrent = AttributeID(rawValue: 0x0003)
        /// Maximum speed level. UInt8 (read-only).
        public static let speedMax     = AttributeID(rawValue: 0x0004)
        /// Speed setting. UInt8 (0–speedMax, writable).
        public static let speedSetting = AttributeID(rawValue: 0x0005)
        /// Current speed. UInt8 (0–speedMax, read-only).
        public static let speedCurrent = AttributeID(rawValue: 0x0006)
    }
}
