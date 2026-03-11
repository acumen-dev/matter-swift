// Identifiers.swift
// Copyright 2026 Monagle Pty Ltd

/// A Matter node ID (64-bit).
public struct NodeID: RawRepresentable, Sendable, Hashable, Codable {
    public let rawValue: UInt64
    public init(rawValue: UInt64) { self.rawValue = rawValue }

    /// Unspecified node ID (used in unsecured sessions).
    public static let unspecified = NodeID(rawValue: 0)
}

/// A Matter fabric index (8-bit, 1-254 valid).
public struct FabricIndex: RawRepresentable, Sendable, Hashable, Codable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }
}

/// A Matter endpoint ID (16-bit).
public struct EndpointID: RawRepresentable, Sendable, Hashable, Codable {
    public let rawValue: UInt16
    public init(rawValue: UInt16) { self.rawValue = rawValue }

    /// Root node endpoint.
    public static let root = EndpointID(rawValue: 0)
    /// Bridge aggregator endpoint.
    public static let aggregator = EndpointID(rawValue: 1)
}

/// A Matter cluster ID (32-bit).
public struct ClusterID: RawRepresentable, Sendable, Hashable, Codable {
    public let rawValue: UInt32
    public init(rawValue: UInt32) { self.rawValue = rawValue }
}

/// A Matter attribute ID (32-bit).
public struct AttributeID: RawRepresentable, Sendable, Hashable, Codable {
    public let rawValue: UInt32
    public init(rawValue: UInt32) { self.rawValue = rawValue }
}

/// A Matter command ID (32-bit).
public struct CommandID: RawRepresentable, Sendable, Hashable, Codable {
    public let rawValue: UInt32
    public init(rawValue: UInt32) { self.rawValue = rawValue }
}

/// A Matter event ID (32-bit).
public struct EventID: RawRepresentable, Sendable, Hashable, Codable {
    public let rawValue: UInt32
    public init(rawValue: UInt32) { self.rawValue = rawValue }
}

/// A Matter device type ID (32-bit).
public struct DeviceTypeID: RawRepresentable, Sendable, Hashable, Codable {
    public let rawValue: UInt32
    public init(rawValue: UInt32) { self.rawValue = rawValue }
}

/// A Matter group ID (16-bit).
public struct GroupID: RawRepresentable, Sendable, Hashable, Codable {
    public let rawValue: UInt16
    public init(rawValue: UInt16) { self.rawValue = rawValue }
}

/// A Matter vendor ID (16-bit).
public struct VendorID: RawRepresentable, Sendable, Hashable, Codable {
    public let rawValue: UInt16
    public init(rawValue: UInt16) { self.rawValue = rawValue }

    /// Test vendor ID (for development).
    public static let test = VendorID(rawValue: 0xFFF1)
}

/// A Matter product ID (16-bit).
public struct ProductID: RawRepresentable, Sendable, Hashable, Codable {
    public let rawValue: UInt16
    public init(rawValue: UInt16) { self.rawValue = rawValue }
}

/// A Matter fabric ID (64-bit).
public struct FabricID: RawRepresentable, Sendable, Hashable, Codable {
    public let rawValue: UInt64
    public init(rawValue: UInt64) { self.rawValue = rawValue }
}

/// A subscription ID (32-bit).
public struct SubscriptionID: RawRepresentable, Sendable, Hashable, Codable {
    public let rawValue: UInt32
    public init(rawValue: UInt32) { self.rawValue = rawValue }
}

/// A data version (32-bit, monotonically increasing per cluster instance).
public struct DataVersion: RawRepresentable, Sendable, Hashable, Codable {
    public let rawValue: UInt32
    public init(rawValue: UInt32) { self.rawValue = rawValue }
}

/// An event number (64-bit, monotonically increasing per node).
public struct EventNumber: RawRepresentable, Sendable, Hashable, Codable {
    public let rawValue: UInt64
    public init(rawValue: UInt64) { self.rawValue = rawValue }
}
