// DeviceTypeRegistry.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes

// MARK: - Device Type Registry

/// Registry of device type specifications for runtime lookup.
///
/// Populated at startup from generated code. Custom device types can be
/// registered via `register(_:)`.
public enum DeviceTypeRegistry {

    /// Storage for registered device types.
    /// Initialised once from generated code; mutated only by `register()` for custom types.
    nonisolated(unsafe) private static var specs: [DeviceTypeID: DeviceTypeSpec] = {
        var initial: [DeviceTypeID: DeviceTypeSpec] = [:]
        registerGeneratedTypes(into: &initial)
        return initial
    }()

    /// Returns the spec for a device type, or `nil` if not registered.
    public static func spec(for id: DeviceTypeID) -> DeviceTypeSpec? {
        specs[id]
    }

    /// Register a custom device type spec.
    ///
    /// Use this for vendor-specific device types not covered by the generated
    /// registry. Overwrites any existing registration for the same ID.
    public static func register(_ spec: DeviceTypeSpec) {
        specs[spec.id] = spec
    }

    /// All registered device type IDs.
    public static var allRegisteredIDs: [DeviceTypeID] {
        Array(specs.keys)
    }

    /// The number of registered device types.
    public static var count: Int {
        specs.count
    }
}
