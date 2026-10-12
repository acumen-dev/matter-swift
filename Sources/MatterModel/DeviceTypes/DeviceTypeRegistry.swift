// DeviceTypeRegistry.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes
import Synchronization

// MARK: - Device Type Registry

/// Registry of device type specifications for runtime lookup.
///
/// Populated at startup from generated code. Custom device types can be
/// registered via `register(_:)`.
public enum DeviceTypeRegistry {

    /// Storage for registered device types.
    /// Initialised once from generated code; mutated only by `register()` for custom types.
    /// Guarded by a mutex because tests and callers read and register concurrently.
    private static let specs = Mutex<[DeviceTypeID: DeviceTypeSpec]>({
        var initial: [DeviceTypeID: DeviceTypeSpec] = [:]
        registerGeneratedTypes(into: &initial)
        return initial
    }())

    /// Returns the spec for a device type, or `nil` if not registered.
    public static func spec(for id: DeviceTypeID) -> DeviceTypeSpec? {
        specs.withLock { $0[id] }
    }

    /// Register a custom device type spec.
    ///
    /// Use this for vendor-specific device types not covered by the generated
    /// registry. Overwrites any existing registration for the same ID.
    public static func register(_ spec: DeviceTypeSpec) {
        specs.withLock { $0[spec.id] = spec }
    }

    /// All registered device type IDs.
    public static var allRegisteredIDs: [DeviceTypeID] {
        specs.withLock { Array($0.keys) }
    }

    /// The number of registered device types.
    public static var count: Int {
        specs.withLock { $0.count }
    }
}
