// MatterStore.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

/// Storage protocol for device-side fabric and ACL persistence.
///
/// Persists committed fabrics (certificates, operational keys, IPK) and access
/// control entries across device restarts. Without a store, all commissioned
/// state is lost on restart.
///
/// ```swift
/// let store = JSONFileFabricStore(directory: configDir)
/// let server = MatterDeviceServer(config: config, fabricStore: store)
/// ```
public protocol MatterFabricStore: Sendable {

    /// Load the persisted device state, or `nil` if no state has been saved.
    func load() async throws -> StoredDeviceState?

    /// Save the complete device state.
    func save(_ state: StoredDeviceState) async throws
}

/// Storage protocol for controller-side identity and device registry persistence.
///
/// Persists the controller's root CA key, fabric identity, commissioned device
/// list, and node ID allocation counter. Without a store, the controller
/// generates a new root CA on every startup and forgets all commissioned devices.
///
/// ```swift
/// let store = JSONFileControllerStore(directory: configDir)
/// let controller = try MatterController(
///     transport: transport,
///     discovery: discovery,
///     configuration: config,
///     store: store
/// )
/// ```
public protocol MatterControllerStore: Sendable {

    /// Load the persisted controller state, or `nil` if no state has been saved.
    func load() async throws -> StoredControllerState?

    /// Save the complete controller state.
    func save(_ state: StoredControllerState) async throws
}

/// Storage protocol for device-side attribute value persistence.
///
/// Persists TLV-encoded attribute values (on/off state, brightness, temperature,
/// etc.) and cluster data versions. Without a store, all device state resets to
/// initial values on restart.
public protocol MatterAttributeStore: Sendable {

    /// Load the persisted attribute data, or `nil` if no data has been saved.
    func load() async throws -> StoredAttributeData?

    /// Save the complete attribute data.
    func save(_ data: StoredAttributeData) async throws
}
