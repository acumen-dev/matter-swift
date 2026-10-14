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
///
/// ## Contract
///
/// - `load()` returns `nil` when nothing has been saved, and **throws** when state exists
///   but cannot be read, including state with a `schemaVersion` newer than this library
///   understands. It never returns partial state.
/// - `save(_:)` replaces the stored state entirely (no merge) and returns only once the
///   state is durable; a failed save throws and leaves the previous state intact.
/// - The state holds secrets, named so an implementation can protect them: the root CA key
///   (`StoredControllerIdentity.rootKeyRaw`), the controller's operational key
///   (`operationalKeyRaw`) and the IPK epoch key (`ipkEpochKey`). A store must keep them
///   readable by the owning user only (``JSONFileControllerStore`` writes `0600`) and must
///   not log them.
///
/// ``MatterControllerStoreConformance`` in `MatterTestSupport` runs this contract against
/// any implementation.
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
