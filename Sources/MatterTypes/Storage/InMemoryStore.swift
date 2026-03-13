// InMemoryStore.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

/// In-memory fabric store for testing.
///
/// Stores the last saved state in memory. Useful for unit tests and
/// integration tests that need persistence without file I/O.
public actor InMemoryFabricStore: MatterFabricStore {

    private var state: StoredDeviceState?

    /// The number of times `save()` has been called.
    public private(set) var saveCount: Int = 0

    public init(state: StoredDeviceState? = nil) {
        self.state = state
    }

    public func load() async throws -> StoredDeviceState? {
        state
    }

    public func save(_ state: StoredDeviceState) async throws {
        self.state = state
        saveCount += 1
    }
}

/// In-memory controller store for testing.
///
/// Stores the last saved state in memory. Useful for unit tests and
/// integration tests that need persistence without file I/O.
public actor InMemoryControllerStore: MatterControllerStore {

    private var state: StoredControllerState?

    /// The number of times `save()` has been called.
    public private(set) var saveCount: Int = 0

    public init(state: StoredControllerState? = nil) {
        self.state = state
    }

    public func load() async throws -> StoredControllerState? {
        state
    }

    public func save(_ state: StoredControllerState) async throws {
        self.state = state
        saveCount += 1
    }
}

/// In-memory attribute store for testing.
///
/// Stores the last saved attribute data in memory.
public actor InMemoryAttributeStore: MatterAttributeStore {

    private var data: StoredAttributeData?

    /// The number of times `save()` has been called.
    public private(set) var saveCount: Int = 0

    public init(data: StoredAttributeData? = nil) {
        self.data = data
    }

    public func load() async throws -> StoredAttributeData? {
        data
    }

    public func save(_ data: StoredAttributeData) async throws {
        self.data = data
        saveCount += 1
    }
}
