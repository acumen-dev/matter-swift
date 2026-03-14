// GroupKeySetStorage.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Storage for GroupKeySet entries, keyed by fabric index and key set ID.
///
/// Acts as the backing store for the GroupKeyManagement cluster's key set operations.
/// Marked `@unchecked Sendable` — callers must ensure access is serialized (the
/// `GroupKeyManagementHandler` is used inside `MatterBridge` which owns the
/// `MatterDeviceServer` actor context).
public final class GroupKeySetStorage: @unchecked Sendable {

    // MARK: - State

    /// fabricIndex → keySetID → GroupKeySetStruct
    private var storage: [UInt8: [UInt16: GroupKeyManagementCluster.GroupKeySetStruct]] = [:]

    // MARK: - Init

    public init() {}

    // MARK: - Operations

    /// Store a key set for the given fabric.
    ///
    /// Replaces any existing key set with the same `groupKeySetID` on that fabric.
    public func store(keySet: GroupKeyManagementCluster.GroupKeySetStruct, fabricIndex: UInt8) {
        if storage[fabricIndex] == nil {
            storage[fabricIndex] = [:]
        }
        storage[fabricIndex]![keySet.groupKeySetID] = keySet
    }

    /// Retrieve a key set by ID for the given fabric.
    ///
    /// - Returns: The key set, or nil if not found.
    public func get(keySetID: UInt16, fabricIndex: UInt8) -> GroupKeyManagementCluster.GroupKeySetStruct? {
        storage[fabricIndex]?[keySetID]
    }

    /// Remove a key set by ID for the given fabric.
    ///
    /// - Returns: `true` if the key set existed and was removed, `false` if it was not found.
    @discardableResult
    public func remove(keySetID: UInt16, fabricIndex: UInt8) -> Bool {
        guard storage[fabricIndex]?[keySetID] != nil else { return false }
        storage[fabricIndex]?.removeValue(forKey: keySetID)
        return true
    }

    /// Return all key set IDs for the given fabric.
    public func allKeySetIDs(fabricIndex: UInt8) -> [UInt16] {
        Array(storage[fabricIndex]?.keys ?? [:].keys).sorted()
    }

    /// Remove all key sets for a fabric (called when a fabric is removed).
    public func removeFabric(_ fabricIndex: UInt8) {
        storage.removeValue(forKey: fabricIndex)
    }
}
