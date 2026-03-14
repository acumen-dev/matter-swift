// GroupMembershipTable.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

/// Stores per-fabric group membership for endpoints.
///
/// Tracks which endpoints belong to which groups, keyed by fabric index.
/// Thread-safe via an internal `NSLock`. Callers do not need to serialize
/// access externally.
public final class GroupMembershipTable: @unchecked Sendable {

    // MARK: - State

    private let lock = NSLock()
    private var membership: [UInt8: [UInt16: Set<UInt16>]] = [:]
    // fabricIndex -> groupID -> Set<endpointID>

    // MARK: - Init

    public init() {}

    // MARK: - API

    /// Add an endpoint to a group on a specific fabric.
    public func addMember(fabricIndex: UInt8, groupID: UInt16, endpointID: UInt16) {
        lock.withLock {
            if membership[fabricIndex] == nil { membership[fabricIndex] = [:] }
            if membership[fabricIndex]![groupID] == nil { membership[fabricIndex]![groupID] = [] }
            membership[fabricIndex]![groupID]!.insert(endpointID)
        }
    }

    /// Remove an endpoint from a group on a specific fabric.
    public func removeMember(fabricIndex: UInt8, groupID: UInt16, endpointID: UInt16) {
        lock.withLock {
            membership[fabricIndex]?[groupID]?.remove(endpointID)
            if membership[fabricIndex]?[groupID]?.isEmpty == true {
                membership[fabricIndex]?.removeValue(forKey: groupID)
            }
        }
    }

    /// Remove an endpoint from all groups on a specific fabric.
    public func removeAllGroupsForEndpoint(fabricIndex: UInt8, endpointID: UInt16) {
        lock.withLock {
            guard var groups = membership[fabricIndex] else { return }
            for groupID in groups.keys {
                groups[groupID]?.remove(endpointID)
                if groups[groupID]?.isEmpty == true {
                    groups.removeValue(forKey: groupID)
                }
            }
            membership[fabricIndex] = groups
        }
    }

    /// Return all endpoint IDs that belong to a group on a specific fabric, sorted.
    public func endpoints(fabricIndex: UInt8, groupID: UInt16) -> [UInt16] {
        lock.withLock {
            Array(membership[fabricIndex]?[groupID] ?? []).sorted()
        }
    }

    /// Return all group IDs that an endpoint belongs to on a specific fabric, sorted.
    public func groups(fabricIndex: UInt8, endpointID: UInt16) -> [UInt16] {
        lock.withLock {
            guard let fabricGroups = membership[fabricIndex] else { return [] }
            return fabricGroups.compactMap { groupID, endpoints in
                endpoints.contains(endpointID) ? groupID : nil
            }.sorted()
        }
    }

    /// Remove all group membership data for a fabric.
    public func removeFabric(_ fabricIndex: UInt8) {
        lock.withLock {
            _ = membership.removeValue(forKey: fabricIndex)
        }
    }

    /// Return all group-to-endpoint mappings for a fabric, sorted by group ID.
    public func allGroupsForFabric(_ fabricIndex: UInt8) -> [(groupID: UInt16, endpoints: [UInt16])] {
        lock.withLock {
            guard let fabricGroups = membership[fabricIndex] else { return [] }
            return fabricGroups.map { groupID, endpoints in
                (groupID: groupID, endpoints: Array(endpoints).sorted())
            }.sorted { $0.groupID < $1.groupID }
        }
    }
}
