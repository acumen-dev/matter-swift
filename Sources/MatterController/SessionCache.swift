// SessionCache.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterProtocol

/// Internal CASE session cache — accessed only within `MatterController` actor isolation.
///
/// Stores established secure sessions keyed by peer node ID, with
/// sequential session ID allocation.
///
/// A cached session never expires by age: it stays until the controller
/// invalidates it (the device stopped acknowledging, or the session was
/// closed). Evicting by wall-clock age would unregister a healthy session
/// out from under operations still running on it, failing them after the
/// device may already have acted.
struct SessionCache: Sendable {

    // MARK: - Storage

    private var entries: [NodeID: SecureSession] = [:]
    private var nextID: UInt16 = 100

    // MARK: - Lookup

    /// Retrieve the cached session for a node, or `nil` if absent.
    func session(for nodeID: NodeID) -> SecureSession? {
        entries[nodeID]
    }

    // MARK: - Store / Remove

    /// Cache a session for a node, replacing any existing entry.
    mutating func store(_ session: SecureSession, for nodeID: NodeID) {
        entries[nodeID] = session
    }

    /// Remove the cached session for a node.
    mutating func remove(for nodeID: NodeID) {
        entries.removeValue(forKey: nodeID)
    }

    // MARK: - Session ID Allocation

    /// Allocate the next session ID (sequential from 100, wrapping at UInt16.max).
    mutating func allocateSessionID() -> UInt16 {
        let id = nextID
        nextID = nextID == UInt16.max ? 100 : nextID + 1
        return id
    }

    // MARK: - Queries

    /// The number of cached sessions.
    var count: Int {
        entries.count
    }
}
