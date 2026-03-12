// SessionCache.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterProtocol

/// Internal CASE session cache — accessed only within `MatterController` actor isolation.
///
/// Stores established secure sessions keyed by peer node ID, with
/// expiry checking and sequential session ID allocation.
struct SessionCache: Sendable {

    // MARK: - Storage

    private struct Entry: Sendable {
        let session: SecureSession
        let storedAt: Date
    }

    private var entries: [NodeID: Entry] = [:]
    private var nextID: UInt16 = 100

    // MARK: - Lookup

    /// Retrieve a cached session for a node, or `nil` if expired/absent.
    func session(for nodeID: NodeID) -> SecureSession? {
        guard let entry = entries[nodeID] else { return nil }
        guard !isExpired(entry) else { return nil }
        return entry.session
    }

    // MARK: - Store / Remove

    /// Cache a session for a node, replacing any existing entry.
    mutating func store(_ session: SecureSession, for nodeID: NodeID) {
        entries[nodeID] = Entry(session: session, storedAt: Date())
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

    // MARK: - Maintenance

    /// Remove all expired sessions.
    mutating func pruneExpired() {
        entries = entries.filter { !isExpired($0.value) }
    }

    /// The number of cached sessions (including potentially expired ones).
    var count: Int {
        entries.count
    }

    // MARK: - Private

    private func isExpired(_ entry: Entry) -> Bool {
        let elapsed = Date().timeIntervalSince(entry.storedAt)
        let timeoutSeconds = Double(entry.session.timeout.components.seconds)
        return elapsed >= timeoutSeconds
    }
}
