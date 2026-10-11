// SessionCache.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterProtocol

/// Internal CASE session cache — accessed only within `MatterController` actor isolation.
///
/// Stores established secure sessions keyed by peer node ID, and allocates
/// local session IDs.
///
/// A cached session never expires by age: it stays until the controller
/// invalidates it (the device stopped acknowledging, or the session was
/// closed). Evicting by wall-clock age would unregister a healthy session
/// out from under operations still running on it, failing them after the
/// device may already have acted.
struct SessionCache: Sendable {

    // MARK: - Storage

    private var entries: [NodeID: SecureSession] = [:]
    private var nextID: UInt16
    /// IDs handed out for a handshake (or a PASE commissioning) that is
    /// still running; released when it ends, whatever the outcome.
    private var reserved: Set<UInt16> = []

    /// The lowest local session ID allocated; allocation wraps back to it.
    static let firstSessionID: UInt16 = 100

    /// - Parameter nextSessionID: where allocation starts (tests seed it
    ///   near the wrap).
    init(nextSessionID: UInt16 = SessionCache.firstSessionID) {
        self.nextID = max(nextSessionID, Self.firstSessionID)
    }

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

    /// Reserve the next free local session ID, sequentially from 100 and
    /// wrapping at `UInt16.max` back to 100.
    ///
    /// An ID is free unless it is registered with the messenger
    /// (`registered`, the caller's snapshot), held by a cached session, or
    /// already reserved. All three are needed: a cached session can be
    /// unregistered behind the cache's back, and an invalidated one leaves
    /// the cache before its unregistration completes. Reusing a live ID
    /// would let one node's cached session send under another node's keys.
    ///
    /// Choosing and reserving happen in this one synchronous call, so
    /// callers on the controller actor that suspend only *before* it (to
    /// snapshot `registered`) can never pick the same ID. A session the
    /// controller registers is reserved from before its registration until
    /// it is cached or unregistered, so a stale snapshot never misses one.
    ///
    /// - Returns: the reserved ID (release it with ``releaseSessionID(_:)``
    ///   when the handshake or commissioning ends), or `nil` if every ID is
    ///   in use.
    mutating func reserveSessionID(excluding registered: Set<UInt16>) -> UInt16? {
        let cached = Set(entries.values.map(\.localSessionID))
        let candidates = Int(UInt16.max) - Int(Self.firstSessionID) + 1
        for _ in 0..<candidates {
            let id = nextID
            nextID = nextID == UInt16.max ? Self.firstSessionID : nextID + 1
            if !registered.contains(id) && !cached.contains(id) && !reserved.contains(id) {
                reserved.insert(id)
                return id
            }
        }
        return nil
    }

    /// End a reservation made by ``reserveSessionID(excluding:)``. A session
    /// cached under the ID keeps it in use.
    mutating func releaseSessionID(_ id: UInt16) {
        reserved.remove(id)
    }

    // MARK: - Queries

    /// The number of cached sessions.
    var count: Int {
        entries.count
    }
}
