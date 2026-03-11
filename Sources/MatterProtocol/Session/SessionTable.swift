// SessionTable.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

/// Manages active Matter sessions.
///
/// The session table stores secure sessions indexed by local session ID.
/// It handles session lookup, creation, eviction, and timeout.
public actor SessionTable {
    /// Maximum number of concurrent sessions.
    public let maxSessions: Int

    /// Active sessions keyed by local session ID.
    private var sessions: [UInt16: SecureSession] = [:]

    /// Counter deduplication state per session.
    private var dedup: [UInt16: CounterDeduplication] = [:]

    /// Next session ID to assign.
    private var nextSessionID: UInt16 = 1

    /// Global counter for unsecured messages.
    public let globalCounter = GlobalMessageCounter()

    public init(maxSessions: Int = 16) {
        self.maxSessions = maxSessions
    }

    // MARK: - Session Management

    /// Add a new session to the table.
    ///
    /// If the table is full, the oldest session is evicted.
    public func add(_ session: SecureSession) {
        if sessions.count >= maxSessions {
            evictOldest()
        }
        sessions[session.localSessionID] = session
        dedup[session.localSessionID] = CounterDeduplication(encrypted: true)
    }

    /// Look up a session by local session ID.
    public func session(for sessionID: UInt16) -> SecureSession? {
        sessions[sessionID]
    }

    /// Remove a session by local session ID.
    @discardableResult
    public func remove(sessionID: UInt16) -> SecureSession? {
        dedup.removeValue(forKey: sessionID)
        return sessions.removeValue(forKey: sessionID)
    }

    /// Number of active sessions.
    public var count: Int {
        sessions.count
    }

    /// All active session IDs.
    public var sessionIDs: [UInt16] {
        Array(sessions.keys)
    }

    /// Allocate the next available session ID.
    public func allocateSessionID() -> UInt16 {
        // Skip 0 (reserved for unsecured)
        while nextSessionID == 0 || sessions[nextSessionID] != nil {
            nextSessionID &+= 1
            if nextSessionID == 0 { nextSessionID = 1 }
        }
        let id = nextSessionID
        nextSessionID &+= 1
        if nextSessionID == 0 { nextSessionID = 1 }
        return id
    }

    // MARK: - Counter Deduplication

    /// Check if a received message counter is valid for a session.
    public func acceptCounter(_ counter: UInt32, for sessionID: UInt16) -> Bool {
        guard var d = dedup[sessionID] else { return false }
        let accepted = d.accept(counter)
        dedup[sessionID] = d
        return accepted
    }

    // MARK: - Timeout & Eviction

    /// Remove sessions that have exceeded their timeout.
    public func evictExpired() -> [SecureSession] {
        let now = Date()
        var evicted: [SecureSession] = []

        for (id, session) in sessions {
            let elapsed = now.timeIntervalSince(session.createdAt)
            if elapsed > session.timeout.timeInterval {
                sessions.removeValue(forKey: id)
                dedup.removeValue(forKey: id)
                evicted.append(session)
            }
        }

        return evicted
    }

    /// Evict the oldest session (by creation time).
    private func evictOldest() {
        guard let oldest = sessions.min(by: { $0.value.createdAt < $1.value.createdAt }) else {
            return
        }
        sessions.removeValue(forKey: oldest.key)
        dedup.removeValue(forKey: oldest.key)
    }

    /// Find sessions for a specific peer node.
    public func sessions(for peerNodeID: NodeID) -> [SecureSession] {
        sessions.values.filter { $0.peerNodeID == peerNodeID }
    }

    /// Find sessions for a specific fabric.
    public func sessions(for fabricIndex: FabricIndex) -> [SecureSession] {
        sessions.values.filter { $0.fabricIndex == fabricIndex }
    }
}

// MARK: - Duration Extension

extension Duration {
    /// Convert to TimeInterval (seconds as Double).
    var timeInterval: TimeInterval {
        let (seconds, attoseconds) = components
        return Double(seconds) + Double(attoseconds) / 1e18
    }
}
