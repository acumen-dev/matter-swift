// SecureSession.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import MatterTypes

/// A Matter secure session — established via PASE or CASE.
///
/// Sessions carry encryption keys, message counters, and peer identity.
/// They are stored in a `SessionTable` and referenced by session ID.
public final class SecureSession: Sendable {
    /// Unique local session identifier (non-zero for secure sessions).
    public let localSessionID: UInt16

    /// Peer's session identifier.
    public let peerSessionID: UInt16

    /// How this session was established.
    public let establishment: SessionEstablishment

    /// Peer node ID (assigned during commissioning for CASE sessions).
    public let peerNodeID: NodeID

    /// Fabric index this session belongs to (nil for PASE sessions).
    public let fabricIndex: FabricIndex?

    /// Session creation timestamp.
    public let createdAt: Date

    /// Session timeout interval.
    public let timeout: Duration

    /// Whether this is a session resumption (CASE only).
    public let isResumption: Bool

    /// Encryption key for messages this node sends (I2R for initiator, R2I for responder).
    public let encryptKey: SymmetricKey?

    /// Decryption key for messages this node receives (R2I for initiator, I2R for responder).
    public let decryptKey: SymmetricKey?

    /// Attestation challenge key (used during commissioning attestation).
    public let attestationKey: SymmetricKey?

    // Counter state is mutable — managed by the session table/engine
    private let _sendCounter: ManagedAtomic<UInt32>
    private let _maxReceivedCounter: ManagedAtomic<UInt32>

    public init(
        localSessionID: UInt16,
        peerSessionID: UInt16,
        establishment: SessionEstablishment,
        peerNodeID: NodeID,
        fabricIndex: FabricIndex? = nil,
        timeout: Duration = .seconds(3600),
        isResumption: Bool = false,
        initialSendCounter: UInt32? = nil,
        encryptKey: SymmetricKey? = nil,
        decryptKey: SymmetricKey? = nil,
        attestationKey: SymmetricKey? = nil
    ) {
        self.localSessionID = localSessionID
        self.peerSessionID = peerSessionID
        self.establishment = establishment
        self.peerNodeID = peerNodeID
        self.fabricIndex = fabricIndex
        self.createdAt = Date()
        self.timeout = timeout
        self.isResumption = isResumption
        self.encryptKey = encryptKey
        self.decryptKey = decryptKey
        self.attestationKey = attestationKey

        // Initialize counter with random 28-bit value per spec
        let initial = initialSendCounter ?? (UInt32.random(in: 0...UInt32.max) & MessageCounter.randomInitMask)
        self._sendCounter = ManagedAtomic(initial)
        self._maxReceivedCounter = ManagedAtomic(0)
    }

    /// Get the next send counter value (pre-increment).
    public func nextSendCounter() -> UInt32 {
        _sendCounter.wrappingIncrement(ordering: .relaxed)
    }

    /// The current send counter value (for testing/inspection).
    public var currentSendCounter: UInt32 {
        _sendCounter.load(ordering: .relaxed)
    }
}

// MARK: - Session Establishment

/// How a session was established.
public enum SessionEstablishment: Sendable, Equatable {
    /// PASE (Passcode-Authenticated Session Establishment) — commissioning.
    case pase
    /// CASE (Certificate Authenticated Session Establishment) — operational.
    case `case`
}

// MARK: - Managed Atomic

/// Simple atomic wrapper for session counters.
///
/// Uses `OSAtomicIncrement32` on Darwin. A full atomic library would be
/// better for production, but this avoids adding a dependency for now.
final class ManagedAtomic<Value: FixedWidthInteger & Sendable>: @unchecked Sendable {
    private var _value: Value
    private let lock = NSLock()

    init(_ value: Value) {
        self._value = value
    }

    func load(ordering: MemoryOrdering = .relaxed) -> Value {
        lock.lock()
        defer { lock.unlock() }
        return _value
    }

    @discardableResult
    func wrappingIncrement(ordering: MemoryOrdering = .relaxed) -> Value {
        lock.lock()
        defer { lock.unlock() }
        let old = _value
        _value &+= 1
        return old &+ 1
    }

    func store(_ value: Value, ordering: MemoryOrdering = .relaxed) {
        lock.lock()
        defer { lock.unlock() }
        _value = value
    }

    enum MemoryOrdering {
        case relaxed
    }
}
