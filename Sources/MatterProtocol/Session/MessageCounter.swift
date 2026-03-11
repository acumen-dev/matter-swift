// MessageCounter.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

/// Message counter management and deduplication.
///
/// Per the Matter spec, session counters are initialized to a random 28-bit value
/// and pre-incremented before use. Counters are 32-bit and do NOT wrap — when
/// exhausted, a new session must be established.
public enum MessageCounter {
    /// Mask for random counter initialization (28-bit range).
    public static let randomInitMask: UInt32 = 0x0FFF_FFFF

    /// Maximum valid counter value.
    public static let maxValue: UInt32 = 0xFFFF_FFFF

    /// Generate a random initial counter value within the 28-bit range.
    public static func randomInitialValue() -> UInt32 {
        UInt32.random(in: 0...UInt32.max) & randomInitMask
    }
}

// MARK: - Counter Deduplication

/// Sliding-window deduplication for received message counters.
///
/// Maintains a 32-entry bitmap tracking recently received counters.
/// Rejects duplicates and out-of-window counters for encrypted sessions.
public struct CounterDeduplication: Sendable {
    /// Size of the sliding window.
    public static let windowSize: UInt32 = 32

    /// The highest valid counter received.
    private var maxCounter: UInt32?

    /// Bitmap tracking the most recent `windowSize` counters below maxCounter.
    private var bitmap: UInt32 = 0

    /// Whether this is for an encrypted session (stricter rules).
    private let encrypted: Bool

    public init(encrypted: Bool = true) {
        self.encrypted = encrypted
    }

    /// Check if a counter value is valid (not a duplicate, within window).
    ///
    /// Returns `true` if the counter should be accepted, `false` if it's
    /// a duplicate or out of the valid window.
    public mutating func accept(_ counter: UInt32) -> Bool {
        guard let max = maxCounter else {
            // First message — always accept
            maxCounter = counter
            return true
        }

        if counter == max {
            // Exact duplicate of the highest counter
            return false
        }

        if counter > max {
            // New highest counter — shift the window
            let shift = counter - max
            if shift < Self.windowSize {
                // Mark the old max position in the bitmap
                bitmap = (bitmap << shift) | (1 << (shift - 1))
            } else {
                // Window completely shifted past — reset bitmap
                bitmap = 0
            }
            maxCounter = counter
            return true
        }

        // counter < max
        let offset = max - counter
        if offset > Self.windowSize {
            // Below the window
            if encrypted {
                return false // Encrypted: reject out-of-window
            } else {
                // Unencrypted: accept (possible device reboot) — reset state
                maxCounter = counter
                bitmap = 0
                return true
            }
        }

        // Within the window — check bitmap
        let bit: UInt32 = 1 << (offset - 1)
        if bitmap & bit != 0 {
            return false // Already received this counter
        }

        // Mark as received
        bitmap |= bit
        return true
    }

    /// Reset deduplication state (e.g., on session re-establishment).
    public mutating func reset() {
        maxCounter = nil
        bitmap = 0
    }
}

// MARK: - Global Message Counter

/// A global monotonic message counter for unsecured sessions.
///
/// Unlike session counters (random init, per-session), the global counter
/// starts at 0 and increments across all unsecured messages.
public final class GlobalMessageCounter: @unchecked Sendable {
    private let counter: ManagedAtomic<UInt32>

    public init(initialValue: UInt32 = 0) {
        self.counter = ManagedAtomic(initialValue)
    }

    /// Get the next counter value.
    public func next() -> UInt32 {
        counter.wrappingIncrement()
    }

    /// The current counter value.
    public var current: UInt32 {
        counter.load()
    }
}
