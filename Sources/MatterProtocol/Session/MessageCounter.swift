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
        check(counter) == .accepted
    }

    /// Reset deduplication state (e.g., on session re-establishment).
    public mutating func reset() {
        maxCounter = nil
        bitmap = 0
    }
}

extension CounterDeduplication {
    /// Classification of a received message counter (Matter Core §4.6.5).
    public enum Verdict: Sendable, Equatable {
        /// New: process it. Recorded in the window.
        case accepted
        /// Seen before: acknowledge it again if it asked for an ack, never
        /// process it twice.
        case duplicate
        /// Encrypted session only: below the window — acknowledged if it
        /// requested an ack, never processed.
        case outOfWindow
    }

    /// Classify `counter` and record it if accepted.
    public mutating func check(_ counter: UInt32) -> Verdict {
        guard let max = maxCounter else {
            // First message — always accept
            maxCounter = counter
            return .accepted
        }

        if counter == max {
            return .duplicate
        }

        if counter > max {
            // New highest counter — shift the window
            let shift = counter - max
            if shift < Self.windowSize {
                bitmap = (bitmap << shift) | (1 << (shift - 1))
            } else if shift == Self.windowSize {
                // The previous max sits at offset 32, the oldest slot still in the window.
                bitmap = 1 << (Self.windowSize - 1)
            } else {
                bitmap = 0
            }
            maxCounter = counter
            return .accepted
        }

        // counter < max
        let offset = max - counter
        if offset > Self.windowSize {
            if encrypted {
                return .outOfWindow
            }
            // Unencrypted: accept (possible peer reboot) — reset state
            maxCounter = counter
            bitmap = 0
            return .accepted
        }

        let bit: UInt32 = 1 << (offset - 1)
        if bitmap & bit != 0 {
            return .duplicate
        }
        bitmap |= bit
        return .accepted
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
