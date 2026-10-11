// SeededJitter.swift
// Copyright 2026 Monagle Pty Ltd

import Synchronization

/// SplitMix64 (Steele, Lea & Flood): small, fast, fully reproducible.
public struct SplitMix64: RandomNumberGenerator, Sendable {
    private var state: UInt64

    public init(seed: UInt64) {
        state = seed
    }

    public mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

/// A reproducible MRP jitter source: pass `{ jitter() }` as `jitterSource`.
public final class SeededJitter: Sendable {
    private let generator: Mutex<SplitMix64>

    public init(seed: UInt64) {
        generator = Mutex(SplitMix64(seed: seed))
    }

    /// The next value in `0..<1`.
    public func callAsFunction() -> Double {
        let bits = generator.withLock { $0.next() }
        return Double(bits >> 11) * 0x1.0p-53
    }
}
