// MRPClock.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

/// The clock MRP timers run on. Production uses `ContinuousClock`; tests
/// inject a manual clock so retransmission schedules are asserted exactly.
public protocol MRPClock: Sendable {
    /// The current instant.
    var now: ContinuousClock.Instant { get }

    /// Suspend until `deadline`. Throws `CancellationError` if the calling
    /// task is cancelled first.
    func sleep(until deadline: ContinuousClock.Instant) async throws
}

extension ContinuousClock: MRPClock {
    /// `Clock.sleep(until:tolerance:)` has a defaulted parameter and so does
    /// not witness the requirement on its own.
    public func sleep(until deadline: ContinuousClock.Instant) async throws {
        try await sleep(until: deadline, tolerance: nil)
    }
}
