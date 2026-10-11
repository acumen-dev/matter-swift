// ManualClock.swift
// Copyright 2026 Monagle Pty Ltd

import Synchronization
import MatterProtocol

/// An `MRPClock` that moves only when a test calls ``advance(by:)``.
///
/// ``advance(by:)`` walks deadline by deadline. After resuming the sleepers
/// due at a step it waits until as many sleepers are registered as before
/// the step: a timer that goes back to sleep once per wake (the controller
/// messenger's does) has then finished the work its wake triggered. Delayed
/// link deliveries use ``schedule(at:_:)`` and are not sleepers.
public final class ManualClock: MRPClock, Sendable {

    /// Bound on the scheduler yields spent waiting for sleepers to re-register.
    /// Reaching it means a woken task did not go back to sleep: a fail-fast
    /// fallback, not a timing margin.
    public static let quiescenceYieldLimit = 1_000_000

    private struct Sleeper: Sendable {
        let deadline: ContinuousClock.Instant
        let continuation: CheckedContinuation<Void, any Error>
    }

    private struct Scheduled: Sendable {
        let deadline: ContinuousClock.Instant
        let action: @Sendable () -> Void
    }

    private struct State: Sendable {
        var now: ContinuousClock.Instant
        var nextID: UInt64 = 0
        var sleepers: [UInt64: Sleeper] = [:]
        var cancelledBeforeRegistration: Set<UInt64> = []
        var scheduled: [UInt64: Scheduled] = [:]
    }

    private struct Step: Sendable {
        let sleepers: [Sleeper]
        let actions: [@Sendable () -> Void]
        let sleeperCountBefore: Int
    }

    private enum Registration {
        case waiting, resumeNow, cancelled
    }

    private let state: Mutex<State>

    public init(origin: ContinuousClock.Instant = .now) {
        state = Mutex(State(now: origin))
    }

    public var now: ContinuousClock.Instant {
        state.withLock { $0.now }
    }

    /// Tasks currently suspended in ``sleep(until:)``.
    public var sleeperCount: Int {
        state.withLock { $0.sleepers.count }
    }

    /// The earliest deadline a sleeper is waiting for.
    public var nextSleeperDeadline: ContinuousClock.Instant? {
        state.withLock { $0.sleepers.values.map(\.deadline).min() }
    }

    public func sleep(until deadline: ContinuousClock.Instant) async throws {
        let id: UInt64 = state.withLock { state in
            state.nextID += 1
            return state.nextID
        }
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                let registration: Registration = state.withLock { state in
                    if state.cancelledBeforeRegistration.remove(id) != nil {
                        return .cancelled
                    }
                    if deadline <= state.now {
                        return .resumeNow
                    }
                    state.sleepers[id] = Sleeper(deadline: deadline, continuation: continuation)
                    return .waiting
                }
                switch registration {
                case .waiting:
                    break
                case .resumeNow:
                    continuation.resume()
                case .cancelled:
                    continuation.resume(throwing: CancellationError())
                }
            }
        } onCancel: {
            let sleeper: Sleeper? = state.withLock { state in
                if let sleeper = state.sleepers.removeValue(forKey: id) {
                    return sleeper
                }
                state.cancelledBeforeRegistration.insert(id)
                return nil
            }
            sleeper?.continuation.resume(throwing: CancellationError())
        }
    }

    /// Run `action` when ``advance(by:)`` reaches `deadline` — immediately if
    /// it already has.
    public func schedule(at deadline: ContinuousClock.Instant, _ action: @escaping @Sendable () -> Void) {
        let runNow: Bool = state.withLock { state in
            if deadline <= state.now {
                return true
            }
            state.nextID += 1
            state.scheduled[state.nextID] = Scheduled(deadline: deadline, action: action)
            return false
        }
        if runNow {
            action()
        }
    }

    /// Move time forward by `duration`, stopping at every sleeper or
    /// scheduled deadline on the way (see the type documentation).
    public func advance(by duration: Duration) async {
        let target = now + duration
        while true {
            let step: Step? = state.withLock { state in
                let deadlines = state.sleepers.values.map(\.deadline) + state.scheduled.values.map(\.deadline)
                guard let earliest = deadlines.min(), earliest <= target else {
                    return nil
                }
                if earliest > state.now {
                    state.now = earliest
                }
                let countBefore = state.sleepers.count
                let dueSleepers = state.sleepers.filter { $0.value.deadline <= earliest }.map(\.key)
                let dueActions = state.scheduled.filter { $0.value.deadline <= earliest }.map(\.key).sorted()
                return Step(
                    sleepers: dueSleepers.compactMap { state.sleepers.removeValue(forKey: $0) },
                    actions: dueActions.compactMap { state.scheduled.removeValue(forKey: $0)?.action },
                    sleeperCountBefore: countBefore
                )
            }
            guard let step else { break }
            for action in step.actions {
                action()
            }
            for sleeper in step.sleepers {
                sleeper.continuation.resume()
            }
            await waitForSleepers(step.sleeperCountBefore)
        }
        state.withLock { state in
            if target > state.now {
                state.now = target
            }
        }
    }

    /// Yield until at least `count` sleepers are registered (bounded).
    public func waitForSleepers(_ count: Int) async {
        for _ in 0..<Self.quiescenceYieldLimit {
            if sleeperCount >= count { return }
            await Task.yield()
        }
    }

    /// Yield until a sleeper waits for exactly `deadline` (bounded).
    /// - Returns: whether one did.
    public func waitForSleeper(until deadline: ContinuousClock.Instant) async -> Bool {
        for _ in 0..<Self.quiescenceYieldLimit {
            let found = state.withLock { state in
                state.sleepers.values.contains { $0.deadline == deadline }
            }
            if found { return true }
            await Task.yield()
        }
        return false
    }
}
