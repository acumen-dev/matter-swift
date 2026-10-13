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
///
/// Limitation of the count heuristic: it detects "back to the earlier count",
/// not "re-armed once". A woken task that re-arms twice, or that registers a
/// different sleeper while another one ends, can satisfy or miss the count
/// early. A woken sleeper that never re-arms leaves the count short; ``advance(by:)``
/// then gives up after `quiescenceYieldLimit` yields, still moves on, and
/// increments ``quiescenceTimeouts`` so a test can assert it stayed 0.
public final class ManualClock: MRPClock, Sendable {

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

    /// One lock for everything, sleepers included: ``awaitSleepers(atLeast:)``
    /// and ``awaitSleeper(until:)`` wait on it directly, so what they see is
    /// what ``advance(by:)`` sees.
    private let state: LockedValue<State>
    private let timeouts = Mutex(0)

    /// Bound on the scheduler yields spent waiting for sleepers to re-register.
    /// The default is large enough to outlast an OS preemption of the woken
    /// task on a loaded 2-core runner, so it never acts as a timing margin for
    /// a correct test: a correct test never reaches it, and it only costs time
    /// (a fraction of a second) on a path that is already failing. Tests that
    /// deliberately leave a sleeper un-re-armed pass a small limit. Reaching
    /// it is counted in ``quiescenceTimeouts``.
    public let quiescenceYieldLimit: Int

    public init(origin: ContinuousClock.Instant = .now, quiescenceYieldLimit: Int = 100_000) {
        precondition(quiescenceYieldLimit >= 0, "quiescenceYieldLimit must not be negative")
        state = LockedValue(State(now: origin))
        self.quiescenceYieldLimit = quiescenceYieldLimit
    }

    /// How many waits for sleepers gave up at the yield bound. Tests assert 0.
    public var quiescenceTimeouts: Int {
        timeouts.withLock { $0 }
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

    /// Returns once at least `count` sleepers are registered — at once if
    /// they already are. Woken by the registration itself, so it has no
    /// bound of its own: the test's `.timeLimit` is the hang guard. Throws
    /// `CancellationError` if the calling task is cancelled first.
    public func awaitSleepers(atLeast count: Int) async throws {
        try await state.wait { $0.sleepers.count >= count }
    }

    /// How many ``awaitSleepers(atLeast:)`` / ``awaitSleeper(until:)`` calls
    /// are suspended. For tests of the clock itself.
    public var sleeperWaiterCount: Int {
        state.waiterCount
    }

    /// Returns once a sleeper waits for exactly `deadline` (unbounded, as
    /// ``awaitSleepers(atLeast:)``).
    public func awaitSleeper(until deadline: ContinuousClock.Instant) async throws {
        try await state.wait { $0.sleepers.values.contains { $0.deadline == deadline } }
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
                    if target > state.now {
                        state.now = target
                    }
                    return nil
                }
                if earliest > state.now {
                    state.now = earliest
                }
                let countBefore = state.sleepers.count
                let dueSleepers = state.sleepers.filter { $0.value.deadline <= earliest }.map(\.key).sorted()
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
    }

    /// Yield until at least `count` sleepers are registered (bounded by
    /// `quiescenceYieldLimit`, and by cancellation of the caller).
    /// - Returns: whether the count was reached. Hitting the yield bound
    ///   increments ``quiescenceTimeouts``; returning `false` because the
    ///   caller was cancelled does not.
    @discardableResult
    public func waitForSleepers(_ count: Int) async -> Bool {
        for _ in 0..<quiescenceYieldLimit {
            if sleeperCount >= count { return true }
            if Task.isCancelled { return false }
            await Task.yield()
        }
        if sleeperCount >= count { return true }
        timeouts.withLock { $0 += 1 }
        return false
    }

    /// Yield until a sleeper waits for exactly `deadline` (bounded as in
    /// ``waitForSleepers(_:)``).
    /// - Returns: whether one did. Hitting the yield bound increments
    ///   ``quiescenceTimeouts``; a cancelled caller returns `false` without counting.
    public func waitForSleeper(until deadline: ContinuousClock.Instant) async -> Bool {
        func isWaiting() -> Bool {
            state.withLock { state in
                state.sleepers.values.contains { $0.deadline == deadline }
            }
        }
        for _ in 0..<quiescenceYieldLimit {
            if isWaiting() { return true }
            if Task.isCancelled { return false }
            await Task.yield()
        }
        if isWaiting() { return true }
        timeouts.withLock { $0 += 1 }
        return false
    }
}
