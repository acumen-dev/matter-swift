// LockedValue.swift
// Copyright 2026 Monagle Pty Ltd

import Synchronization

/// A `Mutex`-protected value that escaping `@Sendable` closures can share
/// (a `Mutex` itself cannot be captured: it is non-copyable).
///
/// A test can also wait for the value to reach a state, with
/// ``wait(until:)``: the waiter is woken by the ``withLock(_:)`` call that
/// gets it there, so a wait has no deadline and no polling interval. The
/// test's `.timeLimit` is its hang guard.
public final class LockedValue<Value: Sendable>: Sendable {

    private struct Waiter: Sendable {
        let id: UInt64
        let predicate: @Sendable (Value) -> Bool
        let continuation: CheckedContinuation<Void, any Error>
    }

    private struct Storage: Sendable {
        var value: Value
        var nextWaiterID: UInt64 = 0
        var waiters: [Waiter] = []
        /// Waiters cancelled before they registered.
        var cancelled: Set<UInt64> = []
    }

    private enum Registration {
        case waiting, satisfied, cancelled
    }

    private let storage: Mutex<Storage>

    public init(_ value: Value) {
        storage = Mutex(Storage(value: value))
    }

    /// A copy of the current value.
    public var value: Value {
        storage.withLock { $0.value }
    }

    /// How many ``wait(until:)`` calls are suspended, waiting for an update.
    /// For tests of a waiting primitive: it shows a waiter has looked at the
    /// value and found its predicate false.
    public var waiterCount: Int {
        storage.withLock { $0.waiters.count }
    }

    @discardableResult
    public func withLock<Result: Sendable>(_ body: (inout Value) -> Result) -> Result {
        let (result, satisfied) = storage.withLock { storage -> (Result, [CheckedContinuation<Void, any Error>]) in
            let result = body(&storage.value)
            guard !storage.waiters.isEmpty else { return (result, []) }
            var satisfied: [CheckedContinuation<Void, any Error>] = []
            let value = storage.value
            storage.waiters.removeAll { waiter in
                guard waiter.predicate(value) else { return false }
                satisfied.append(waiter.continuation)
                return true
            }
            return (result, satisfied)
        }
        for continuation in satisfied {
            continuation.resume()
        }
        return result
    }

    /// Suspend until `predicate` holds for the value — at once if it already
    /// does. Throws `CancellationError` if the calling task is cancelled
    /// first (as `.timeLimit` does).
    public func wait(until predicate: @escaping @Sendable (Value) -> Bool) async throws {
        let id: UInt64 = storage.withLock { storage in
            storage.nextWaiterID += 1
            return storage.nextWaiterID
        }
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                let registration: Registration = storage.withLock { storage in
                    if storage.cancelled.remove(id) != nil { return .cancelled }
                    if predicate(storage.value) { return .satisfied }
                    storage.waiters.append(Waiter(id: id, predicate: predicate, continuation: continuation))
                    return .waiting
                }
                switch registration {
                case .waiting: break
                case .satisfied: continuation.resume()
                case .cancelled: continuation.resume(throwing: CancellationError())
                }
            }
        } onCancel: {
            let waiter: Waiter? = storage.withLock { storage in
                if let index = storage.waiters.firstIndex(where: { $0.id == id }) {
                    return storage.waiters.remove(at: index)
                }
                storage.cancelled.insert(id)
                return nil
            }
            waiter?.continuation.resume(throwing: CancellationError())
        }
    }
}
