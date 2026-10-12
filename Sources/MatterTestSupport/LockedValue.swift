// LockedValue.swift
// Copyright 2026 Monagle Pty Ltd

import Synchronization

/// A `Mutex`-protected value that escaping `@Sendable` closures can share
/// (a `Mutex` itself cannot be captured: it is non-copyable).
public final class LockedValue<Value: Sendable>: Sendable {
    private let storage: Mutex<Value>

    public init(_ value: Value) {
        storage = Mutex(value)
    }

    /// A copy of the current value.
    public var value: Value {
        storage.withLock { $0 }
    }

    @discardableResult
    public func withLock<Result: Sendable>(_ body: (inout Value) -> Result) -> Result {
        storage.withLock { body(&$0) }
    }
}
