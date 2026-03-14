// TimedRequestTracker.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

/// Result of consuming a timed interaction window.
public enum TimedWindowResult: Sendable, Equatable {
    /// A valid, non-expired timed window was present and consumed.
    case valid
    /// No timed window was recorded for this exchange.
    case noTimedWindow
    /// A timed window was recorded but has since expired.
    case expired
}

/// Tracks outstanding timed interaction windows per exchange.
///
/// A timed interaction begins with a `TimedRequest` message that specifies a
/// timeout (in milliseconds). A subsequent `WriteRequest` or `InvokeRequest`
/// with `timedRequest = true` must arrive within that window, or the request
/// is rejected with `TimedRequestMismatch`.
///
/// ```swift
/// let tracker = TimedRequestTracker()
///
/// // On receiving a TimedRequest message:
/// await tracker.recordTimedRequest(exchangeID: 42, timeoutMs: 500)
///
/// // On receiving the timed Write/Invoke:
/// let result = await tracker.consumeTimedWindow(exchangeID: 42)
/// // result == .valid (if within the window)
/// // result == .expired (if the window has passed)
/// // result == .noTimedWindow (if no prior TimedRequest)
/// ```
public actor TimedRequestTracker {

    // MARK: - State

    private var windows: [UInt16: Date] = [:]

    // MARK: - Init

    public init() {}

    // MARK: - API

    /// Record a timed interaction window for the given exchange.
    ///
    /// Stores a deadline of `now + timeoutMs` milliseconds for `exchangeID`.
    /// Overwrites any existing entry for the same exchange.
    public func recordTimedRequest(exchangeID: UInt16, timeoutMs: UInt16) {
        let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000.0)
        windows[exchangeID] = deadline
    }

    /// Consume and return the status of the timed window for the given exchange.
    ///
    /// Removes the entry regardless of outcome, so each timed window is consumed
    /// at most once.
    public func consumeTimedWindow(exchangeID: UInt16) -> TimedWindowResult {
        guard let deadline = windows.removeValue(forKey: exchangeID) else {
            return .noTimedWindow
        }
        return Date() <= deadline ? .valid : .expired
    }

    /// Remove all entries whose deadlines have already passed.
    ///
    /// Call periodically (e.g., in the subscription report tick) to prevent
    /// unbounded growth of the window table.
    public func purgeExpired() {
        let now = Date()
        windows = windows.filter { $0.value > now }
    }
}
