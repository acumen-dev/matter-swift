// PollUntil.swift
// Copyright 2026 Monagle Pty Ltd

/// Re-checks `condition` every `interval` until it holds.
///
/// For an outcome with no event to wait on (a value in a store, state behind
/// an actor). There is deliberately no deadline: a deadline here would be a
/// wall-clock margin that decides the test on a loaded host. The test's
/// `.timeLimit` is the hang guard; its cancellation ends the wait with
/// `CancellationError`.
public func pollUntil(
    every interval: Duration = .milliseconds(20),
    _ condition: () async throws -> Bool
) async throws {
    while try await !condition() {
        try await Task.sleep(for: interval)
    }
}
