// LogCapture.swift
// Copyright 2026 Monagle Pty Ltd

import Logging

/// One log call, as a ``CapturingLogHandler`` saw it.
public struct CapturedLog: Sendable, Equatable {
    public let label: String
    public let level: Logger.Level
    public let message: String
    /// The logger's metadata merged with the call's (the call's wins), rendered as text.
    public let metadata: [String: String]

    /// The `matter.subsystem` metadata value, if any.
    public var subsystem: String? { metadata["matter.subsystem"] }
}

/// Collects every line written through the loggers it makes. Thread-safe: actors log
/// from any executor.
public final class LogCapture: Sendable {
    private let store = LockedValue<[CapturedLog]>([])

    public init() {}

    /// Everything captured so far, in call order.
    public var entries: [CapturedLog] { store.value }

    /// A logger labelled `label` whose lines land here, at `level` (default trace).
    public func logger(label: String, level: Logger.Level = .trace) -> Logger {
        var logger = Logger(label: label) { CapturingLogHandler(label: $0, capture: self) }
        logger.logLevel = level
        return logger
    }

    /// Captured lines satisfying `predicate`.
    public func entries(where predicate: (CapturedLog) -> Bool) -> [CapturedLog] {
        entries.filter(predicate)
    }

    /// Suspends until a line satisfying `predicate` is captured, then returns the first such
    /// line. No deadline: the test's `.timeLimit` is the hang guard.
    public func first(where predicate: @escaping @Sendable (CapturedLog) -> Bool) async throws -> CapturedLog {
        try await store.wait { $0.contains(where: predicate) }
        // The store only grows (reset aside), so the line that satisfied the wait is still there.
        return store.value.first(where: predicate)!
    }

    public func reset() {
        store.withLock { $0.removeAll() }
    }

    func append(_ entry: CapturedLog) {
        store.withLock { $0.append(entry) }
    }
}

/// A `LogHandler` that records into a ``LogCapture``.
public struct CapturingLogHandler: LogHandler {
    public let label: String
    private let capture: LogCapture
    public var logLevel: Logger.Level = .trace
    public var metadata: Logger.Metadata = [:]

    public init(label: String, capture: LogCapture) {
        self.label = label
        self.capture = capture
    }

    public subscript(metadataKey key: String) -> Logger.Metadata.Value? {
        get { metadata[key] }
        set { metadata[key] = newValue }
    }

    public func log(
        level: Logger.Level,
        message: Logger.Message,
        metadata: Logger.Metadata?,
        source: String,
        file: String,
        function: String,
        line: UInt
    ) {
        var merged = self.metadata
        if let metadata { merged.merge(metadata) { _, call in call } }
        capture.append(CapturedLog(
            label: label,
            level: level,
            message: message.description,
            metadata: merged.mapValues { $0.description }
        ))
    }
}
