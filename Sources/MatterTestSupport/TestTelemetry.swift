// TestTelemetry.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Logging
import MetricsTestKit
import Tracing
import InMemoryTracing

/// Logs, metrics and spans for one test: injected, never bootstrapped (a process bootstraps
/// `LoggingSystem`, `MetricsSystem` and `InstrumentationSystem` at most once).
public struct TestTelemetry: Sendable {
    public let logs = LogCapture()
    public let metrics = TestMetrics()
    public let tracer = InMemoryTracer()

    public init() {}

    public func logger(label: String = "test.matter") -> Logger {
        logs.logger(label: label)
    }

    /// Total of counter `label` with exactly `dimensions` (any order); 0 if it was never created.
    public func counter(_ label: String, _ dimensions: [(String, String)] = []) -> Int64 {
        let wanted = Self.normalised(dimensions)
        return metrics.counters
            .filter { $0.label == label && Self.normalised($0.dimensions) == wanted }
            .reduce(0) { $0 + $1.totalValue }
    }

    /// Values (nanoseconds) recorded by timer `label` with `dimensions` (any order); empty if never created.
    public func timerValues(_ label: String, _ dimensions: [(String, String)] = []) -> [Int64] {
        let wanted = Self.normalised(dimensions)
        return metrics.timers
            .filter { $0.label == label && Self.normalised($0.dimensions) == wanted }
            .flatMap { $0.values }
    }

    /// Dimensions as a sorted list, so two orderings of the same set compare equal.
    private static func normalised(_ dimensions: [(String, String)]) -> [String] {
        dimensions.map { "\($0.0)\u{0}\($0.1)" }.sorted()
    }

    public func finishedSpans(named name: String) -> [FinishedInMemorySpan] {
        tracer.finishedSpans.filter { $0.operationName == name }
    }

    public func activeSpans(named name: String) -> [InMemorySpan] {
        tracer.activeSpans.filter { $0.operationName == name }
    }

    /// Every recorded log message and metadata value, and every span name, attribute value,
    /// event name, event attribute value, status message and recorded error, as text.
    public func allRecordedText() -> [String] {
        var text: [String] = []
        for entry in logs.entries {
            text.append(entry.message)
            text.append(contentsOf: entry.metadata.values)
        }
        func add(_ attributes: SpanAttributes) {
            attributes.forEach { _, value in text.append(Self.render(value)) }
        }
        func addSpan(
            _ name: String,
            _ attributes: SpanAttributes,
            _ events: [SpanEvent],
            _ status: SpanStatus?,
            _ errors: [InMemorySpan.RecordedError]
        ) {
            text.append(name)
            add(attributes)
            for event in events { text.append(event.name); add(event.attributes) }
            if let message = status?.message { text.append(message) }
            for error in errors { text.append(String(describing: error.error)) }
        }
        for span in tracer.finishedSpans {
            addSpan(span.operationName, span.attributes, span.events, span.status, span.errors)
        }
        for span in tracer.activeSpans {
            addSpan(span.operationName, span.attributes, span.events, span.status, span.errors)
        }
        return text
    }

    public static func render(_ attribute: SpanAttribute) -> String {
        switch attribute {
        case .string(let value): return value
        case .int64(let value): return String(value)
        case .stringArray(let values): return values.joined(separator: ",")
        default: return String(describing: attribute)
        }
    }
}

/// The forms a secret could take in a log line or span.
public enum SecretForms {
    /// `bytes` as lower-case hex, upper-case hex and base64.
    public static func of(_ bytes: Data) -> [String] {
        let lower = bytes.map { String(format: "%02x", $0) }.joined()
        return [lower, lower.uppercased(), bytes.base64EncodedString()]
    }
}
