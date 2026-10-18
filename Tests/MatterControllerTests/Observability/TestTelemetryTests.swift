// TestTelemetryTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Logging
import Metrics
import Tracing
import InMemoryTracing
import MatterTestSupport

@Suite("Test telemetry support", .timeLimit(.minutes(1)))
struct TestTelemetryTests {

    @Test("LogCapture records label, level, message and merged metadata")
    func capturesEntries() throws {
        let telemetry = TestTelemetry()
        var logger = telemetry.logger(label: "test.capture")
        logger[metadataKey: "matter.subsystem"] = "messenger"
        logger.trace("hello", metadata: ["matter.counter": "7"])
        let entry = try #require(telemetry.logs.entries.first)
        #expect(entry.label == "test.capture")
        #expect(entry.level == .trace)
        #expect(entry.message == "hello")
        #expect(entry.metadata == ["matter.subsystem": "messenger", "matter.counter": "7"])
        #expect(entry.subsystem == "messenger")
    }

    @Test("first(where:) waits for a line logged later")
    func waitsForLine() async throws {
        let telemetry = TestTelemetry()
        let logger = telemetry.logger()
        let waiter = Task { try await telemetry.logs.first { $0.message == "later" } }
        logger.info("earlier")
        logger.info("later")
        let line = try await waiter.value
        #expect(line.level == .info)
        #expect(line.message == "later")
    }

    @Test("allRecordedText covers log text, metadata, span attributes and span events")
    func recordedText() {
        let telemetry = TestTelemetry()
        telemetry.logger().debug("line", metadata: ["k": "meta-value"])
        let span = telemetry.tracer.startSpan("op")
        span.attributes["a"] = "attr-value"
        span.addEvent(SpanEvent(name: "evt", attributes: ["e": .string("event-value")]))
        span.end()
        let open = telemetry.tracer.startSpan("still-open")
        open.attributes["b"] = "open-value"
        let text = telemetry.allRecordedText()
        for needle in ["line", "meta-value", "op", "attr-value", "evt", "event-value", "open-value"] {
            #expect(text.contains { $0.contains(needle) }, "missing \(needle)")
        }
        #expect(telemetry.finishedSpans(named: "op").count == 1)
        #expect(telemetry.activeSpans(named: "still-open").count == 1)
    }

    @Test("Counters and timers read back by label and dimensions; a missing one is 0 / empty")
    func metricsReadBack() {
        let telemetry = TestTelemetry()
        #expect(telemetry.counter("nothing") == 0)
        #expect(telemetry.timerValues("nothing").isEmpty)

        let counter = Counter(label: "c", dimensions: [("a", "1"), ("b", "2")], factory: telemetry.metrics)
        counter.increment(by: 3)
        counter.increment()
        let timer = Metrics.Timer(label: "t", dimensions: [("a", "1"), ("b", "2")], factory: telemetry.metrics)
        timer.recordNanoseconds(10)
        timer.recordNanoseconds(20)

        #expect(telemetry.counter("c", [("a", "1"), ("b", "2")]) == 4)
        // Dimensions match as an unordered set.
        #expect(telemetry.counter("c", [("b", "2"), ("a", "1")]) == 4)
        #expect(telemetry.timerValues("t", [("a", "1"), ("b", "2")]) == [10, 20])
        #expect(telemetry.timerValues("t", [("b", "2"), ("a", "1")]) == [10, 20])
        // Different dimensions are a different metric.
        #expect(telemetry.counter("c", [("a", "1")]) == 0)
        #expect(telemetry.timerValues("t").isEmpty)
    }

    @Test("SecretForms renders bytes as lower hex, upper hex, base64 and decimal array")
    func secretForms() {
        #expect(SecretForms.of(Data([0xAB, 0x01])) == ["ab01", "AB01", "qwE=", "[171, 1]"])
        #expect(SecretForms.of(Data()).isEmpty)
    }
}
