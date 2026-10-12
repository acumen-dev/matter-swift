// ChipAppRunnerTests.swift
// Copyright 2026 Monagle Pty Ltd
//
// Verifies the chip-all-clusters-app runner starts, reports readiness and stops.
// Skips silently when the binary has not been built (make ref-setup-app).

#if canImport(Network)
import Foundation
import Testing

// MARK: - ChipAppRunnerTests

@Suite("ChipAppRunner", .serialized)
struct ChipAppRunnerTests {

    @Test("The CHIP app starts, logs readiness, and stops", .timeLimit(.minutes(2)))
    func startStop() async throws {
        guard ChipAppRunner.findBinary() != nil else { return }   // skip when not built
        let kvs = FileManager.default.temporaryDirectory.appendingPathComponent("chip-kvs-\(UUID().uuidString)")
        let app = try await ChipAppRunner.start(port: 5641, kvsPath: kvs)
        #expect(app.log.contains("Server Listening") || app.log.contains("Server initialization complete"))
        await app.stop()
        try? FileManager.default.removeItem(at: kvs)
    }
}
#endif
