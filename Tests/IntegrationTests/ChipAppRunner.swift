// ChipAppRunner.swift
// Copyright 2026 Monagle Pty Ltd
//
// Runs connectedhomeip's chip-all-clusters-app as a Matter device on localhost.
// Build it first via:
//   make ref-setup-app
//
// Tests that use this runner skip gracefully when the binary is not available.

#if canImport(Network)
import Foundation

// MARK: - ChipAppRunner

/// A chip-all-clusters-app process acting as a Matter device on localhost.
///
/// `@unchecked Sendable`: this test-target helper wraps `Foundation.Process`
/// (not Sendable). The captured output (`buffer`, `reachedEOF`) is guarded by
/// `lock`. Calls on `process` (isRunning, terminate, processIdentifier) rely on
/// Process's own internal synchronisation and are only made after `run()`.
/// This is the only exception to strict sendability in the plan.
final class ChipAppRunner: @unchecked Sendable {

    // MARK: - Types

    struct StartError: Error, CustomStringConvertible {
        let reason: String
        let log: String
        var description: String { "\(reason)\n--- app log ---\n\(log)" }
    }

    /// Line the app prints once its server is up and listening.
    static let readinessMarker = "Server Listening"

    // MARK: - State

    let port: UInt16
    let kvsPath: URL

    private let process: Process
    private let lock = NSLock()
    private var buffer = Data()
    private var reachedEOF = false

    /// Whether the app process is still alive.
    var isRunning: Bool { process.isRunning }

    deinit {
        if process.isRunning { process.terminate() }
    }

    /// Captured stdout+stderr so far.
    var log: String {
        lock.lock()
        defer { lock.unlock() }
        return String(decoding: buffer, as: UTF8.self)
    }

    // MARK: - Locating

    static func findBinary(sourceFile: String = #filePath) -> URL? {
        let root = URL(fileURLWithPath: sourceFile)
            .deletingLastPathComponent()  // IntegrationTests/
            .deletingLastPathComponent()  // Tests/
            .deletingLastPathComponent()  // package root
        let url = root.appendingPathComponent("Tools/RefImpl/bin/chip-all-clusters-app")
        return FileManager.default.isExecutableFile(atPath: url.path) ? url : nil
    }

    // MARK: - Init

    private init(process: Process, port: UInt16, kvsPath: URL) {
        self.process = process
        self.port = port
        self.kvsPath = kvsPath
    }

    // MARK: - Start

    /// Start with a fresh (or given) KVS file. Returns once the app logs that it is ready.
    static func start(
        discriminator: UInt16 = 3840,
        passcode: UInt32 = 20202021,
        port: UInt16,
        kvsPath: URL,
        timeout: Duration = .seconds(30)
    ) async throws -> ChipAppRunner {
        guard let binary = findBinary() else {
            throw StartError(reason: "chip-all-clusters-app not built (make ref-setup-app)", log: "")
        }
        let process = Process()
        process.executableURL = binary
        process.arguments = [
            "--discriminator", String(discriminator),
            "--passcode", String(passcode),
            "--secured-device-port", String(port),
            "--KVS", kvsPath.path,
        ]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        let runner = ChipAppRunner(process: process, port: port, kvsPath: kvsPath)
        pipe.fileHandleForReading.readabilityHandler = { [weak runner] handle in
            let data = handle.availableData
            if data.isEmpty {
                handle.readabilityHandler = nil
                runner?.markEOF()
                return
            }
            runner?.append(data)
        }
        try process.run()

        // Any throw out of the readiness wait (timeout, early exit, cancellation)
        // must not leave the app running.
        do {
            let deadline = ContinuousClock.now.advanced(by: timeout)
            while !runner.log.contains(readinessMarker) {
                if !process.isRunning {
                    await runner.drainAfterExit()
                    throw StartError(reason: "chip-all-clusters-app exited before becoming ready", log: runner.log)
                }
                if ContinuousClock.now >= deadline {
                    await runner.stop()
                    throw StartError(reason: "timed out waiting for readiness", log: runner.log)
                }
                try await Task.sleep(for: .milliseconds(20))
            }
        } catch {
            await runner.stop()
            throw error
        }
        return runner
    }

    // MARK: - Stop

    /// SIGTERM, wait for exit (SIGKILL after 5 s), then drain the output.
    func stop() async {
        if process.isRunning {
            process.terminate()
            if !(await waitForExit(seconds: 5)) {
                kill(process.processIdentifier, SIGKILL)
                _ = await waitForExit(seconds: 2)
            }
        }
        await drainAfterExit()
    }

    // MARK: - Private

    /// Polls for exit without being interrupted by task cancellation.
    private func waitForExit(seconds: Int) async -> Bool {
        await Task.detached { [process] in
            let deadline = ContinuousClock.now.advanced(by: .seconds(seconds))
            while process.isRunning && ContinuousClock.now < deadline {
                try? await Task.sleep(for: .milliseconds(20))
            }
            return !process.isRunning
        }.value
    }

    /// Waits (bounded) for the pipe to reach EOF so `log` has the final lines.
    private func drainAfterExit() async {
        await Task.detached { [self] in
            let deadline = ContinuousClock.now.advanced(by: .seconds(1))
            while !eof && ContinuousClock.now < deadline {
                try? await Task.sleep(for: .milliseconds(10))
            }
        }.value
    }

    private var eof: Bool {
        lock.lock()
        defer { lock.unlock() }
        return reachedEOF
    }

    private func markEOF() {
        lock.lock()
        reachedEOF = true
        lock.unlock()
    }

    private func append(_ data: Data) {
        lock.lock()
        buffer.append(data)
        lock.unlock()
    }
}
#endif
