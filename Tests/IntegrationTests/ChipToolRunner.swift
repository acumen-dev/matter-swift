// ChipToolRunner.swift
// Copyright 2026 Monagle Pty Ltd
//
// Wrapper for invoking the chip-tool reference implementation binary.
// chip-tool is part of the connectedhomeip SDK and must be built first via:
//   make ref-setup-tool
//
// Tests that use this runner skip gracefully when chip-tool is not available.

#if canImport(Network)
import Foundation

// MARK: - ChipToolRunner

/// Invokes the chip-tool binary from the connectedhomeip reference implementation.
///
/// Finds the binary relative to the package root using `#filePath`. Tests that
/// call this runner should call `findBinary()` first and skip if nil.
struct ChipToolRunner: Sendable {

    // MARK: - Properties

    /// Absolute path to the chip-tool binary.
    let binaryPath: String

    // MARK: - Init

    /// Create a runner pointing at the chip-tool binary.
    ///
    /// Returns `nil` if the binary does not exist. Tests should skip when this
    /// returns `nil` to avoid failures on machines that haven't run `setup.sh`.
    static func findBinary(sourceFile: String = #filePath) -> ChipToolRunner? {
        let url = URL(fileURLWithPath: sourceFile)
            .deletingLastPathComponent()  // IntegrationTests/
            .deletingLastPathComponent()  // Tests/
            .deletingLastPathComponent()  // package root
        let binaryURL = url
            .appendingPathComponent("Tools/RefImpl/bin/chip-tool")
        let path = binaryURL.path
        guard FileManager.default.isExecutableFile(atPath: path) else {
            return nil
        }
        return ChipToolRunner(binaryPath: path)
    }

    // MARK: - Result

    struct RunResult: Sendable {
        let exitCode: Int32
        let stdout: String
        let stderr: String

        var succeeded: Bool { exitCode == 0 }
    }

    // MARK: - Run

    /// Run chip-tool with the given arguments and an optional timeout.
    ///
    /// If the process does not complete within `timeout` seconds, it is terminated
    /// and the result will have a non-zero exit code.
    func run(_ arguments: [String], timeout: TimeInterval = 30) throws -> RunResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: binaryPath)
        process.arguments = arguments

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        // Timeout watchdog
        let timeoutItem = DispatchWorkItem { [process] in
            if process.isRunning {
                process.terminate()
            }
        }
        DispatchQueue.global().asyncAfter(
            deadline: .now() + timeout,
            execute: timeoutItem
        )

        try process.run()
        process.waitUntilExit()
        timeoutItem.cancel()

        let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()

        return RunResult(
            exitCode: process.terminationStatus,
            stdout: String(data: stdoutData, encoding: .utf8) ?? "",
            stderr: String(data: stderrData, encoding: .utf8) ?? ""
        )
    }

    // MARK: - Commissioning

    /// Commission a device using a setup code (manual pairing code or QR payload).
    ///
    /// Runs: `chip-tool pairing code <nodeID> <setupPayload> --storage-directory <dir>`
    func pairWithCode(
        nodeID: UInt64,
        setupPayload: String,
        stateDir: URL,
        timeout: TimeInterval = 60
    ) throws -> RunResult {
        try run([
            "pairing", "code",
            "\(nodeID)", setupPayload,
            "--storage-directory", stateDir.path,
        ], timeout: timeout)
    }

    /// Unpair / remove fabric from a commissioned device.
    ///
    /// Runs: `chip-tool pairing unpair <nodeID> --storage-directory <dir>`
    func unpair(
        nodeID: UInt64,
        stateDir: URL,
        timeout: TimeInterval = 30
    ) throws -> RunResult {
        try run([
            "pairing", "unpair",
            "\(nodeID)",
            "--storage-directory", stateDir.path,
        ], timeout: timeout)
    }

    // MARK: - Attribute Reads

    /// Read the OnOff attribute from a commissioned device.
    ///
    /// Runs: `chip-tool onoff read on-off <nodeID> <endpointID> --storage-directory <dir>`
    func readOnOff(
        nodeID: UInt64,
        endpointID: UInt16,
        stateDir: URL,
        timeout: TimeInterval = 30
    ) throws -> RunResult {
        try run([
            "onoff", "read", "on-off",
            "\(nodeID)", "\(endpointID)",
            "--storage-directory", stateDir.path,
        ], timeout: timeout)
    }

    // MARK: - Command Invocation

    /// Invoke the OnOff toggle command on a commissioned device.
    ///
    /// Runs: `chip-tool onoff toggle <nodeID> <endpointID> --storage-directory <dir>`
    func toggleOnOff(
        nodeID: UInt64,
        endpointID: UInt16,
        stateDir: URL,
        timeout: TimeInterval = 30
    ) throws -> RunResult {
        try run([
            "onoff", "toggle",
            "\(nodeID)", "\(endpointID)",
            "--storage-directory", stateDir.path,
        ], timeout: timeout)
    }

    // MARK: - Temp State Directory

    /// Create a fresh temporary directory for chip-tool state.
    ///
    /// chip-tool stores fabric credentials and session state in this directory.
    /// Each test run should use a fresh directory to avoid stale state.
    static func createStateDirectory() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("chip-tool-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: dir,
            withIntermediateDirectories: true
        )
        return dir
    }

    /// Remove a chip-tool state directory.
    static func cleanupStateDirectory(_ dir: URL) {
        try? FileManager.default.removeItem(at: dir)
    }
}
#endif
