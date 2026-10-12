// ChipAppRunnerTests.swift
// Copyright 2026 Monagle Pty Ltd
//
// Verifies the chip-all-clusters-app runner starts, reports readiness and stops.
// Skips silently when the binary has not been built (make ref-setup-app).

#if canImport(Network)
import Foundation
import Testing

// MARK: - Free port helper

/// Picks a free UDP port on 127.0.0.1 (bind to port 0, read it back, close).
func freeUDPPort() -> UInt16 {
    let fd = socket(AF_INET, SOCK_DGRAM, 0)
    guard fd >= 0 else { return 0 }
    defer { close(fd) }
    var addr = sockaddr_in()
    addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = 0
    addr.sin_addr.s_addr = inet_addr("127.0.0.1")
    let bound = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    guard bound == 0 else { return 0 }
    var out = sockaddr_in()
    var len = socklen_t(MemoryLayout<sockaddr_in>.size)
    let got = withUnsafeMutablePointer(to: &out) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
    }
    guard got == 0 else { return 0 }
    return UInt16(bigEndian: out.sin_port)
}

// MARK: - ChipAppRunnerTests

@Suite("ChipAppRunner", .serialized)
struct ChipAppRunnerTests {

    @Test("The CHIP app starts, logs readiness, and stops", .timeLimit(.minutes(2)))
    func startStop() async throws {
        guard ChipAppRunner.findBinary() != nil else { return }   // skip when not built
        let kvs = FileManager.default.temporaryDirectory.appendingPathComponent("chip-kvs-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: kvs) }
        let app = try await ChipAppRunner.start(port: freeUDPPort(), kvsPath: kvs)
        #expect(app.log.contains("Server Listening") || app.log.contains("Server initialization complete"))
        await app.stop()
        #expect(!app.isRunning)
    }

    @Test("Cancelling start does not leave the app running", .timeLimit(.minutes(2)))
    func cancelledStartTerminatesApp() async throws {
        guard ChipAppRunner.findBinary() != nil else { return }
        let kvs = FileManager.default.temporaryDirectory.appendingPathComponent("chip-kvs-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: kvs) }
        let port = freeUDPPort()
        let task = Task { try await ChipAppRunner.start(port: port, kvsPath: kvs) }
        task.cancel()
        do {
            let app = try await task.value
            await app.stop()   // won the race and started; still clean up
        } catch {
            // expected: cancelled; the runner must have terminated the app itself
        }
        let leaked = Process()
        leaked.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        leaked.arguments = ["-f", "secured-device-port \(port)"]
        leaked.standardOutput = Pipe()
        try leaked.run()
        leaked.waitUntilExit()
        #expect(leaked.terminationStatus != 0, "app on port \(port) is still running")
    }
}
#endif
