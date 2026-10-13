// ChipAppRunnerTests.swift
// Copyright 2026 Monagle Pty Ltd
//
// Verifies the chip-all-clusters-app runner starts, reports readiness and stops.
// Skips silently when the binary has not been built (make ref-setup-app).

#if canImport(Network)
import Foundation
import Testing

// MARK: - Free port helper

/// Picks a port for the CHIP app's `--secured-device-port`: a free UDP
/// port that is also free for TCP, on IPv4 and IPv6 wildcards. The app binds
/// UDP *and* TCP on that port, on both families, and fails to start if any
/// is taken; an ephemeral UDP port alone can collide with some process's TCP
/// connection (measured: "Failed to initialize TCP transport: Address
/// already in use", readiness never logged). Returns 0 if none is found.
func freeUDPPort() -> UInt16 {
    for _ in 0..<64 {
        guard let port = boundPort(family: AF_INET, type: SOCK_DGRAM, port: 0) else { return 0 }
        if isFreeForChipApp(port) { return port }
    }
    return 0
}

/// Whether `port` can be bound for UDP and TCP on the IPv4 and IPv6 wildcards.
func isFreeForChipApp(_ port: UInt16) -> Bool {
    [(AF_INET, SOCK_DGRAM), (AF_INET, SOCK_STREAM), (AF_INET6, SOCK_DGRAM), (AF_INET6, SOCK_STREAM)]
        .allSatisfy { boundPort(family: $0.0, type: $0.1, port: port) != nil }
}

/// Bind a socket of `family`/`type` to the wildcard address and `port` (0:
/// any), read the bound port back and close it. Nil if the bind fails.
private func boundPort(family: Int32, type: Int32, port: UInt16) -> UInt16? {
    let fd = socket(family, type, 0)
    guard fd >= 0 else { return nil }
    defer { close(fd) }
    if family == AF_INET6 {
        var v6only: Int32 = 1   // the IPv4 bind is checked separately
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in6()
        addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        addr.sin6_family = sa_family_t(AF_INET6)
        addr.sin6_port = port.bigEndian
        addr.sin6_addr = in6addr_any
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        }
        guard bound == 0 else { return nil }
        var out = sockaddr_in6()
        var len = socklen_t(MemoryLayout<sockaddr_in6>.size)
        let got = withUnsafeMutablePointer(to: &out) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }
        return got == 0 ? UInt16(bigEndian: out.sin6_port) : nil
    }
    var addr = sockaddr_in()
    addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = port.bigEndian
    addr.sin_addr.s_addr = INADDR_ANY
    let bound = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    guard bound == 0 else { return nil }
    var out = sockaddr_in()
    var len = socklen_t(MemoryLayout<sockaddr_in>.size)
    let got = withUnsafeMutablePointer(to: &out) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
    }
    return got == 0 ? UInt16(bigEndian: out.sin_port) : nil
}

// MARK: - ChipAppRunnerTests

@Suite("ChipAppRunner", .serialized)
struct ChipAppRunnerTests {

    @Test("The CHIP app starts, logs readiness, and stops", .timeLimit(.minutes(2)))
    func startStop() async throws {
        guard ChipAppRunner.findBinary() != nil else { return }   // skip when not built
        let kvs = FileManager.default.temporaryDirectory.appendingPathComponent("chip-kvs-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: kvs) }
        let port = freeUDPPort()
        try #require(port != 0, "a free port for the app")
        let app = try await ChipAppRunner.start(port: port, kvsPath: kvs)
        #expect(app.log.contains("Server Listening") || app.log.contains("Server initialization complete"))
        #expect(app.manualPairingCode?.count == 11, "manual pairing code parsed from the log")
        #expect(app.qrCode?.hasPrefix("MT:") == true, "QR payload parsed from the log")
        await app.stop()
        #expect(!app.isRunning)
    }

    @Test("A port from freeUDPPort is free for both UDP and TCP")
    func freePortIsFreeForTCP() throws {
        // A TCP listener on a port makes it unusable for the app.
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        try #require(fd >= 0)
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = INADDR_ANY
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        try #require(bound == 0 && listen(fd, 1) == 0)
        var out = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &out) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }
        let held = UInt16(bigEndian: out.sin_port)
        #expect(!isFreeForChipApp(held), "a port held for TCP is not free for the app")
        let port = freeUDPPort()
        try #require(port != 0, "a free port for the app")
        #expect(isFreeForChipApp(port))
    }

    @Test("Onboarding codes are parsed from the app's colourised log lines")
    func parsesOnboardingCodes() {
        // Shape of v1.4.0.0's lines; the codes are this test's own.
        let log = """
            \u{1B}[0;32m[1.520] [1:2] [SVR] SetupQRCode: [MT:-24J0AFN00KA0648G00]\u{1B}[0m
            \u{1B}[0;32m[1.520] [1:2] [SVR] Manual pairing code: [34970112332]\u{1B}[0m
            """
        #expect(ChipAppRunner.bracketed(after: ChipAppRunner.qrCodeMarker, in: log) == "MT:-24J0AFN00KA0648G00")
        #expect(ChipAppRunner.bracketed(after: ChipAppRunner.manualCodeMarker, in: log) == "34970112332")
        #expect(ChipAppRunner.bracketed(after: ChipAppRunner.manualCodeMarker, in: "Server Listening...") == nil)
        #expect(ChipAppRunner.bracketed(after: ChipAppRunner.manualCodeMarker, in: "Manual pairing code: [") == nil)
    }

    @Test("Cancelling start does not leave the app running", .timeLimit(.minutes(2)))
    func cancelledStartTerminatesApp() async throws {
        guard ChipAppRunner.findBinary() != nil else { return }
        let kvs = FileManager.default.temporaryDirectory.appendingPathComponent("chip-kvs-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: kvs) }
        let port = freeUDPPort()
        try #require(port != 0, "a free port for the app")
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
        // Anchored so port 5540 does not match 55401.
        leaked.arguments = ["-f", "secured-device-port \(port)( |$)"]
        leaked.standardOutput = Pipe()
        try leaked.run()
        leaked.waitUntilExit()
        // pgrep: 0 = a match, 1 = no match, anything else = pgrep itself failed.
        #expect(leaked.terminationStatus != 0, "app on port \(port) is still running")
        #expect(leaked.terminationStatus <= 1, "pgrep failed with status \(leaked.terminationStatus)")
    }
}
#endif
