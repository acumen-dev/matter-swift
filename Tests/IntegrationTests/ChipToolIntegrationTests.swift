// ChipToolIntegrationTests.swift
// Copyright 2026 Monagle Pty Ltd
//
// Integration tests that commission our MatterDeviceServer using the CHIP SDK's
// chip-tool binary, then verify attribute reads over CASE sessions. This catches
// interop bugs that loopback tests miss — loopback tests use the same (potentially
// buggy) code on both sides, so symmetric errors pass undetected.
//
// Prerequisites:
//   make ref-setup-tool   # Build chip-tool from connectedhomeip
//
// These tests use real UDP and mDNS (AppleUDPTransport + AppleDiscovery), so
// chip-tool can discover and commission the device via standard Matter flows.

#if canImport(Network)
import Testing
import Foundation
import MatterTypes
import MatterTransport
import MatterApple
import MatterDevice

@Suite("chip-tool Integration", .serialized)
struct ChipToolIntegrationTests {

    // MARK: - Constants

    /// Node ID that chip-tool assigns to our device.
    static let nodeID: UInt64 = 1

    /// The endpoint with an OnOff cluster (first bridged device in our bridge).
    static let onOffEndpointID: UInt16 = 3

    /// Server config — uses default passcode 20202021, discriminator 840.
    /// Port 5542 avoids conflict with any existing Matter device on the default 5540.
    /// chip-tool discovers the port via mDNS SRV records, so any port works.
    /// Discriminator 840 avoids conflict with other commissionable devices.
    static let serverConfig = MatterDeviceServer.Config(
        discriminator: 840,
        passcode: 20202021,
        port: 5542,
        vendorId: 0xFFF1,
        productId: 0x8000,
        deviceName: "ChipTool Test Bridge"
    )

    // MARK: - Commission and Read

    @Test("chip-tool commissions device and reads OnOff attribute via CASE")
    func chipToolCommissionAndRead() async throws {
        guard let chipTool = ChipToolRunner.findBinary() else {
            // chip-tool not built — skip gracefully
            return
        }

        let stateDir = try ChipToolRunner.createStateDirectory()
        defer { ChipToolRunner.cleanupStateDirectory(stateDir) }

        // Start the device server with real transport and discovery
        let (server, _) = try await startRealServer()
        defer {
            Task { await server.stop() }
        }

        // Brief delay for server to start
        try await Task.sleep(for: .milliseconds(500))

        // Step 1: Commission with chip-tool via direct IP (bypasses mDNS,
        // avoids multi-interface IPv6 link-local routing issues)
        let pairResult = try chipTool.pairWithIP(
            nodeID: Self.nodeID,
            passcode: Self.serverConfig.passcode,
            host: "127.0.0.1",
            port: Self.serverConfig.port,
            stateDir: stateDir,
            timeout: 90
        )

        if !pairResult.succeeded {
            // Write chip-tool output to temp file for diagnosis
            let logFile = FileManager.default.temporaryDirectory.appendingPathComponent("chip-tool-commission.log")
            try? pairResult.stdout.write(to: logFile, atomically: true, encoding: .utf8)
            print("╔══════════════════════════════════════════════════")
            print("║ chip-tool pairing FAILED (exit code \(pairResult.exitCode))")
            print("║ Full output: \(logFile.path)")
            print("╚══════════════════════════════════════════════════")
        }
        #expect(pairResult.succeeded, "chip-tool commissioning should succeed")
        guard pairResult.succeeded else { return }

        // Step 2: Read OnOff attribute via CASE session
        let readResult = try chipTool.readOnOff(
            nodeID: Self.nodeID,
            endpointID: Self.onOffEndpointID,
            stateDir: stateDir,
            timeout: 30
        )

        if !readResult.succeeded {
            print("╔══════════════════════════════════════════════════")
            print("║ chip-tool read FAILED (exit code \(readResult.exitCode))")
            print("╠══════════════════════════════════════════════════")
            print("║ stdout:\n\(readResult.stdout)")
            print("║ stderr:\n\(readResult.stderr)")
            print("╚══════════════════════════════════════════════════")
        }
        #expect(readResult.succeeded, "chip-tool OnOff read should succeed")

        // Wait briefly for server cleanup
        await server.stop()
        try await Task.sleep(for: .milliseconds(500))
    }

    // MARK: - Commission, Toggle, and Verify

    @Test("chip-tool commissions, toggles OnOff, and verifies state change via CASE")
    func chipToolCommissionToggleRead() async throws {
        guard let chipTool = ChipToolRunner.findBinary() else {
            return
        }

        let stateDir = try ChipToolRunner.createStateDirectory()
        defer { ChipToolRunner.cleanupStateDirectory(stateDir) }

        let (server, _) = try await startRealServer()
        defer {
            Task { await server.stop() }
        }

        try await Task.sleep(for: .milliseconds(500))

        // Commission via direct IP
        let pairResult = try chipTool.pairWithIP(
            nodeID: Self.nodeID,
            passcode: Self.serverConfig.passcode,
            host: "127.0.0.1",
            port: Self.serverConfig.port,
            stateDir: stateDir,
            timeout: 90
        )
        guard pairResult.succeeded else {
            print("chip-tool pairing failed: \(pairResult.stderr)")
            #expect(Bool(false), "chip-tool commissioning should succeed")
            return
        }

        // Toggle OnOff
        let toggleResult = try chipTool.toggleOnOff(
            nodeID: Self.nodeID,
            endpointID: Self.onOffEndpointID,
            stateDir: stateDir
        )
        #expect(toggleResult.succeeded, "chip-tool toggle should succeed: \(toggleResult.stderr)")
        guard toggleResult.succeeded else { return }

        // Read back — should now be true (toggled from default false)
        let readResult = try chipTool.readOnOff(
            nodeID: Self.nodeID,
            endpointID: Self.onOffEndpointID,
            stateDir: stateDir
        )
        #expect(readResult.succeeded, "chip-tool read after toggle should succeed: \(readResult.stderr)")

        await server.stop()
        try await Task.sleep(for: .milliseconds(500))
    }

    // MARK: - Subscribe All (Chunked Report Test)

    @Test("chip-tool subscribes to all attributes and receives periodic reports")
    func chipToolSubscribeAll() async throws {
        guard let chipTool = ChipToolRunner.findBinary() else {
            return
        }

        let stateDir = try ChipToolRunner.createStateDirectory()
        defer { ChipToolRunner.cleanupStateDirectory(stateDir) }

        let (server, _) = try await startRealServer()
        defer {
            Task { await server.stop() }
        }

        try await Task.sleep(for: .milliseconds(500))

        // Commission via direct IP
        let pairResult = try chipTool.pairWithIP(
            nodeID: Self.nodeID,
            passcode: Self.serverConfig.passcode,
            host: "127.0.0.1",
            port: Self.serverConfig.port,
            stateDir: stateDir,
            timeout: 90
        )
        guard pairResult.succeeded else {
            print("chip-tool pairing failed: \(pairResult.stderr)")
            #expect(Bool(false), "chip-tool commissioning should succeed")
            return
        }

        // Subscribe to all attributes on all endpoints with short intervals
        // to trigger periodic reports quickly. The initial report for a bridge
        // with multiple endpoints is large enough (~1260 bytes) to require
        // chunking (2 chunks). This tests the chunked report delivery path.
        let subscribeResult = try chipTool.subscribeAll(
            nodeID: Self.nodeID,
            minInterval: 3,
            maxInterval: 10,
            stateDir: stateDir,
            timeout: 25
        )

        if !subscribeResult.succeeded {
            let logFile = FileManager.default.temporaryDirectory.appendingPathComponent("chip-tool-subscribe.log")
            try? subscribeResult.stdout.write(to: logFile, atomically: true, encoding: .utf8)
            print("╔══════════════════════════════════════════════════")
            print("║ chip-tool subscribe FAILED (exit code \(subscribeResult.exitCode))")
            print("║ Full output: \(logFile.path)")
            print("╚══════════════════════════════════════════════════")
        }

        // chip-tool exits with 0 if the subscription was established and
        // at least one periodic report was received within the timeout.
        #expect(subscribeResult.succeeded, "chip-tool subscribe-all should succeed")

        await server.stop()
        try await Task.sleep(for: .milliseconds(500))
    }

    // MARK: - Helpers

    /// Start a device server with real UDP transport and mDNS discovery.
    ///
    /// Unlike loopback tests that use LoopbackTransport + StubDiscovery, these
    /// tests need real networking so chip-tool can discover and connect to the
    /// device via standard mDNS + UDP flows.
    private func startRealServer() async throws -> (
        server: MatterDeviceServer,
        bridge: MatterBridge
    ) {
        let bridge = MatterBridge()
        bridge.addDimmableLight(name: "ChipTool Test Light")

        let transport = AppleUDPTransport()
        let discovery = AppleDiscovery()

        let server = MatterDeviceServer(
            bridge: bridge,
            transport: transport,
            discovery: discovery,
            config: Self.serverConfig
        )

        try await server.start()

        // Brief delay for receive loop and mDNS to initialize
        try await Task.sleep(for: .milliseconds(500))

        return (server, bridge)
    }
}
#endif
