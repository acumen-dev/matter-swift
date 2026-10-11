// CommissioningWindowTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
@testable import MatterDevice
import MatterTypes
import MatterTransport

/// The commissioning window can be opened on demand, and the commissionable
/// advertisement exists only while it is open — a controller browsing for
/// `_matterc._udp` never finds a device that will not accept PASE.
@Suite("Commissioning window", .timeLimit(.minutes(1)))
struct CommissioningWindowTests {

    private let instanceName = "Test Bridge-3840"

    private func makeServer() -> (MatterDeviceServer, MockServerDiscovery) {
        let discovery = MockServerDiscovery()
        let server = MatterDeviceServer(
            bridge: MatterBridge(),
            transport: MockServerUDPTransport(),
            discovery: discovery,
            config: .init(discriminator: 3840, passcode: 20202021, port: 5540, deviceName: "Test Bridge")
        )
        return (server, discovery)
    }

    /// The most recent commissionable record for the instance, or nil when it
    /// is not currently advertised.
    private func commissionable(_ discovery: MockServerDiscovery) async -> MatterServiceRecord? {
        await discovery.services(ofType: .commissionable).last { $0.name == instanceName }
    }

    /// Outcome wait: polls until `condition` holds, failing after `timeout`.
    private func waitUntil(
        timeout: Duration = .seconds(10),
        _ condition: () async -> Bool
    ) async throws {
        let deadline = ContinuousClock.now + timeout
        while !(await condition()) {
            guard ContinuousClock.now < deadline else {
                Issue.record("condition not met within \(timeout)")
                return
            }
            try await Task.sleep(for: .milliseconds(20))
        }
    }

    @Test("A fresh device opens its window and advertises CM=1 with discriminator subtypes")
    func freshDeviceAdvertisesOpenWindow() async throws {
        let (server, discovery) = makeServer()
        try await server.start()
        try await waitUntil { await commissionable(discovery) != nil }

        let record = try #require(await commissionable(discovery))
        #expect(record.txtRecords["CM"] == "1")
        #expect(Set(record.subtypes) == ["_CM", "_L3840", "_S15"])
        let window = await server.commissioningWindow
        #expect(window.isOpen)
        #expect(window.expiresAt != nil)

        await server.stop()
    }

    @Test("Closing the window withdraws the commissionable advertisement")
    func closingWithdrawsAdvertisement() async throws {
        let (server, discovery) = makeServer()
        try await server.start()
        try await waitUntil { await commissionable(discovery) != nil }

        await server.closeCommissioningWindow()
        try await waitUntil { await commissionable(discovery) == nil }

        #expect(await commissionable(discovery) == nil)
        let window = await server.commissioningWindow
        #expect(!window.isOpen)
        #expect(window.expiresAt == nil)

        await server.stop()
    }

    @Test("Opening the window on demand re-advertises with CM=1")
    func openingOnDemandReadvertises() async throws {
        let (server, discovery) = makeServer()
        try await server.start()
        try await waitUntil { await commissionable(discovery) != nil }
        await server.closeCommissioningWindow()
        try await waitUntil { await commissionable(discovery) == nil }

        let before = Date()
        await server.openCommissioningWindow(timeout: 900)
        try await waitUntil { await commissionable(discovery) != nil }

        let record = try #require(await commissionable(discovery))
        #expect(record.txtRecords["CM"] == "1")
        #expect(record.subtypes.contains("_L3840"))
        let window = await server.commissioningWindow
        #expect(window.isOpen)
        let expiry = try #require(window.expiresAt)
        #expect(expiry >= before.addingTimeInterval(899))
        #expect(expiry <= Date().addingTimeInterval(901))

        await server.stop()
    }

    @Test("Window timeout is clamped to the spec range 180–900 s")
    func timeoutIsClamped() async throws {
        let (server, _) = makeServer()
        try await server.start()

        await server.openCommissioningWindow(timeout: 10)
        let short = try #require(await server.commissioningWindow.expiresAt)
        #expect(short.timeIntervalSinceNow > 170)
        #expect(short.timeIntervalSinceNow <= 180)

        await server.openCommissioningWindow(timeout: 5000)
        let long = try #require(await server.commissioningWindow.expiresAt)
        #expect(long.timeIntervalSinceNow > 890)
        #expect(long.timeIntervalSinceNow <= 900)

        await server.stop()
    }
}
