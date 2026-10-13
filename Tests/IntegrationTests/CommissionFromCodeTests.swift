// CommissionFromCodeTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterProtocol
import MatterTransport
@testable import MatterController
import MatterDevice
import MatterTestSupport

/// `commission(setupCode:)` end to end: the device advertises through one
/// `InMemoryDiscovery`, the controller finds it there by discriminator, and
/// both talk over an in-memory link. No network.
@Suite("CommissionFromCode", .serialized, .timeLimit(.minutes(3)))
struct CommissionFromCodeTests {

    /// Passcode 20202021, short discriminator 15 (the fixture device's 3840).
    static let manualCode = "34970112332"

    private static func makeDiscovery(_ link: FaultInjectingLink) -> InMemoryDiscovery {
        InMemoryDiscovery { _ in link.b.address }
    }

    @Test("commissions the device found by discriminator, with the MRP timing from its TXT")
    func commissionsFromManualCode() async throws {
        let link = FaultInjectingLink(seed: 51)
        let discovery = Self.makeDiscovery(link)
        let (server, _) = try await startServer(on: link, toggles: LockedValue(0), discovery: discovery)
        let store = InMemoryControllerStore()
        let controller = try makeController(on: link, maxRetransmissions: 10, discovery: discovery, store: store)

        do {
            let device = try await controller.commission(setupCode: Self.manualCode)

            // The fixture device publishes no SII/SAI/SAT, so this is the defaults.
            var advertised: [String: String]?
            for await record in discovery.browse(serviceType: .commissionable) {
                advertised = record.txtRecords
                break
            }
            let expected = MRPParameters(txtRecords: try #require(advertised))
            #expect(device.mrpParameters == expected)
            #expect(await controller.device(for: device.nodeID)?.mrpParameters == expected)

            let stored = try #require(await store.load())
            let storedDevice = try #require(stored.devices.first { $0.nodeID == device.nodeID.rawValue })
            #expect(DeviceRegistry.mrpParameters(from: storedDevice) == expected)
        } catch {
            await server.stop()
            throw error
        }
        await server.stop()
    }

    @Test("an explicit mrp overrides the advertised timing")
    func explicitMRPOverrides() async throws {
        let link = FaultInjectingLink(seed: 52)
        let discovery = Self.makeDiscovery(link)
        let (server, _) = try await startServer(on: link, toggles: LockedValue(0), discovery: discovery)
        let controller = try makeController(on: link, maxRetransmissions: 10, discovery: discovery)

        let device = try await controller.commission(setupCode: Self.manualCode, mrp: fast)
        #expect(device.mrpParameters == fast)
        await server.stop()
    }

    @Test("a non-matching record is skipped; the right device is commissioned")
    func skipsNonMatching() async throws {
        let link = FaultInjectingLink(seed: 53)
        let discovery = Self.makeDiscovery(link)
        // Advertised first, so the controller meets it before the real device.
        try await discovery.advertise(service: MatterServiceRecord(
            name: "other-1234", serviceType: .commissionable, host: "", port: 5541,
            txtRecords: ["D": "1234", "CM": "1"]))
        let (server, _) = try await startServer(on: link, toggles: LockedValue(0), discovery: discovery)
        let controller = try makeController(on: link, maxRetransmissions: 10, discovery: discovery)

        let device = try await controller.commission(setupCode: Self.manualCode)
        #expect(await controller.allDevices().map(\.nodeID) == [device.nodeID])
        await server.stop()
    }

    @Test("an invalid code throws invalidSetupCode, never echoes the code, and sends nothing")
    func invalidCode() async throws {
        let link = FaultInjectingLink(seed: 54)
        let discovery = Self.makeDiscovery(link)
        let (server, _) = try await startServer(on: link, toggles: LockedValue(0), discovery: discovery)
        let controller = try makeController(on: link, maxRetransmissions: 2, discovery: discovery)

        // Right length, wrong check digit.
        let bad = "34970112333"
        do {
            _ = try await controller.commission(setupCode: bad)
            Issue.record("an invalid code must not commission")
        } catch let ControllerError.invalidSetupCode(message) {
            #expect(!message.contains(bad))
            #expect(!message.contains("20202021"))
            #expect(!message.isEmpty)
        } catch {
            Issue.record("expected invalidSetupCode, got \(error)")
        }
        #expect(link.sent(from: .a).isEmpty)
        #expect(link.sent(from: .b).isEmpty)
        #expect(await controller.allDevices().isEmpty)
        await server.stop()
    }
}
