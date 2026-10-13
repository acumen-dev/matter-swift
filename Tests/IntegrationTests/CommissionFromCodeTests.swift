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

    /// The device's own commissionable record, as it advertised it. The
    /// server advertises from an unawaited task, so the record may not be
    /// registered yet; the browse is live and yields it when it is. The
    /// guard only bounds a hang — it is not a timing margin.
    private static func advertisedRecord(_ discovery: InMemoryDiscovery) async throws -> MatterServiceRecord {
        try await withThrowingTaskGroup(of: MatterServiceRecord.self) { group in
            group.addTask {
                for await record in discovery.browse(serviceType: .commissionable) { return record }
                throw CancellationError()
            }
            group.addTask {
                try await Task.sleep(for: .seconds(10))
                throw HangGuard()
            }
            defer { group.cancelAll() }
            return try await group.next()!
        }
    }

    struct HangGuard: Error {}

    private static func storedMRP(_ store: InMemoryControllerStore, _ device: CommissionedDevice) async throws -> MRPParameters? {
        let stored = try #require(await store.load())
        let entry = try #require(stored.devices.first { $0.nodeID == device.nodeID.rawValue })
        return DeviceRegistry.mrpParameters(from: entry)
    }

    @Test("commissions the device found by discriminator, with the MRP timing from its TXT")
    func commissionsFromManualCode() async throws {
        let link = FaultInjectingLink(seed: 51)
        let discovery = Self.makeDiscovery(link)
        let (server, _) = try await startServer(on: link, toggles: LockedValue(0), discovery: discovery)
        let store = InMemoryControllerStore()
        let controller = try makeController(on: link, maxRetransmissions: 10, discovery: discovery, store: store)

        do {
            // Re-advertise the device's own instance with an SII, so the
            // expected timing differs from the defaults.
            let original = try await Self.advertisedRecord(discovery)
            var txt = original.txtRecords
            txt["SII"] = "5000"
            try await discovery.advertise(service: MatterServiceRecord(
                name: original.name, serviceType: original.serviceType, host: original.host,
                port: original.port, txtRecords: txt, subtypes: original.subtypes))
            let advertised = try await Self.advertisedRecord(discovery).txtRecords
            let expected = MRPParameters(txtRecords: advertised)
            try #require(expected != MRPParameters.default)

            let device = try await controller.commission(setupCode: Self.manualCode)

            #expect(device.mrpParameters == expected)
            #expect(await controller.device(for: device.nodeID)?.mrpParameters == expected)
            #expect(try await Self.storedMRP(store, device) == expected)
        } catch {
            await controller.stop()
            await server.stop()
            throw error
        }
        await controller.stop()
        await server.stop()
    }

    @Test("an explicit mrp overrides the advertised timing")
    func explicitMRPOverrides() async throws {
        let link = FaultInjectingLink(seed: 52)
        let discovery = Self.makeDiscovery(link)
        let (server, _) = try await startServer(on: link, toggles: LockedValue(0), discovery: discovery)
        let store = InMemoryControllerStore()
        let controller = try makeController(on: link, maxRetransmissions: 10, discovery: discovery, store: store)

        do {
            let device = try await controller.commission(setupCode: Self.manualCode, mrp: fast)
            #expect(device.mrpParameters == fast)
            #expect(await controller.device(for: device.nodeID)?.mrpParameters == fast)
            #expect(try await Self.storedMRP(store, device) == fast)
        } catch {
            await controller.stop()
            await server.stop()
            throw error
        }
        await controller.stop()
        await server.stop()
    }

    @Test("a non-matching record is skipped without being resolved; the right device is commissioned")
    func skipsNonMatching() async throws {
        let link = FaultInjectingLink(seed: 53)
        let discovery = Self.makeDiscovery(link)
        // Advertised first, so the controller meets it before the real device.
        // Every record maps to the real device's address, so only the resolve
        // count shows that the decoy was filtered rather than tried.
        try await discovery.advertise(service: MatterServiceRecord(
            name: "other-1234", serviceType: .commissionable, host: "", port: 5541,
            txtRecords: ["D": "1234", "CM": "1"]))
        let (server, _) = try await startServer(on: link, toggles: LockedValue(0), discovery: discovery)
        let controller = try makeController(on: link, maxRetransmissions: 10, discovery: discovery)

        do {
            let device = try await controller.commission(setupCode: Self.manualCode)
            #expect(await controller.allDevices().map(\.nodeID) == [device.nodeID])
            #expect(discovery.resolveCount(name: "other-1234") == 0)
        } catch {
            await controller.stop()
            await server.stop()
            throw error
        }
        await controller.stop()
        await server.stop()
    }

    @Test("an invalid code throws invalidSetupCode, never echoes the code, and sends nothing",
          arguments: ["34970112333", "MT:SHORT", "MT:!!!!"])
    func invalidCode(bad: String) async throws {
        let link = FaultInjectingLink(seed: 54)
        let discovery = Self.makeDiscovery(link)
        let (server, _) = try await startServer(on: link, toggles: LockedValue(0), discovery: discovery)
        let controller = try makeController(on: link, maxRetransmissions: 2, discovery: discovery)

        do {
            _ = try await controller.commission(setupCode: bad)
            Issue.record("an invalid code must not commission")
        } catch let ControllerError.invalidSetupCode(message) {
            #expect(!message.contains(bad))
            #expect(!message.contains(String(bad.dropFirst(3))))
            #expect(!message.contains("20202021"))
            #expect(!message.isEmpty)
        } catch {
            Issue.record("expected invalidSetupCode, got \(error)")
        }
        #expect(link.sent(from: .a).isEmpty)
        #expect(link.sent(from: .b).isEmpty)
        #expect(await controller.allDevices().isEmpty)
        await controller.stop()
        await server.stop()
    }
}
