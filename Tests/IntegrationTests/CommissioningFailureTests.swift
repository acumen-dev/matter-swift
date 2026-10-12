// CommissioningFailureTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterProtocol
import MatterTransport
@testable import MatterController
import MatterDevice
import MatterTestSupport

/// A commissioning that fails after the fail-safe was armed must disarm it on
/// the device at once (not leave it armed for its 60 s), and must not consume
/// a node ID. Controller ↔ MatterDeviceServer over an in-memory link.
@Suite("Commissioning failure disarms the fail-safe", .serialized, .timeLimit(.minutes(3)))
struct CommissioningFailureTests {

    struct InjectedFailure: Error {}

    @Test("A failure after ArmFailSafe / CSR / AddNOC / the ACL write disarms the device, commits no fabric, and frees the node ID",
          arguments: [CommissioningStep.afterArmFailSafe, .afterCSR, .afterAddNOC, .afterACLWrite])
    fileprivate func failureDisarms(step: CommissioningStep) async throws {
        let link = FaultInjectingLink(seed: 21)
        let bridge = MatterBridge()
        _ = bridge.addDimmableLight(name: "Failing Light", onOffChanged: { _ in })
        let discovery = RecordingDiscovery()
        let server = Self.makeServer(bridge: bridge, link: link, discovery: discovery)
        try await server.start()
        let controller = try makeController(on: link, maxRetransmissions: 10)

        do {
            let expectedNodeID = await controller.nextNodeID
            await controller.setCommissioningFailureInjection { reached in
                if reached == step { throw InjectedFailure() }
            }
            do {
                _ = try await controller.commission(address: link.b.address, setupCode: passcode, mrp: fast)
                Issue.record("commission should have thrown at \(step)")
            } catch {
                #expect(error is InjectedFailure, "the original error must be rethrown unchanged, got \(error)")
            }

            let state = bridge.commissioningState
            let disarmed = await Self.poll { !state.isFailSafeArmed }
            #expect(disarmed, "the device's fail-safe must be disarmed without waiting for its expiry")
            #expect(state.fabrics.isEmpty)
            #expect(state.stagedNOC == nil, "the staged NOC must be reverted")
            #expect(state.stagedRCAC == nil, "the staged root certificate must be reverted")
            // Every operational advert the device staged was withdrawn.
            let withdrawn = await Self.poll { discovery.unwithdrawnOperationalNames().isEmpty }
            #expect(withdrawn, "staged operational advertisements must be withdrawn")
            if step == .afterAddNOC || step == .afterACLWrite {
                #expect(!discovery.operationalNamesAdvertised().isEmpty)
            }
            #expect(await controller.nextNodeID == expectedNodeID, "a failed commissioning must not consume a node ID")

            // A retry succeeds and gets the node ID the failed attempt did not use.
            await controller.setCommissioningFailureInjection(nil)
            await server.openCommissioningWindow(timeout: 180)
            let device = try await controller.commission(address: link.b.address, setupCode: passcode, mrp: fast)
            #expect(device.nodeID.rawValue == expectedNodeID)
        } catch {
            await controller.stop()
            await server.stop()
            throw error
        }
        await controller.stop()
        await server.stop()
    }

    @Test("An ArmFailSafe whose response is lost still gets a best-effort disarm")
    func lostArmResponseIsDisarmed() async throws {
        let link = FaultInjectingLink(seed: 22)
        let bridge = MatterBridge()
        _ = bridge.addDimmableLight(name: "Failing Light", onOffChanged: { _ in })
        let server = Self.makeServer(bridge: bridge, link: link, discovery: RecordingDiscovery())
        try await server.start()
        let controller = try makeController(on: link, maxRetransmissions: 3)
        let state = bridge.commissioningState
        Self.dropDeviceReplies(on: link) { state.isFailSafeArmed }

        do {
            do {
                _ = try await controller.commission(address: link.b.address, setupCode: passcode, mrp: fast)
                Issue.record("commission should have thrown")
            } catch {}
            let disarmed = await Self.poll { !state.isFailSafeArmed }
            #expect(disarmed, "the device must be disarmed without waiting for its expiry")
            #expect(state.fabrics.isEmpty)
        } catch {
            await controller.stop()
            await server.stop()
            throw error
        }
        await controller.stop()
        await server.stop()
    }

    @Test("A CommissioningComplete whose response is lost keeps its node ID (the device may have committed)")
    func lostCompleteKeepsNodeID() async throws {
        let link = FaultInjectingLink(seed: 23)
        let bridge = MatterBridge()
        _ = bridge.addDimmableLight(name: "Failing Light", onOffChanged: { _ in })
        let server = Self.makeServer(bridge: bridge, link: link, discovery: RecordingDiscovery())
        try await server.start()
        let controller = try makeController(on: link, maxRetransmissions: 3)
        let state = bridge.commissioningState
        Self.dropDeviceReplies(on: link) { !state.fabrics.isEmpty }

        do {
            let expectedNodeID = await controller.nextNodeID
            do {
                _ = try await controller.commission(address: link.b.address, setupCode: passcode, mrp: fast)
                Issue.record("commission should have thrown")
            } catch {}
            #expect(!state.fabrics.isEmpty, "the device committed")
            #expect(await controller.nextNodeID == expectedNodeID + 1, "the committed node ID must not be reused")
        } catch {
            await controller.stop()
            await server.stop()
            throw error
        }
        await controller.stop()
        await server.stop()
    }

    private static func makeServer(
        bridge: MatterBridge, link: FaultInjectingLink, discovery: some MatterDiscovery
    ) -> MatterDeviceServer {
        MatterDeviceServer(
            bridge: bridge,
            transport: link.b,
            discovery: discovery,
            config: .init(
                discriminator: 3840, passcode: passcode, port: 5540,
                salt: Data(repeating: 0xAB, count: 32), iterations: 1000
            )
        )
    }

    /// Drop everything the device sends from the first moment `trigger` holds
    /// until the controller sends something it has not sent before (its next
    /// request; retransmissions repeat their message counter). Outcome-driven,
    /// no timing.
    private static func dropDeviceReplies(on link: FaultInjectingLink, trigger: @escaping @Sendable () -> Bool) {
        struct State { var dropping = false; var finished = false; var seen: Set<UInt32> = [] }
        let state = LockedValue(State())
        link.setInterceptor { data, side in
            guard let counter = try? MessageHeader.decode(from: data).header.messageCounter else { return .deliver(after: .zero) }
            return state.withLock { st in
                switch side {
                case .a:
                    if st.dropping, !st.finished, !st.seen.contains(counter) { st.finished = true }
                    st.seen.insert(counter)
                    return .deliver(after: .zero)
                case .b:
                    if !st.dropping, !st.finished, trigger() { st.dropping = true }
                    return st.dropping && !st.finished ? .drop : .deliver(after: .zero)
                }
            }
        }
    }

    /// Poll `condition` until it holds. The 30 s deadline is a hang guard, not
    /// a timing margin: the outcome is what is asserted.
    static func poll(_ condition: @Sendable () async -> Bool) async -> Bool {
        let deadline = ContinuousClock.now + .seconds(30)
        while ContinuousClock.now < deadline, !Task.isCancelled {
            if await condition() { return true }
            try? await Task.sleep(for: .milliseconds(10))
        }
        return false
    }
}

/// Records operational (`_matter._tcp`) adverts and which names were withdrawn.
private final class RecordingDiscovery: MatterDiscovery, Sendable {
    private struct Log {
        var advertised: [String] = []
        var withdrawn: Set<String> = []
        var stoppedAll = false
    }
    private let log = LockedValue(Log())

    func advertise(service: ServiceRecord) async throws {
        guard service.serviceType == .operational else { return }
        log.withLock { $0.advertised.append(service.name); $0.withdrawn.remove(service.name) }
    }
    func browse(serviceType: ServiceType) -> AsyncStream<ServiceRecord> { AsyncStream { $0.finish() } }
    func resolve(_ record: ServiceRecord) async throws -> NetworkAddress {
        throw FaultyLinkDiscoveryError.notAvailable
    }
    func stopAdvertising() async { log.withLock { $0.stoppedAll = true } }
    func stopAdvertising(name: String) async { log.withLock { _ = $0.withdrawn.insert(name) } }

    func operationalNamesAdvertised() -> [String] { log.value.advertised }
    func unwithdrawnOperationalNames() -> [String] {
        let l = log.value
        return l.advertised.filter { !l.withdrawn.contains($0) }
    }
}
