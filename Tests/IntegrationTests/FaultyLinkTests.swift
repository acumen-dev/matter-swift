// FaultyLinkTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterModel
import MatterProtocol
import MatterTransport
import MatterController
import MatterDevice
import MatterTestSupport

/// Controller ↔ MatterDeviceServer over an in-memory link with injected loss,
/// on real clocks. Assertions are outcomes only (no timing).
@Suite("Controller over a faulty link", .serialized, .timeLimit(.minutes(3)))
struct FaultyLinkTests {

    static let passcode: UInt32 = 20202021

    /// Short intervals keep lossy runs quick (values are illustrative, not
    /// spec). With 4 retransmissions a silent peer exhausts after ≈ 3.5–4.3 s,
    /// comfortably above a debug build's handshake processing time, even
    /// under linux/amd64 emulation.
    static let fast = MRPParameters(
        sessionIdleInterval: .milliseconds(200),
        sessionActiveInterval: .milliseconds(200),
        sessionActiveThreshold: .milliseconds(4000)
    )

    @Test("Commission, read and toggle over a 20 % lossy link; the toggle executes exactly once")
    func lossyLink() async throws {
        let link = FaultInjectingLink(seed: 0x5EED)
        let toggles = LockedValue(0)
        let (server, light) = try await startServer(on: link, toggles: toggles)
        // 10 retransmissions: with 20 % loss each way, exhausting one exchange
        // needs 11 consecutive failed round trips (≈ 1e-5), so the outcome is
        // reliable whatever the interleaving.
        let controller = try makeController(on: link, maxRetransmissions: 10)
        link.setDropProbability(0.2, from: .a)
        link.setDropProbability(0.2, from: .b)

        do {
            let device = try await controller.commission(address: link.b.address, setupCode: Self.passcode, mrp: Self.fast)
            #expect(device.mrpParameters == Self.fast)

            // PASE ran with an ephemeral initiator node ID as Source, and the
            // device server answered it as Destination.
            let firstSent = try MessageHeader.decode(from: link.sent(from: .a)[0]).header
            let firstReply = try MessageHeader.decode(from: link.sent(from: .b)[0]).header
            #expect(firstSent.isUnsecured)
            #expect(firstSent.sourceNodeID != nil)
            #expect(firstReply.destinationNodeID == firstSent.sourceNodeID)

            let before = try await controller.readAttribute(
                nodeID: device.nodeID, endpointID: light.endpointID,
                clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff
            )
            #expect(before.boolValue == false)

            _ = try await controller.invokeCommand(
                nodeID: device.nodeID, endpointID: light.endpointID,
                clusterID: .onOff, commandID: OnOffCluster.Command.toggle
            )

            let after = try await controller.readAttribute(
                nodeID: device.nodeID, endpointID: light.endpointID,
                clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff
            )
            #expect(after.boolValue == true)
            #expect(toggles.value == 1, "a retransmitted invoke must be de-duplicated, not executed again")
        } catch {
            await controller.stop()
            await server.stop()
            throw error
        }
        await controller.stop()
        await server.stop()
    }

    @Test("A silent peer surfaces peerUnreachable; the next call re-establishes CASE and never re-sends the invoke")
    func silentPeer() async throws {
        let link = FaultInjectingLink(seed: 7)
        let toggles = LockedValue(0)
        let (server, light) = try await startServer(on: link, toggles: toggles)
        let controller = try makeController(on: link, maxRetransmissions: 4)

        do {
            let device = try await controller.commission(address: link.b.address, setupCode: Self.passcode)
            _ = try await controller.readAttribute(
                nodeID: device.nodeID, endpointID: light.endpointID,
                clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff
            )
            // With a CASE session cached, so the live session is updated in place.
            await controller.setMRPParameters(Self.fast, for: device.nodeID)
            #expect(await controller.device(for: device.nodeID)?.mrpParameters == Self.fast)

            // The device still receives and executes, but every reply is lost.
            link.setDropProbability(1, from: .b)
            let sentBefore = link.sent(from: .a).count
            await #expect(throws: ControllerError.peerUnreachable(device.nodeID)) {
                try await controller.invokeCommand(
                    nodeID: device.nodeID, endpointID: light.endpointID,
                    clusterID: .onOff, commandID: OnOffCluster.Command.toggle
                )
            }
            let duringFailure = Array(link.sent(from: .a)[sentBefore...])
            let failedCounters = Set(try duringFailure.map { try MessageHeader.decode(from: $0).header.messageCounter })
            #expect(duringFailure.count == 5, "1 transmission + 4 MRP retransmissions")
            #expect(failedCounters.count == 1, "every transmission is the same message")

            link.setDropProbability(0, from: .b)
            let value = try await controller.readAttribute(
                nodeID: device.nodeID, endpointID: light.endpointID,
                clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff
            )
            #expect(value.boolValue == true, "the invoke reached the device once and was not re-issued")
            #expect(toggles.value == 1)

            let afterRecovery = link.sent(from: .a).dropFirst(sentBefore + duringFailure.count)
            let recoveryCounters = try afterRecovery.map { try MessageHeader.decode(from: $0).header.messageCounter }
            #expect(!recoveryCounters.contains { failedCounters.contains($0) })
            let recoveryHeaders = try afterRecovery.map { try MessageHeader.decode(from: $0).header }
            #expect(recoveryHeaders.contains { $0.isUnsecured }, "the next call re-established CASE")
        } catch {
            await controller.stop()
            await server.stop()
            throw error
        }
        await controller.stop()
        await server.stop()
    }

    // MARK: - Rig

    private func startServer(on link: FaultInjectingLink, toggles: LockedValue<Int>) async throws -> (MatterDeviceServer, BridgedEndpoint) {
        let bridge = MatterBridge()
        let light = bridge.addDimmableLight(name: "Faulty Light", onOffChanged: { _ in
            toggles.withLock { $0 += 1 }
        })
        let server = MatterDeviceServer(
            bridge: bridge,
            transport: link.b,
            discovery: FaultyLinkDiscovery(),
            config: .init(
                discriminator: 3840,
                passcode: Self.passcode,
                port: 5540,
                salt: Data(repeating: 0xAB, count: 32),
                iterations: 1000
            )
        )
        try await server.start()
        return (server, light)
    }

    private func makeController(on link: FaultInjectingLink, maxRetransmissions: Int) throws -> MatterController {
        try MatterController(
            transport: link.a,
            discovery: FaultyLinkDiscovery(),
            configuration: .init(
                fabricID: FabricID(rawValue: 1),
                mrp: MRPConfig(maxRetransmissions: maxRetransmissions)
            )
        )
    }
}

/// Discovery is not exercised: the link carries addresses directly.
private struct FaultyLinkDiscovery: MatterDiscovery {
    func advertise(service: MatterServiceRecord) async throws {}
    func browse(serviceType: ServiceType) -> AsyncStream<MatterServiceRecord> {
        AsyncStream { $0.finish() }
    }
    func resolve(_ record: MatterServiceRecord) async throws -> MatterAddress {
        throw FaultyLinkDiscoveryError.notAvailable
    }
    func stopAdvertising() async {}
}

private enum FaultyLinkDiscoveryError: Error {
    case notAvailable
}
