// FaultyLinkTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterModel
import MatterProtocol
import MatterTransport
@testable import MatterController
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

    @Test("Concurrent operations on a node share one CASE handshake, and all succeed")
    func concurrentOperationsShareOneSession() async throws {
        let link = FaultInjectingLink(seed: 11)
        let toggles = LockedValue(0)
        let (server, light) = try await startServer(on: link, toggles: toggles)
        let controller = try makeController(on: link, maxRetransmissions: 4)

        do {
            let device = try await controller.commission(address: link.b.address, setupCode: Self.passcode)
            let sentBefore = link.sent(from: .a).count

            // Overlapping reads and one invoke, all issued before any CASE session exists.
            let results = try await withThrowingTaskGroup(of: Bool.self) { group in
                for _ in 0..<6 {
                    group.addTask {
                        _ = try await controller.readAttribute(
                            nodeID: device.nodeID, endpointID: light.endpointID,
                            clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff
                        )
                        return true
                    }
                }
                group.addTask {
                    _ = try await controller.invokeCommand(
                        nodeID: device.nodeID, endpointID: light.endpointID,
                        clusterID: .onOff, commandID: OnOffCluster.Command.toggle
                    )
                    return true
                }
                var all: [Bool] = []
                for try await ok in group { all.append(ok) }
                return all
            }
            #expect(results.count == 7)
            #expect(toggles.value == 1)

            // One Sigma1 exchange on the wire (MRP may resend its Sigma1; same exchange).
            let sigma1Exchanges = Self.sigma1Exchanges(in: link.sent(from: .a).dropFirst(sentBefore))
            #expect(sigma1Exchanges.count == 1)
            #expect(await controller.messenger.sessions.count == 1, "exactly one registered session for the node")

            // The session survives its operations: still cached, still the same one.
            let session = try await controller.session(for: device.nodeID)
            #expect(await controller.messenger.sessions[session.localSessionID]?.session === session)
        } catch {
            await controller.stop()
            await server.stop()
            throw error
        }
        await controller.stop()
        await server.stop()
    }

    @Test("A caller cancelled while waiting on a shared CASE handshake never sends its request")
    func cancelledWaiterNeverSends() async throws {
        let link = FaultInjectingLink(seed: 17)
        let toggles = LockedValue(0)
        let (server, light) = try await startServer(on: link, toggles: toggles)
        let controller = try makeController(on: link, maxRetransmissions: 4)

        do {
            let device = try await controller.commission(address: link.b.address, setupCode: Self.passcode)
            let sentBefore = link.sent(from: .a).count

            // Hold the handshake: the device's replies are lost until released.
            link.setDropProbability(1, from: .b)
            let invoke: @Sendable () async throws -> Void = {
                _ = try await controller.invokeCommand(
                    nodeID: device.nodeID, endpointID: light.endpointID,
                    clusterID: .onOff, commandID: OnOffCluster.Command.toggle
                )
            }
            let first = Task { try await invoke() }
            let cancelled = Task { try await invoke() }
            let third = Task { try await invoke() }

            // The handshake is under way (Sigma1 sent) and cannot complete yet.
            let handshakeStarted = await Self.eventually {
                !Self.sigma1Exchanges(in: link.sent(from: .a).dropFirst(sentBefore)).isEmpty
            }
            #expect(handshakeStarted)
            cancelled.cancel()
            link.setDropProbability(0, from: .b)

            try await first.value
            try await third.value
            await #expect(throws: CancellationError.self) {
                try await cancelled.value
            }

            // Served in order after both invokes: two toggles, back to off.
            let value = try await controller.readAttribute(
                nodeID: device.nodeID, endpointID: light.endpointID,
                clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff
            )
            #expect(toggles.value == 2, "the cancelled caller's toggle must never be sent")
            #expect(value.boolValue == false)
        } catch {
            await controller.stop()
            await server.stop()
            throw error
        }
        await controller.stop()
        await server.stop()
    }

    @Test("A caller cancelled while waiting on a shared CASE handshake stops waiting at once; the others still succeed")
    func cancelledWaiterReturnsBeforeHandshakeCompletes() async throws {
        let link = FaultInjectingLink(seed: 19)
        let toggles = LockedValue(0)
        let (server, light) = try await startServer(on: link, toggles: toggles)
        let controller = try makeController(on: link, maxRetransmissions: 4)

        do {
            let device = try await controller.commission(address: link.b.address, setupCode: Self.passcode)
            let sentBefore = link.sent(from: .a).count

            // Hold the handshake: the device's replies are lost until released.
            link.setDropProbability(1, from: .b)
            let invoke: @Sendable () async throws -> Void = {
                _ = try await controller.invokeCommand(
                    nodeID: device.nodeID, endpointID: light.endpointID,
                    clusterID: .onOff, commandID: OnOffCluster.Command.toggle
                )
            }
            let first = Task { try await invoke() }
            let cancelled = Task { try await invoke() }
            let third = Task { try await invoke() }

            let handshakeStarted = await Self.eventually {
                !Self.sigma1Exchanges(in: link.sent(from: .a).dropFirst(sentBefore)).isEmpty
            }
            #expect(handshakeStarted)
            cancelled.cancel()

            // Still holding the handshake: the cancelled caller must not wait for it.
            await #expect(throws: CancellationError.self) {
                try await cancelled.value
            }
            #expect(await controller.messenger.sessions.isEmpty, "the handshake had not completed")

            link.setDropProbability(0, from: .b)
            try await first.value
            try await third.value

            let value = try await controller.readAttribute(
                nodeID: device.nodeID, endpointID: light.endpointID,
                clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff
            )
            #expect(toggles.value == 2, "the cancelled caller's toggle must never be sent")
            #expect(value.boolValue == false)
        } catch {
            await controller.stop()
            await server.stop()
            throw error
        }
        await controller.stop()
        await server.stop()
    }

    @Test("A session unregistered behind the controller's back surfaces as peerUnreachable; the next call re-establishes CASE")
    func unregisteredSessionIsInvalidated() async throws {
        let link = FaultInjectingLink(seed: 23)
        let (server, light) = try await startServer(on: link, toggles: LockedValue(0))
        let controller = try makeController(on: link, maxRetransmissions: 4)

        do {
            let device = try await controller.commission(address: link.b.address, setupCode: Self.passcode)
            let stale = try await controller.session(for: device.nodeID)
            let sentBefore = link.sent(from: .a).count

            await controller.messenger.unregisterSession(localSessionID: stale.localSessionID)
            await #expect(throws: ControllerError.peerUnreachable(device.nodeID)) {
                try await controller.readAttribute(
                    nodeID: device.nodeID, endpointID: light.endpointID,
                    clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff
                )
            }

            let value = try await controller.readAttribute(
                nodeID: device.nodeID, endpointID: light.endpointID,
                clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff
            )
            #expect(value.boolValue == false)
            let fresh = try await controller.session(for: device.nodeID)
            #expect(fresh !== stale, "the broken session was invalidated, not reused")
            #expect(await controller.messenger.sessions[fresh.localSessionID]?.session === fresh)
            #expect(Self.sigma1Exchanges(in: link.sent(from: .a).dropFirst(sentBefore)).count == 1, "one new CASE handshake")
        } catch {
            await controller.stop()
            await server.stop()
            throw error
        }
        await controller.stop()
        await server.stop()
    }

    @Test("setMRPParameters on a live CASE session reaches the messenger")
    func mrpParametersReachLiveSession() async throws {
        let link = FaultInjectingLink(seed: 13)
        let (server, _) = try await startServer(on: link, toggles: LockedValue(0))
        let controller = try makeController(on: link, maxRetransmissions: 4)

        do {
            let device = try await controller.commission(address: link.b.address, setupCode: Self.passcode)
            let session = try await controller.session(for: device.nodeID)
            let scope = SessionScope.secured(localSessionID: session.localSessionID)
            #expect(await controller.messenger.parameters(for: scope) == nil)

            await controller.setMRPParameters(Self.fast, for: device.nodeID)
            #expect(await controller.messenger.parameters(for: scope) == Self.fast)

            await controller.setMRPParameters(nil, for: device.nodeID)
            #expect(await controller.messenger.parameters(for: scope) == nil)
        } catch {
            await controller.stop()
            await server.stop()
            throw error
        }
        await controller.stop()
        await server.stop()
    }

    // MARK: - Rig

    /// Exchange IDs of CASE Sigma1 frames among `frames` (an MRP resend of
    /// Sigma1 shares its exchange).
    static func sigma1Exchanges(in frames: some Sequence<Data>) -> Set<UInt16> {
        Set(frames.compactMap { data -> UInt16? in
            guard let frame = try? ScriptedPeer.decodeUnsecured(data),
                  frame.exchangeHeader.protocolID == MatterProtocolID.secureChannel.rawValue,
                  frame.exchangeHeader.protocolOpcode == SecureChannelOpcode.caseSigma1.rawValue else { return nil }
            return frame.exchangeHeader.exchangeID
        })
    }

    /// Yield until `condition` holds (bounded). An outcome wait, never a timing margin.
    static func eventually(_ condition: @Sendable () async -> Bool) async -> Bool {
        for _ in 0..<1_000_000 {
            if await condition() { return true }
            await Task.yield()
        }
        return false
    }

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
