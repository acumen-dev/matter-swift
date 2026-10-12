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
            let device = try await controller.commission(address: link.b.address, setupCode: passcode, mrp: fast)
            #expect(device.mrpParameters == fast)

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

    @Test("Two controllers in turn: CommissionedDevice.fabricIndex is the device's index (1, then 2), not the controller's own")
    func deviceAssignedFabricIndex() async throws {
        let link = FaultInjectingLink(seed: 11)
        let (server, _) = try await startServer(on: link, toggles: LockedValue(0))
        // A controller's stop() cancels its receive task (it does not close
        // the transport), which would end the link's single receive stream;
        // the hand-off keeps one reader on it and lends each controller its own.
        let side = HandoffTransport(link.a)
        let first = try makeBorrowingController(transport: side)
        var second: MatterController?

        do {
            let d1 = try await first.commission(address: link.b.address, setupCode: passcode, mrp: fast)
            #expect(d1.fabricIndex == FabricIndex(rawValue: 1))
            await first.stop()

            // The first commit closed the window; reopen it for the second admin.
            await server.openCommissioningWindow(timeout: 180)
            let other = try makeBorrowingController(transport: side)
            second = other
            let d2 = try await other.commission(address: link.b.address, setupCode: passcode, mrp: fast)
            #expect(d2.fabricIndex == FabricIndex(rawValue: 2))
        } catch {
            await first.stop()
            await second?.stop()
            await server.stop()
            side.shutdown()
            throw error
        }
        await second?.stop()
        await server.stop()
        side.shutdown()
    }

    /// Checks that `isFabricFiltered` reaches the device. The device server
    /// leaves OperationalCredentials.Fabrics empty (only CommissionedFabrics
    /// is maintained), so the fabric-scoped list read here is the ACL. It
    /// keeps one device-wide readable ACL list (a filed device issue), so the
    /// fabric-1 entry is whatever the last raw ACL write left there, not
    /// necessarily the first admin's; the assertions are on fabric indices,
    /// not on whose entries or how many.
    @Test("isFabricFiltered reaches the device: an unfiltered ACL read shows a fabric-1 entry; a filtered one shows no other fabric's")
    func fabricFilteredRead() async throws {
        let link = FaultInjectingLink(seed: 29)
        let (server, _) = try await startServer(on: link, toggles: LockedValue(0))
        // Controllers borrow the link in turn (see deviceAssignedFabricIndex).
        let side = HandoffTransport(link.a)
        let first = try makeBorrowingController(transport: side)
        var second: MatterController?

        do {
            _ = try await first.commission(address: link.b.address, setupCode: passcode, mrp: fast)
            await first.stop()
            await server.openCommissioningWindow(timeout: 180)
            let other = try makeBorrowingController(transport: side)
            second = other
            let device = try await other.commission(address: link.b.address, setupCode: passcode, mrp: fast)

            let all = try await other.readAttribute(
                nodeID: device.nodeID, endpointID: .root, clusterID: .accessControl,
                attributeID: AccessControlCluster.Attribute.acl, isFabricFiltered: false
            )
            #expect(Self.fabricIndices(all).contains(1),
                    "an unfiltered read (isFabricFiltered: false) shows an entry of fabric 1, not the reader's: \(all)")
            let own = try await other.readAttribute(
                nodeID: device.nodeID, endpointID: .root, clusterID: .accessControl,
                attributeID: AccessControlCluster.Attribute.acl
            )
            #expect(Self.fabricIndices(own).allSatisfy { $0 == UInt64(device.fabricIndex.rawValue) },
                    "a filtered read shows no other fabric's entry: \(own)")
        } catch {
            await first.stop()
            await second?.stop()
            await server.stop()
            side.shutdown()
            throw error
        }
        await second?.stop()
        await server.stop()
        side.shutdown()
    }

    /// The FabricIndex (tag 0xFE) of each entry of a fabric-scoped list.
    private static func fabricIndices(_ list: TLVElement) -> [UInt64] {
        (list.arrayElements ?? []).compactMap { entry in
            guard case .structure(let fields) = entry else { return nil }
            return fields.first(where: { $0.tag == .contextSpecific(0xFE) })?.value.uintValue
        }
    }

    private func makeBorrowingController(transport: any MatterUDPTransport) throws -> MatterController {
        try MatterController(
            transport: transport,
            discovery: FaultyLinkDiscovery(),
            configuration: .init(
                fabricID: FabricID(rawValue: 1),
                mrp: MRPConfig(maxRetransmissions: 10)
            )
        )
    }

    @Test("A silent peer surfaces peerUnreachable; the next call re-establishes CASE and never re-sends the invoke")
    func silentPeer() async throws {
        let link = FaultInjectingLink(seed: 7)
        let toggles = LockedValue(0)
        let (server, light) = try await startServer(on: link, toggles: toggles)
        let controller = try makeController(on: link, maxRetransmissions: 4)

        do {
            let device = try await controller.commission(address: link.b.address, setupCode: passcode)
            _ = try await controller.readAttribute(
                nodeID: device.nodeID, endpointID: light.endpointID,
                clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff
            )
            // With a CASE session cached, so the live session is updated in place.
            await controller.setMRPParameters(fast, for: device.nodeID)
            #expect(await controller.device(for: device.nodeID)?.mrpParameters == fast)

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
            let device = try await controller.commission(address: link.b.address, setupCode: passcode)
            // Commissioning leaves its CASE session cached; drop it so the
            // operations below must establish (and share) a fresh one.
            await controller.invalidateSession(for: device.nodeID)
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
            let device = try await controller.commission(address: link.b.address, setupCode: passcode)
            // Commissioning leaves its CASE session cached; drop it so the
            // operations below must establish (and share) a fresh one.
            await controller.invalidateSession(for: device.nodeID)
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
            let device = try await controller.commission(address: link.b.address, setupCode: passcode)
            // Commissioning leaves its CASE session cached; drop it so the
            // operations below must establish (and share) a fresh one.
            await controller.invalidateSession(for: device.nodeID)
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
            let device = try await controller.commission(address: link.b.address, setupCode: passcode)
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
            let device = try await controller.commission(address: link.b.address, setupCode: passcode)
            let session = try await controller.session(for: device.nodeID)
            let scope = SessionScope.secured(localSessionID: session.localSessionID)
            #expect(await controller.messenger.parameters(for: scope) == nil)

            await controller.setMRPParameters(fast, for: device.nodeID)
            #expect(await controller.messenger.parameters(for: scope) == fast)

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
}

/// Lends one link endpoint to controllers in turn. `close()` ends only the
/// current borrower's stream; a permanent pump keeps reading the endpoint and
/// forwards to whichever borrower is current (datagrams in between are lost).
private final class HandoffTransport: MatterUDPTransport, Sendable {
    private let base: FaultInjectingEndpoint
    private let current = LockedValue<AsyncStream<(Data, MatterAddress)>.Continuation?>(nil)
    private let pump = LockedValue<Task<Void, Never>?>(nil)

    init(_ base: FaultInjectingEndpoint) {
        self.base = base
        let current = self.current
        let source = base.receive()
        pump.withLock {
            $0 = Task {
                for await datagram in source {
                    current.withLock { $0 }?.yield(datagram)
                }
            }
        }
    }

    var address: MatterAddress { base.address }

    func send(_ data: Data, to address: MatterAddress) async throws {
        try await base.send(data, to: address)
    }

    func receive() -> AsyncStream<(Data, MatterAddress)> {
        let (stream, continuation) = AsyncStream<(Data, MatterAddress)>.makeStream()
        current.withLock { $0?.finish(); $0 = continuation }
        return stream
    }

    func bind(port: UInt16) async throws {}

    func close() async {
        current.withLock { $0?.finish(); $0 = nil }
    }

    func shutdown() {
        pump.withLock { $0?.cancel(); $0 = nil }
    }
}
