// MessengerPathTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Logging
import Tracing
import InMemoryTracing
import MatterTypes
import MatterCrypto
import MatterProtocol
import MatterTransport
import MatterTestSupport
@testable import MatterController

private let en0Path = MatterPath(interfaceIndex: 7, interfaceName: "en0", localAddress: "fd48::a")
private let en1Path = MatterPath(interfaceIndex: 15, interfaceName: "en1", localAddress: "fd48::b")

/// A messenger on a dual-homed fake wrapping `link.a`: `en0` (`fd48::a`) and `en1` (`fd48::b`)
/// both reach the peer (`10.0.0.2`); the route table picks `routeTable`. The fake logs into the
/// same capture as the messenger.
private struct PathRig {
    let telemetry = TestTelemetry()
    let clock = ManualClock()
    let origin: ContinuousClock.Instant
    let link = FaultInjectingLink(seed: 1)
    let endpoint: MultiInterfaceEndpoint
    let messenger: ControllerMessenger

    init(policy: InterfacePolicy = .automatic, routeTable: String? = "en0") {
        origin = clock.now
        let peerHost = link.b.address.host
        endpoint = MultiInterfaceEndpoint(
            wrapping: link.a,
            interfaces: [
                .init(snapshot: InterfaceSnapshot(name: "en0", index: 7, isUp: true, addresses: ["fd48::a"]), reachable: [peerHost]),
                .init(snapshot: InterfaceSnapshot(name: "en1", index: 15, isUp: true, addresses: ["fd48::b"]), reachable: [peerHost]),
            ],
            routeTable: routeTable,
            logger: telemetry.logger(label: "test.transport")
        )
        messenger = makeMessenger(link: link, clock: clock, telemetry: telemetry, transport: endpoint, interfaces: policy)
    }

    /// Mirrored sessions 10 / 20, registered with `path`.
    func registerSession(path: MatterPath?) async throws -> (controller: SecureSession, peer: SecureSession) {
        let (controllerSession, peerSession) = ScriptedPeer.mirroredSessions(controllerSessionID: 10, peerSessionID: 20)
        try await messenger.registerSession(controllerSession, peerAddress: link.b.address, path: path)
        return (controllerSession, peerSession)
    }

    var sentPaths: [MatterPath] { endpoint.sends.map(\.path) }

    func selections(_ outcome: String) -> Int64 {
        telemetry.counter("matter_transport_path_selections_total", [("outcome", outcome)])
    }

    func repins(_ reason: String) -> Int64 {
        telemetry.counter("matter_transport_path_repins_total", [("reason", reason)])
    }

    func logged(_ level: Logger.Level, containing text: String) -> Bool {
        telemetry.logs.entries.contains { $0.level == level && $0.message.contains(text) }
    }
}

@Suite("ControllerMessenger interface paths", .timeLimit(.minutes(5)))
struct MessengerPathTests {

    // MARK: - Handshakes (unsecured exchanges)

    @Test("Every frame of a handshake leaves by the path its first frame chose")
    func handshakeStaysOnFirstPath() async throws {
        let rig = PathRig()
        var peer = TestPeer(link: rig.link)
        let exchange = await rig.messenger.openExchange(peer: rig.link.b.address)
        try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data([1]))
        #expect(rig.sentPaths == [en0Path])
        #expect(await exchange.path() == en0Path)

        rig.endpoint.setRouteTable("en1")
        #expect(await rig.clock.waitForSleeper(until: rig.origin + .milliseconds(550)))
        await rig.clock.advance(by: .milliseconds(550))
        #expect(await eventually { rig.endpoint.sends.count == 2 })

        let first = try await peer.next()
        _ = try await peer.next()
        try await peer.send(ScriptedPeer.unsecuredReply(to: first, protocolID: .echo, opcode: echoResponse, payload: Data([2]), counter: 500))
        _ = try await exchange.receive(timeout: .seconds(30))
        try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data([3]))
        #expect(rig.sentPaths.count == 3)
        #expect(rig.sentPaths.allSatisfy { $0 == en0Path }, "\(rig.sentPaths)")
        #expect(rig.selections("route_table") == 1, "one selection per exchange")
        await exchange.close()
        await rig.messenger.stop()
    }

    @Test("Preference is honoured on first contact")
    func preferenceOnFirstContact() async throws {
        let rig = PathRig(policy: InterfacePolicy(preferred: ["en1"]))
        let exchange = await rig.messenger.openExchange(peer: rig.link.b.address)
        try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data([1]))
        #expect(rig.sentPaths == [en1Path])
        #expect(rig.selections("preferred") == 1)
        #expect(rig.endpoint.policy == InterfacePolicy(preferred: ["en1"]))
        await exchange.close()
        await rig.messenger.stop()
    }

    @Test("A preferred interface without a route falls through")
    func preferredWithoutRouteFallsThrough() async throws {
        let rig = PathRig(policy: InterfacePolicy(preferred: ["en1"]))
        rig.endpoint.setReachable("en1", [])
        let exchange = await rig.messenger.openExchange(peer: rig.link.b.address)
        try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data([1]))
        #expect(rig.sentPaths == [en0Path])
        #expect(rig.selections("fallthrough") == 1)
        #expect(rig.selections("preferred") == 0)
        #expect(rig.logged(.info, containing: "en1 preferred"))
        await exchange.close()
        await rig.messenger.stop()
    }

    @Test("An excluded interface is never used")
    func excludedNeverUsed() async throws {
        let rig = PathRig(policy: InterfacePolicy(excluded: ["en0"]), routeTable: "en0")
        let exchange = await rig.messenger.openExchange(peer: rig.link.b.address)
        try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data([1]))
        #expect(rig.sentPaths == [en1Path])
        await exchange.close()
        await rig.messenger.stop()

        let none = PathRig(policy: InterfacePolicy(excluded: ["en0", "en1"]))
        let blocked = await none.messenger.openExchange(peer: none.link.b.address)
        let error = MessagingError.noAllowedRoute(blocked.key, peer: none.link.b.address)
        await #expect(throws: error) {
            try await blocked.send(protocolID: .echo, opcode: echoRequest, payload: Data([1]))
        }
        await #expect(throws: error) { _ = try await blocked.receive(timeout: .seconds(5)) }
        #expect(none.endpoint.sends.isEmpty)
        #expect(await none.messenger.activeExchangeCount == 0)
        #expect(await none.messenger.closingExchangeCount == 0, "MRP does not retransmit into nothing")
        #expect(none.logged(.warning, containing: "No allowed interface"))
        await none.messenger.stop()
    }

    @Test("Unauthenticated traffic never moves a pin")
    func unauthenticatedNeverMovesPin() async throws {
        let rig = PathRig()
        var peer = TestPeer(link: rig.link)
        let exchange = await rig.messenger.openExchange(peer: rig.link.b.address)
        try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data([1]))
        let first = try await peer.next()

        rig.endpoint.setArrival("en1")
        try await peer.send(ScriptedPeer.unsecuredReply(to: first, protocolID: .echo, opcode: echoResponse, payload: Data([2]), counter: 500))
        _ = try await exchange.receive(timeout: .seconds(30))
        try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data([3]))
        #expect(rig.sentPaths == [en0Path, en0Path])
        #expect(await exchange.path() == en0Path)
        await exchange.close()

        // A secured frame that fails decryption, arriving on en1, leaves the session on en0.
        let sessions = try await rig.registerSession(path: en0Path)
        let (_, forger) = ScriptedPeer.mirroredSessions(controllerSessionID: 10, peerSessionID: 20)
        try await peer.send(ScriptedPeer.secured(
            session: forger, exchangeID: 9, initiator: true, protocolID: .echo, opcode: echoRequest
        ))
        #expect(await eventually { rig.telemetry.logs.entries.contains { $0.message.contains("decryption failed") } })
        #expect(await rig.messenger.path(forSession: sessions.controller.localSessionID) == en0Path)
        #expect(rig.repins("arrival") == 0)
        await rig.messenger.stop()
    }

    @Test("Losing a route fails a handshake at once")
    func routeLossFailsHandshake() async throws {
        let rig = PathRig(routeTable: "en1")
        let exchange = await rig.messenger.openExchange(peer: rig.link.b.address)
        try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data([1]))
        #expect(rig.sentPaths == [en1Path])
        rig.endpoint.setReachable("en1", [])

        let waiting = Task { try await exchange.receive(timeout: .seconds(30)) }
        #expect(await eventually { await rig.messenger.pendingReceiveCount == 1 })
        #expect(await rig.clock.waitForSleeper(until: rig.origin + .milliseconds(550)))
        await rig.clock.advance(by: .milliseconds(550))
        await #expect(throws: MessagingError.pathLost(exchange.key, en1Path)) { try await waiting.value }
        #expect(rig.sentPaths == [en1Path], "nothing leaves by another interface mid-handshake")
        #expect(await rig.messenger.activeExchangeCount == 0)
        #expect(await rig.messenger.closingExchangeCount == 0)
        #expect(rig.logged(.info, containing: "lost its route"))
        await rig.messenger.stop()
    }

    @Test("A peer-initiated handshake is answered by the path it arrived on")
    func peerInitiatedHandshakeAnsweredByArrival() async throws {
        let rig = PathRig(routeTable: "en0")
        await rig.messenger.setUnsolicitedHandler { message, exchange in
            try? await exchange.send(protocolID: .echo, opcode: echoResponse, payload: message.payload, reliable: false)
        }
        // Started (and the policy applied) before the peer speaks.
        let warmup = await rig.messenger.openExchange(peer: rig.link.b.address)
        await warmup.close()
        rig.endpoint.setArrival("en1")
        try await TestPeer(link: rig.link).send(ScriptedPeer.unsecured(
            exchangeID: 0x55, initiator: true, protocolID: .echo, opcode: echoRequest, payload: Data([4]),
            counter: 900, sourceNodeID: NodeID(rawValue: 77)
        ))
        #expect(await eventually { rig.endpoint.sends.count == 1 })
        #expect(rig.sentPaths == [en1Path])
        #expect(rig.selections("route_table") == 0)
        await rig.messenger.stop()
    }

    // MARK: - Sessions

    @Test("A session replies by the path its traffic arrived on")
    func sessionFollowsAuthenticatedArrival() async throws {
        let rig = PathRig()
        var peer = TestPeer(link: rig.link)
        let sessions = try await rig.registerSession(path: en0Path)
        let exchange = try await rig.messenger.openExchange(sessionID: 10)
        try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data([1]))
        #expect(rig.sentPaths == [en0Path])
        let request = try await peer.nextSecured(session: sessions.peer)

        rig.endpoint.setArrival("en1")
        try await peer.send(ScriptedPeer.securedReply(
            to: request, session: sessions.peer, protocolID: .echo, opcode: echoResponse, payload: Data([2])
        ))
        _ = try await exchange.receive(timeout: .seconds(30))
        await exchange.close()                                  // the owed ack goes out now
        #expect(await eventually { rig.endpoint.sends.count == 2 })
        #expect(rig.sentPaths == [en0Path, en1Path])
        #expect(await rig.messenger.path(forSession: 10) == en1Path)
        #expect(rig.logged(.info, containing: "Session 0xA re-pinned en0 → en1 (traffic arrived on en1)"))
        #expect(rig.repins("arrival") == 1)
        #expect(rig.selections("route_table") == 0, "a pinned session never selects")
        await rig.messenger.stop()
    }

    @Test("Arrival on an excluded interface leaves the pin")
    func excludedArrivalKeepsPin() async throws {
        let rig = PathRig(policy: InterfacePolicy(excluded: ["en1"]))
        var peer = TestPeer(link: rig.link)
        let sessions = try await rig.registerSession(path: en0Path)
        let exchange = try await rig.messenger.openExchange(sessionID: 10)
        try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data([1]))
        let request = try await peer.nextSecured(session: sessions.peer)
        rig.endpoint.setArrival("en1")
        try await peer.send(ScriptedPeer.securedReply(
            to: request, session: sessions.peer, protocolID: .echo, opcode: echoResponse, payload: Data([2])
        ))
        _ = try await exchange.receive(timeout: .seconds(30))
        await exchange.close()
        #expect(await eventually { rig.endpoint.sends.count == 2 })
        #expect(rig.sentPaths == [en0Path, en0Path])
        #expect(await rig.messenger.path(forSession: 10) == en0Path)
        #expect(rig.repins("arrival") == 0)
        await rig.messenger.stop()
    }

    @Test("Losing a route re-pins a session")
    func routeLossRepinsSession() async throws {
        let rig = PathRig()
        _ = try await rig.registerSession(path: en1Path)
        rig.endpoint.setReachable("en1", [])
        let exchange = try await rig.messenger.openExchange(sessionID: 10)
        try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data([1]))
        #expect(rig.sentPaths == [en0Path])
        #expect(await rig.messenger.path(forSession: 10) == en0Path)
        #expect(rig.repins("route_lost") == 1)
        #expect(rig.selections("route_table") == 1)
        #expect(rig.logged(.info, containing: "Session 0xA: en1 lost its route to"))
        #expect(rig.logged(.info, containing: "Session 0xA re-pinned to en0"))
        await exchange.close()
        await rig.messenger.stop()
    }

    // MARK: - Policy

    @Test("A named interface that is missing is reported")
    func missingInterfaceReported() async throws {
        let rig = PathRig(policy: InterfacePolicy(preferred: ["en7"]))
        let exchange = await rig.messenger.openExchange(peer: rig.link.b.address)
        #expect(await eventually { rig.logged(.warning, containing: "Interface en7 named in the Matter interface policy is missing") })
        await exchange.close()
        await rig.messenger.stop()
    }

    @Test("A transport that cannot tell its path is used unpinned")
    func pathlessTransport() async throws {
        let clock = ManualClock()
        let link = FaultInjectingLink(seed: 1)
        let telemetry = TestTelemetry()
        let messenger = makeMessenger(link: link, clock: clock, telemetry: telemetry)
        let exchange = await messenger.openExchange(peer: link.b.address)
        try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data([1]))
        #expect(link.sent(from: .a).count == 1)
        #expect(await exchange.path() == nil)
        #expect(telemetry.metrics.counters.allSatisfy { !$0.label.hasPrefix("matter_transport_path") || $0.totalValue == 0 })
        await exchange.close()
        await messenger.stop()
    }
}

@Suite("MatterController interface paths", .timeLimit(.minutes(5)))
struct ControllerPathTests {

    /// The dual-homed fake of ``PathRig`` around the controller's end of the link.
    private static func dualHomed(_ link: FaultInjectingLink, _ logger: Logger) -> MultiInterfaceEndpoint {
        let peerHost = link.b.address.host
        return MultiInterfaceEndpoint(
            wrapping: link.a,
            interfaces: [
                .init(snapshot: InterfaceSnapshot(name: "en0", index: 7, isUp: true, addresses: ["fd48::a"]), reachable: [peerHost]),
                .init(snapshot: InterfaceSnapshot(name: "en1", index: 15, isUp: true, addresses: ["fd48::b"]), reachable: [peerHost]),
            ],
            routeTable: "en0",
            logger: logger
        )
    }

    @Test("A CASE session keeps the path its handshake chose, recorded on the matter.case span")
    func caseSessionKeepsHandshakePath() async throws {
        let endpoint = LockedValue<MultiInterfaceEndpoint?>(nil)
        let policy = InterfacePolicy(preferred: ["en1"])
        let (rig, fabric) = try await makeCASEControllerRig(transport: { link, logger in
            let fake = Self.dualHomed(link, logger)
            endpoint.withLock { $0 = fake }
            return fake
        }, interfaces: policy)
        let fake = try #require(endpoint.withLock { $0 })
        var peer = TestPeer(link: rig.link)
        var seen = Set<UInt32>()
        let node = rig.node
        let establishing = Task { try await rig.controller.session(for: node) }
        let sigma1 = try await nextNewUnsecuredFrame(&peer, seen: &seen)
        let (sigma2, _) = try CASEProtocolHandler(fabricInfo: fabric.deviceFabric).handleSigma1(payload: sigma1.payload, responderSessionID: 300)
        try await peer.send(ScriptedPeer.unsecuredReply(
            to: sigma1, protocolID: .secureChannel, opcode: SecureChannelOpcode.caseSigma2.rawValue,
            payload: sigma2, counter: 800
        ))
        let sigma3 = try await nextNewUnsecuredFrame(&peer, seen: &seen)
        try await peer.send(ScriptedPeer.unsecuredReply(
            to: sigma3, protocolID: .secureChannel, opcode: SecureChannelOpcode.statusReport.rawValue,
            payload: StatusReportMessage(generalStatus: .success, protocolID: 0, protocolStatus: 0).encode(), counter: 801
        ))
        let session = try await establishing.value

        #expect(fake.policy == policy)
        #expect(fake.sends.allSatisfy { $0.path == en1Path }, "\(fake.sends.map(\.path))")
        #expect(await rig.controller.messenger.path(forSession: session.localSessionID) == en1Path)
        let span = try #require(rig.telemetry.finishedSpans(named: "matter.case").first)
        #expect(span.attributes.get(MatterLogKey.interface) == .string("en1"))
        #expect(span.attributes.get(MatterLogKey.localAddress) == .string("fd48::b"))
        await rig.controller.stop()
    }
}
