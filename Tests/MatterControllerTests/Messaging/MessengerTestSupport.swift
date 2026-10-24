// MessengerTestSupport.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterProtocol
import MatterTransport
import MatterTestSupport
@testable import MatterController

/// SII 500 ms / SAI 300 ms / SAT 4000 ms.
let testPeerParameters = MRPParameters(
    sessionIdleInterval: .milliseconds(500),
    sessionActiveInterval: .milliseconds(300),
    sessionActiveThreshold: .milliseconds(4000)
)

/// A messenger on endpoint `a` of `link` (or on `transport`, when given), zero jitter, on
/// `clock`, under `interfaces`; with `telemetry`, its metrics, tracer and a `test.messenger` logger.
func makeMessenger(
    link: FaultInjectingLink,
    clock: ManualClock,
    peer: MRPParameters = testPeerParameters,
    maxRetransmissions: Int = 4,
    telemetry: TestTelemetry? = nil,
    transport: (any MatterUDPTransport)? = nil,
    interfaces: InterfacePolicy = .automatic
) -> ControllerMessenger {
    let transport = transport ?? link.a
    var configuration = ControllerMessenger.Configuration()
    configuration.mrp = MRPConfig(peer: peer, maxRetransmissions: maxRetransmissions)
    configuration.interfaces = interfaces
    guard let telemetry else {
        return ControllerMessenger(
            transport: transport, localNodeID: NodeID(rawValue: 1), configuration: configuration,
            clock: clock, jitterSource: { 0 }
        )
    }
    configuration.metricsFactory = telemetry.metrics
    configuration.tracer = telemetry.tracer
    return ControllerMessenger(
        transport: transport, localNodeID: NodeID(rawValue: 1), configuration: configuration,
        clock: clock, jitterSource: { 0 }, logger: telemetry.logger(label: "test.messenger")
    )
}

struct Rig {
    let clock: ManualClock
    let link: FaultInjectingLink
    let messenger: ControllerMessenger
    let controllerSession: SecureSession
    let peerSession: SecureSession
}

/// Mirrored sessions 10 (controller) / 20 (peer) on a ManualClock.
func makeRig(telemetry: TestTelemetry? = nil) async throws -> Rig {
    let clock = ManualClock()
    let link = FaultInjectingLink(seed: 1)
    let messenger = makeMessenger(link: link, clock: clock, telemetry: telemetry)
    let (controllerSession, peerSession) = ScriptedPeer.mirroredSessions(controllerSessionID: 10, peerSessionID: 20)
    try await messenger.registerSession(controllerSession, peerAddress: link.b.address)
    return Rig(clock: clock, link: link, messenger: messenger, controllerSession: controllerSession, peerSession: peerSession)
}

/// The test's side of the link (endpoint `b`).
struct TestPeer {
    let link: FaultInjectingLink
    private var inbox: AsyncStream<(Data, MatterAddress)>.Iterator

    init(link: FaultInjectingLink) {
        self.link = link
        self.inbox = link.b.receive().makeAsyncIterator()
    }

    /// The next datagram the controller sent.
    mutating func nextDatagram() async throws -> Data {
        guard let element = await inbox.next() else { throw TestPeerError.linkClosed }
        return element.0
    }

    mutating func next() async throws -> PeerFrame {
        try ScriptedPeer.decodeUnsecured(try await nextDatagram())
    }

    mutating func nextSecured(session: SecureSession) async throws -> PeerFrame {
        try ScriptedPeer.decodeSecured(try await nextDatagram(), session: session)
    }

    func send(_ data: Data) async throws {
        try await link.b.send(data, to: link.a.address)
    }

    func send(_ data: Data, from source: MatterAddress) async throws {
        try await link.b.send(data, to: link.a.address, from: source)
    }
}

enum TestPeerError: Error {
    case linkClosed
}

/// Yield until `condition` holds (bounded). Waits for an outcome; never a timing margin.
func eventually(_ condition: @Sendable () async -> Bool) async -> Bool {
    for _ in 0..<100_000 {
        if await condition() { return true }
        await Task.yield()
    }
    return false
}

let echoRequest: UInt8 = 0x01
let echoResponse: UInt8 = 0x02
