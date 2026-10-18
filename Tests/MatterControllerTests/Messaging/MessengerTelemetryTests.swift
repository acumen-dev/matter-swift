// MessengerTelemetryTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Tracing
import InMemoryTracing
import MatterTypes
import MatterProtocol
import MatterTransport
import MatterTestSupport
@testable import MatterController

@Suite("ControllerMessenger telemetry", .timeLimit(.minutes(1)))
struct MessengerTelemetryTests {

    @Test("Each send and receive is traced with session, exchange, protocol, opcode, counter and ack, and counted")
    func framesTraced() async throws {
        let telemetry = TestTelemetry()
        let rig = try await makeRig(telemetry: telemetry)
        var peer = TestPeer(link: rig.link)
        let exchange = try await rig.messenger.openExchange(sessionID: 10)
        async let reply = exchange.request(protocolID: .echo, opcode: echoRequest, payload: Data([1]), timeout: .seconds(30))
        let request = try await peer.nextSecured(session: rig.peerSession)
        try await peer.send(ScriptedPeer.securedReply(to: request, session: rig.peerSession, protocolID: .echo, opcode: echoResponse, payload: Data([2])))
        let response = try await reply
        await exchange.close()
        let ack = try await peer.nextSecured(session: rig.peerSession)
        #expect(ack.isStandaloneAck)

        let sent = try #require(telemetry.logs.entries.first { $0.message.hasPrefix("send secured") })
        #expect(sent.level == .trace)
        #expect(sent.subsystem == "messenger")
        #expect(sent.message == "send secured I=1 R=1")
        #expect(sent.metadata[MatterLogKey.session] == "0xA")
        #expect(sent.metadata[MatterLogKey.exchange] == MatterLogValue.hexString(exchange.key.exchangeID))
        #expect(sent.metadata[MatterLogKey.protocolID] == "0x4")
        #expect(sent.metadata[MatterLogKey.opcode] == "0x1")
        #expect(sent.metadata[MatterLogKey.counter] == String(request.counter))
        #expect(sent.metadata[MatterLogKey.ack] == nil)

        let received = try #require(telemetry.logs.entries.first { $0.message.hasPrefix("receive secured") })
        #expect(received.message == "receive secured I=0 R=1")
        #expect(received.metadata[MatterLogKey.counter] == String(response.messageCounter))
        #expect(received.metadata[MatterLogKey.ack] == String(request.counter))

        #expect(telemetry.logs.entries.contains {
            $0.message == "Ack received" && $0.subsystem == "mrp" && $0.metadata[MatterLogKey.ack] == String(request.counter)
        })
        let standalone = try #require(telemetry.logs.entries.first { $0.message == "standalone ack" })
        #expect(standalone.subsystem == "mrp")
        #expect(standalone.metadata[MatterLogKey.ack] == String(response.messageCounter))

        #expect(telemetry.counter("matter_controller_messages_total", [("direction", "out"), ("protocol", "echo")]) == 1)
        #expect(telemetry.counter("matter_controller_messages_total", [("direction", "in"), ("protocol", "echo")]) == 1)
        #expect(telemetry.counter("matter_controller_messages_total", [("direction", "out"), ("protocol", "secure_channel")]) == 1)
        #expect(telemetry.finishedSpans(named: "matter.exchange").isEmpty, "no context, no exchange span")
        #expect(telemetry.activeSpans(named: "matter.exchange").isEmpty, "no context, no exchange span")
        await rig.messenger.stop()
    }

    @Test("Frame lines on a secure session carry its peer's matter.node, a PASE peer's unspecified 0x0 included")
    func framesCarryNode() async throws {
        let telemetry = TestTelemetry()
        let rig = try await makeRig(telemetry: telemetry)
        var peer = TestPeer(link: rig.link)
        let (operational, operationalPeer) = ScriptedPeer.mirroredSessions(
            controllerSessionID: 30, peerSessionID: 40, peerNodeID: NodeID(rawValue: 0x42)
        )
        try await rig.messenger.registerSession(operational, peerAddress: rig.link.b.address)

        for (sessionID, session) in [(UInt16(30), operationalPeer), (UInt16(10), rig.peerSession)] {
            let exchange = try await rig.messenger.openExchange(sessionID: sessionID)
            try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data([1]))
            _ = try await peer.nextSecured(session: session)
            await exchange.close()
        }

        let sends = telemetry.logs.entries.filter { $0.message.hasPrefix("send secured") }
        let operationalSend = try #require(sends.first { $0.metadata[MatterLogKey.session] == "0x1E" })
        #expect(operationalSend.metadata[MatterLogKey.node] == "0x42")
        let paseSend = try #require(sends.first { $0.metadata[MatterLogKey.session] == "0xA" })
        #expect(paseSend.metadata[MatterLogKey.node] == "0x0")
        await rig.messenger.stop()
    }

    @Test("An unsolicited message with no handler is logged with matter.reason no_handler")
    func noHandlerReason() async throws {
        let telemetry = TestTelemetry()
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: ManualClock(), telemetry: telemetry)
        var peer = TestPeer(link: link)
        await messenger.start()
        try await peer.send(ScriptedPeer.unsecured(exchangeID: 0x4242, initiator: true, protocolID: .echo, opcode: echoRequest, counter: 500))
        #expect(try await peer.next().isStandaloneAck)

        let line = try await telemetry.logs.first { $0.message.hasPrefix("No handler for unsolicited") }
        #expect(line.level == .debug)
        #expect(line.metadata[MatterLogKey.reason] == "no_handler")
        #expect(line.metadata[MatterLogKey.session] == "unsecured")
        await messenger.stop()
    }

    @Test("An exchange span that is not recording is ended at once and never kept")
    func unrecordedExchangeSpanNotKept() async throws {
        let tracer = CountingTracer()
        let link = FaultInjectingLink(seed: 1)
        var configuration = ControllerMessenger.Configuration()
        configuration.mrp = MRPConfig(peer: testPeerParameters, maxRetransmissions: 4)
        configuration.tracer = tracer
        let messenger = ControllerMessenger(
            transport: link.a, localNodeID: NodeID(rawValue: 1), configuration: configuration,
            clock: ManualClock(), jitterSource: { 0 }
        )
        var peer = TestPeer(link: link)
        let exchange = await messenger.openExchange(peer: link.b.address, context: .topLevel)
        try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data([1]))
        _ = try await peer.next()

        #expect(tracer.started.value == 1)
        #expect(tracer.ended.value == 1, "ended at once")
        #expect(await messenger.exchangeSpans.isEmpty)
        await exchange.close()
        await messenger.stop()
    }

    @Test("A final message on a closed exchange that goes unacknowledged is a give-up at info")
    func closedExchangeGiveUp() async throws {
        let telemetry = TestTelemetry()
        let clock = ManualClock()
        let origin = clock.now
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: clock, telemetry: telemetry)
        link.setDropProbability(1, from: .a)
        let exchange = await messenger.openExchange(peer: link.b.address)
        try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data())
        await exchange.close()

        var previous = origin
        for deadline in [550.0, 1430.0, 2838.0, 5090.8] {
            let instant = origin + .microseconds(Int64(deadline * 1000))
            #expect(await clock.waitForSleeper(until: instant))
            await clock.advance(by: instant - previous)
            previous = instant
        }
        let exhaustion = origin + .nanoseconds(8_695_280_000)
        #expect(await clock.waitForSleeper(until: exhaustion))
        await clock.advance(by: exhaustion - previous)

        let line = try await telemetry.logs.first { $0.message.hasPrefix("Final message on closed exchange") }
        #expect(line.level == .info)
        #expect(line.subsystem == "mrp")
        #expect(telemetry.counter("matter_mrp_give_ups_total") == 1)
        await messenger.stop()
    }

    @Test("A dropped request: a trace retransmit line, the retransmit counter, and a retransmit span event")
    func droppedDatagram() async throws {
        let telemetry = TestTelemetry()
        let clock = ManualClock()
        let origin = clock.now
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: clock, telemetry: telemetry)
        link.dropNext(1, from: .a)
        let parent = telemetry.tracer.startSpan("test.parent")

        let exchange = await messenger.openExchange(peer: link.b.address, context: parent.context)
        try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data([1]))
        #expect(await clock.waitForSleeper(until: origin + .milliseconds(550)))
        await clock.advance(by: .milliseconds(550))
        #expect(await eventually { link.sent(from: .a).count == 2 })

        let line = try #require(telemetry.logs.entries.first { $0.message.hasPrefix("MRP retransmit") })
        #expect(line.level == .trace)
        #expect(line.subsystem == "mrp")
        #expect(line.message == "MRP retransmit 1, next in 880 ms")
        #expect(line.metadata[MatterLogKey.attempt] == "1")
        #expect(line.metadata[MatterLogKey.session] == "unsecured")
        #expect(telemetry.counter("matter_mrp_retransmits_total") == 1)

        let span = try #require(telemetry.activeSpans(named: "matter.exchange").first)
        #expect(span.parentSpanID == parent.spanID)
        #expect(span.events.map(\.name) == ["send", "retransmit"])
        #expect(span.events.last?.attributes.get(MatterLogKey.attempt) == .int64(1))

        await exchange.close()
        let finished = telemetry.finishedSpans(named: "matter.exchange")
        #expect(finished.count == 1)
        #expect(finished.first?.status == nil, "a clean close is not an error")
        #expect(clock.quiescenceTimeouts == 0)
        await messenger.stop()
    }

    @Test("Exhaustion: the give-up at info, the give-up counter, and error status on the exchange span")
    func giveUp() async throws {
        let telemetry = TestTelemetry()
        let clock = ManualClock()
        let origin = clock.now
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: clock, telemetry: telemetry)
        link.setDropProbability(1, from: .a)
        let parent = telemetry.tracer.startSpan("test.parent")
        let exchange = await messenger.openExchange(peer: link.b.address, context: parent.context)

        let requesting = Task {
            try await exchange.request(protocolID: .echo, opcode: echoRequest, payload: Data(), timeout: .seconds(1))
        }
        #expect(await eventually { await messenger.pendingReceiveCount == 1 })
        var previous = origin
        for deadline in [550.0, 1430.0, 2838.0, 5090.8] {
            let instant = origin + .microseconds(Int64(deadline * 1000))
            #expect(await clock.waitForSleeper(until: instant))
            await clock.advance(by: instant - previous)
            previous = instant
        }
        let exhaustion = origin + .nanoseconds(8_695_280_000)
        #expect(await clock.waitForSleeper(until: exhaustion))
        await clock.advance(by: exhaustion - previous)
        await #expect(throws: MessagingError.peerUnreachable(exchange.key, transmissions: 5)) {
            try await requesting.value
        }

        let line = try #require(telemetry.logs.entries.first { $0.message.hasPrefix("Peer unreachable") })
        #expect(line.level == .info)
        #expect(line.subsystem == "mrp")
        #expect(line.metadata[MatterLogKey.attempt] == "5")
        #expect(telemetry.counter("matter_mrp_retransmits_total") == 4)
        #expect(telemetry.counter("matter_mrp_give_ups_total") == 1)

        let span = try #require(telemetry.finishedSpans(named: "matter.exchange").first)
        #expect(span.status?.code == .error)
        #expect(span.parentSpanID == parent.spanID)
        #expect(span.events.map(\.name) == ["send", "retransmit", "retransmit", "retransmit", "retransmit"])
        #expect(clock.quiescenceTimeouts == 0)
        await messenger.stop()
    }

    @Test("A response timeout: debug line, timeout counter, and error status on the exchange span")
    func responseTimeout() async throws {
        let telemetry = TestTelemetry()
        let clock = ManualClock()
        let origin = clock.now
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: clock, telemetry: telemetry)
        var peer = TestPeer(link: link)
        let parent = telemetry.tracer.startSpan("test.parent")
        let exchange = await messenger.openExchange(peer: link.b.address, context: parent.context)

        let waiting = Task {
            try await exchange.request(protocolID: .echo, opcode: echoRequest, payload: Data(), timeout: .seconds(30))
        }
        let request = try await peer.next()
        try await peer.send(ScriptedPeer.unsecuredAck(for: request, counter: 400))
        #expect(await clock.waitForSleeper(until: origin + .seconds(30)), "acked: only the receive deadline is left")
        await clock.advance(by: .seconds(30))
        await #expect(throws: MessagingError.responseTimeout(exchange.key)) { try await waiting.value }

        let line = try #require(telemetry.logs.entries.first { $0.message.hasPrefix("Exchange response timeout") })
        #expect(line.level == .debug)
        #expect(line.subsystem == "exchange")
        #expect(line.metadata[MatterLogKey.exchange] == MatterLogValue.hexString(exchange.key.exchangeID))
        #expect(telemetry.counter("matter_exchange_timeouts_total") == 1)
        let span = try #require(telemetry.finishedSpans(named: "matter.exchange").first)
        #expect(span.status?.code == .error)
        #expect(span.events.map(\.name) == ["send", "ack"])
        #expect(clock.quiescenceTimeouts == 0)
        await messenger.stop()
    }

    @Test("Duplicate and unknown-session drops are traced with their reason")
    func dropsTraced() async throws {
        let telemetry = TestTelemetry()
        let rig = try await makeRig(telemetry: telemetry)
        var peer = TestPeer(link: rig.link)
        let stranger = ScriptedPeer.mirroredSessions(controllerSessionID: 77, peerSessionID: 78).peer
        try await peer.send(ScriptedPeer.secured(session: stranger, exchangeID: 0x0700, initiator: true, protocolID: .echo, opcode: echoRequest))

        let exchange = try await rig.messenger.openExchange(sessionID: 10)
        async let reply = exchange.request(protocolID: .echo, opcode: echoRequest, payload: Data(), timeout: .seconds(30))
        let request = try await peer.nextSecured(session: rig.peerSession)
        let response = try ScriptedPeer.securedReply(to: request, session: rig.peerSession, protocolID: .echo, opcode: echoResponse)
        try await peer.send(response)
        _ = try await reply
        try await peer.send(response)                                   // the same bytes again
        let reAck = try await peer.nextSecured(session: rig.peerSession)
        #expect(reAck.isStandaloneAck)

        let unknown = try #require(telemetry.logs.entries.first { $0.message.hasPrefix("Dropping message for unknown session") })
        #expect(unknown.level == .trace)
        #expect(unknown.metadata[MatterLogKey.reason] == "unknown_session")
        #expect(unknown.metadata[MatterLogKey.session] == "0x4D")
        let duplicate = try #require(telemetry.logs.entries.first { $0.message.hasPrefix("Dropping duplicate") })
        #expect(duplicate.level == .trace)
        #expect(duplicate.metadata[MatterLogKey.reason] == "duplicate")
        await exchange.close()
        await rig.messenger.stop()
    }

    @Test("A frame failing its MIC on a known session is dropped as decrypt_failed; garbage as undecodable")
    func decryptFailed() async throws {
        let telemetry = TestTelemetry()
        let rig = try await makeRig(telemetry: telemetry)
        let peer = TestPeer(link: rig.link)
        var forged = try ScriptedPeer.secured(session: rig.peerSession, exchangeID: 0x0701, initiator: true, protocolID: .echo, opcode: echoRequest)
        forged[forged.index(before: forged.endIndex)] ^= 0xFF                 // corrupt the MIC
        try await peer.send(forged)
        try await peer.send(Data([0xFF]))

        let rejected = try await telemetry.logs.first { $0.metadata[MatterLogKey.reason] == "decrypt_failed" }
        #expect(rejected.level == .debug)
        #expect(rejected.subsystem == "messenger")
        #expect(rejected.metadata[MatterLogKey.session] == "0xA")
        let garbage = try await telemetry.logs.first { $0.metadata[MatterLogKey.reason] == "undecodable" }
        #expect(garbage.message.hasPrefix("Dropping datagram"))
        #expect(telemetry.logs.entries.filter { $0.metadata[MatterLogKey.reason] == "undecodable" }.count == 1, "the forged frame is not undecodable")
        #expect(telemetry.counter("matter_controller_messages_total", [("direction", "in"), ("protocol", "echo")]) == 0)
        await rig.messenger.stop()
    }

    @Test("A secure session's peer address change is logged at info, old → new")
    func peerMoved() async throws {
        let telemetry = TestTelemetry()
        let rig = try await makeRig(telemetry: telemetry)
        var peer = TestPeer(link: rig.link)
        let exchange = try await rig.messenger.openExchange(sessionID: 10)
        async let reply = exchange.request(protocolID: .echo, opcode: echoRequest, payload: Data(), timeout: .seconds(30))
        let request = try await peer.nextSecured(session: rig.peerSession)
        let moved = MatterAddress(host: "10.0.0.3", port: 5541)
        try await peer.send(ScriptedPeer.securedReply(to: request, session: rig.peerSession, protocolID: .echo, opcode: echoResponse), from: moved)
        _ = try await reply

        let line = try #require(telemetry.logs.entries.first { $0.message.hasPrefix("Session peer address changed") })
        #expect(line.level == .info)
        #expect(line.subsystem == "session")
        #expect(line.message == "Session peer address changed: 10.0.0.2:5540 → 10.0.0.3:5541")
        #expect(line.metadata[MatterLogKey.session] == "0xA")
        await exchange.close()
        await rig.messenger.stop()
    }
}

// MARK: - Counting Tracer

/// A tracer whose spans never record, counting how many it started and how many were ended.
private final class CountingTracer: Tracer, Sendable {
    let started = LockedValue(0)
    let ended = LockedValue(0)

    func startSpan<Instant: TracerInstant>(
        _ operationName: String,
        context: @autoclosure () -> ServiceContext,
        ofKind kind: SpanKind,
        at instant: @autoclosure () -> Instant,
        function: String,
        file fileID: String,
        line: UInt
    ) -> UnrecordedSpan {
        started.withLock { $0 += 1 }
        return UnrecordedSpan(context: context(), ended: ended)
    }

    func activeSpan(identifiedBy context: ServiceContext) -> UnrecordedSpan? { nil }

    func forceFlush() {}

    func inject<Carrier, Inject: Injector>(_ context: ServiceContext, into carrier: inout Carrier, using injector: Inject)
    where Inject.Carrier == Carrier {}

    func extract<Carrier, Extract: Extractor>(_ carrier: Carrier, into context: inout ServiceContext, using extractor: Extract)
    where Extract.Carrier == Carrier {}
}

/// A span that records nothing and counts its `end`.
private struct UnrecordedSpan: Span {
    let context: ServiceContext
    let ended: LockedValue<Int>

    var operationName: String {
        get { "" }
        nonmutating set {}
    }

    var attributes: SpanAttributes {
        get { [:] }
        nonmutating set {}
    }

    var isRecording: Bool { false }

    func setStatus(_ status: SpanStatus) {}
    func addEvent(_ event: SpanEvent) {}
    func recordError<Instant: TracerInstant>(_ error: any Error, attributes: SpanAttributes, at instant: @autoclosure () -> Instant) {}
    func addLink(_ link: SpanLink) {}

    func end<Instant: TracerInstant>(at instant: @autoclosure () -> Instant) {
        ended.withLock { $0 += 1 }
    }
}
