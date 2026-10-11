// MessengerMRPTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterProtocol
import MatterTransport
import MatterTestSupport
@testable import MatterController

@Suite("ControllerMessenger MRP timing", .timeLimit(.minutes(1)))
struct MessengerMRPTests {

    @Test("A lost request is retransmitted byte for byte SII × 1.1 after it was sent")
    func lostRequestRetransmitted() async throws {
        let clock = ManualClock()
        let origin = clock.now
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: clock)
        var peer = TestPeer(link: link)
        link.dropNext(1, from: .a)

        let exchange = await messenger.openExchange(peer: link.b.address)
        try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data([1]))
        #expect(await clock.waitForSleeper(until: origin + .milliseconds(550)))

        await clock.advance(by: .milliseconds(549))
        #expect(link.sent(from: .a).count == 1)
        await clock.advance(by: .milliseconds(1))
        #expect(link.sent(from: .a).count == 2)

        let sent = link.sent(from: .a)
        #expect(sent[0] == sent[1])
        let delivered = try await peer.next()
        #expect(try ScriptedPeer.decodeUnsecured(sent[0]).counter == delivered.counter)
        #expect(await clock.waitForSleeper(until: origin + .milliseconds(1430)))
        #expect(clock.quiescenceTimeouts == 0)
        await messenger.stop()
    }

    @Test("A lost response is recovered: the peer sees one counter twice, the caller gets one reply")
    func lostResponseRecovered() async throws {
        let clock = ManualClock()
        let origin = clock.now
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: clock)
        var peer = TestPeer(link: link)
        let exchange = await messenger.openExchange(peer: link.b.address)

        async let reply = exchange.request(protocolID: .echo, opcode: echoRequest, payload: Data(), timeout: .seconds(30))
        let first = try await peer.next()
        let response = ScriptedPeer.unsecuredReply(to: first, protocolID: .echo, opcode: echoResponse, payload: Data([7]), counter: 300)
        link.dropNext(1, from: .b)
        try await peer.send(response)                       // lost

        #expect(await clock.waitForSleeper(until: origin + .milliseconds(550)))
        await clock.advance(by: .milliseconds(550))
        let second = try await peer.next()
        #expect(second.counter == first.counter)
        #expect(second == first)

        try await peer.send(response)                       // the peer answers the retransmission
        #expect(try await reply.payload == Data([7]))

        try await peer.send(response)                       // a late third copy
        let ack = try await peer.next()
        #expect(ack.isStandaloneAck)
        #expect(ack.exchangeHeader.acknowledgedMessageCounter == 300)

        // Exactly one response: the next receive gets nothing and expires.
        let waiting = Task { try await exchange.receive(timeout: .seconds(30)) }
        #expect(await eventually { await messenger.pendingReceiveCount == 1 })
        await clock.advance(by: .seconds(30))
        await #expect(throws: MessagingError.responseTimeout(exchange.key)) { try await waiting.value }
        #expect(clock.quiescenceTimeouts == 0)
        await messenger.stop()
    }

    @Test("A silent peer surfaces .peerUnreachable after the fifth interval, never .responseTimeout")
    func exhaustionIsExact() async throws {
        let clock = ManualClock()
        let origin = clock.now
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: clock)
        link.setDropProbability(1, from: .a)
        let exchange = await messenger.openExchange(peer: link.b.address)

        let requesting = Task {
            try await exchange.request(protocolID: .echo, opcode: echoRequest, payload: Data(), timeout: .seconds(1))
        }
        #expect(await eventually { await messenger.pendingReceiveCount == 1 })
        #expect(await clock.waitForSleeper(until: origin + .milliseconds(550)))

        await clock.advance(by: .milliseconds(8695))
        #expect(await messenger.pendingReceiveCount == 1, "a 1 s timeout must not end the wait while MRP is still retransmitting")
        #expect(link.sent(from: .a).count == 5)

        await clock.advance(by: .microseconds(280))
        await #expect(throws: MessagingError.peerUnreachable(exchange.key, transmissions: 5)) {
            try await requesting.value
        }
        #expect(link.sent(from: .a).count == 5, "decide first: nothing is sent at the exhausting deadline")
        #expect(await messenger.activeExchangeCount == 0)
        #expect(clock.quiescenceTimeouts == 0)
        await messenger.stop()
    }

    @Test("Sleepy peer: SII spacing while idle, SAI once it has spoken within SAT, SII again after SAT")
    func sleepySpacing() async throws {
        let clock = ManualClock()
        let origin = clock.now
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(
            link: link,
            clock: clock,
            peer: MRPParameters(
                sessionIdleInterval: .milliseconds(5000),
                sessionActiveInterval: .milliseconds(300),
                sessionActiveThreshold: .milliseconds(4000)
            )
        )
        var peer = TestPeer(link: link)

        // Never heard from: idle, SII-based.
        let first = await messenger.openExchange(peer: link.b.address)
        try await first.send(protocolID: .echo, opcode: echoRequest, payload: Data())
        #expect(await clock.waitForSleeper(until: origin + .milliseconds(5500)))
        let firstRequest = try await peer.next()
        try await peer.send(ScriptedPeer.unsecuredReply(to: firstRequest, protocolID: .echo, opcode: echoResponse, counter: 10))
        _ = try await first.receive(timeout: .seconds(1))
        await first.close()
        let firstFlush = try await peer.next()
        #expect(firstFlush.isStandaloneAck)

        // Spoke at origin, within SAT: active, SAI-based.
        let second = await messenger.openExchange(peer: link.b.address)
        try await second.send(protocolID: .echo, opcode: echoRequest, payload: Data())
        #expect(await clock.waitForSleeper(until: origin + .milliseconds(330)))
        let secondRequest = try await peer.next()
        try await peer.send(ScriptedPeer.unsecuredReply(to: secondRequest, protocolID: .echo, opcode: echoResponse, counter: 11))
        _ = try await second.receive(timeout: .seconds(1))
        await second.close()
        let secondFlush = try await peer.next()
        #expect(secondFlush.isStandaloneAck)

        // SAT lapses: idle again.
        await clock.advance(by: .milliseconds(4001))
        let third = await messenger.openExchange(peer: link.b.address)
        try await third.send(protocolID: .echo, opcode: echoRequest, payload: Data())
        #expect(await clock.waitForSleeper(until: origin + .milliseconds(4001 + 5500)))
        #expect(clock.quiescenceTimeouts == 0)
        await messenger.stop()
    }

    @Test("With nothing to piggyback on, an owed ack goes out standalone after 200 ms")
    func standaloneAckAfterTimeout() async throws {
        let clock = ManualClock()
        let origin = clock.now
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: clock)
        var peer = TestPeer(link: link)
        let exchange = await messenger.openExchange(peer: link.b.address)

        async let reply = exchange.request(protocolID: .echo, opcode: echoRequest, payload: Data(), timeout: .seconds(5))
        let request = try await peer.next()
        try await peer.send(ScriptedPeer.unsecuredReply(to: request, protocolID: .echo, opcode: echoResponse, counter: 77))
        _ = try await reply

        #expect(await clock.waitForSleeper(until: origin + .milliseconds(200)))
        await clock.advance(by: .milliseconds(199))
        #expect(link.sent(from: .a).count == 1)
        await clock.advance(by: .milliseconds(1))
        #expect(link.sent(from: .a).count == 2)
        let ack = try await peer.next()
        #expect(ack.isStandaloneAck)
        #expect(ack.exchangeHeader.acknowledgedMessageCounter == 77)
        #expect(clock.quiescenceTimeouts == 0)
        await messenger.stop()
    }

    @Test("A timeout longer than the horizon applies as given, and expiry closes the exchange")
    func longTimeoutApplies() async throws {
        let clock = ManualClock()
        let origin = clock.now
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: clock)
        var peer = TestPeer(link: link)
        let exchange = await messenger.openExchange(peer: link.b.address)

        let requesting = Task {
            try await exchange.request(protocolID: .echo, opcode: echoRequest, payload: Data(), timeout: .seconds(20))
        }
        let request = try await peer.next()
        try await peer.send(ScriptedPeer.unsecuredAck(for: request, counter: 5))
        #expect(await clock.waitForSleeper(until: origin + .seconds(20)))

        await clock.advance(by: .milliseconds(19_999))
        #expect(await messenger.pendingReceiveCount == 1)
        await clock.advance(by: .milliseconds(1))
        await #expect(throws: MessagingError.responseTimeout(exchange.key)) { try await requesting.value }
        #expect(await messenger.activeExchangeCount == 0)
        #expect(clock.quiescenceTimeouts == 0)
        await messenger.stop()
    }

    @Test("A timeout shorter than the horizon is raised to it")
    func shortTimeoutWaitsForHorizon() async throws {
        let clock = ManualClock()
        let origin = clock.now
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: clock)
        var peer = TestPeer(link: link)
        let exchange = await messenger.openExchange(peer: link.b.address)

        let requesting = Task {
            try await exchange.request(protocolID: .echo, opcode: echoRequest, payload: Data(), timeout: .seconds(1))
        }
        let request = try await peer.next()
        try await peer.send(ScriptedPeer.unsecuredAck(for: request, counter: 5))
        // Horizon at u = 1 for SII 500 (the larger of the idle and active horizons).
        #expect(await clock.waitForSleeper(until: origin + .microseconds(10_869_100)))

        await clock.advance(by: .milliseconds(10_869))
        #expect(await messenger.pendingReceiveCount == 1)
        await clock.advance(by: .microseconds(100))
        await #expect(throws: MessagingError.responseTimeout(exchange.key)) { try await requesting.value }
        #expect(clock.quiescenceTimeouts == 0)
        await messenger.stop()
    }

    @Test("An expired receive closes its exchange through the close path: a pending reliable message keeps retransmitting")
    func expiredReceiveKeepsPendingMessageUnderMRP() async throws {
        let clock = ManualClock()
        let origin = clock.now
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: clock)
        let exchange = await messenger.openExchange(peer: link.b.address)

        let waiting = Task { try await exchange.receive(timeout: .seconds(1)) }
        #expect(await eventually { await messenger.pendingReceiveCount == 1 })
        #expect(await clock.waitForSleeper(until: origin + .microseconds(10_869_100)))

        // A reliable message sent mid-wait outlives the receive deadline.
        await clock.advance(by: .seconds(5))
        try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data())
        #expect(await clock.waitForSleeper(until: origin + .milliseconds(5550)))

        await clock.advance(by: .microseconds(5_869_100))
        await #expect(throws: MessagingError.responseTimeout(exchange.key)) { try await waiting.value }
        #expect(await messenger.activeExchangeCount == 0)
        #expect(await messenger.closingExchangeCount == 1)
        #expect(link.sent(from: .a).count == 5)

        // Exhaustion of the closed exchange's message (5000 + 8695.28 ms) removes it silently.
        await clock.advance(by: .microseconds(2_826_180))
        #expect(await messenger.closingExchangeCount == 0)
        #expect(link.sent(from: .a).count == 5)
        #expect(clock.quiescenceTimeouts == 0)
        await messenger.stop()
    }
}
