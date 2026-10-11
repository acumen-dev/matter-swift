// MessengerReliabilityTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterProtocol
import MatterTransport
import MatterTestSupport
@testable import MatterController

@Suite("ControllerMessenger reliability", .timeLimit(.minutes(1)))
struct MessengerReliabilityTests {

    /// Retransmission interval after `n` transmissions to an idle peer, zero jitter.
    func idleInterval(_ n: Int) -> Duration {
        MRPConfig(peer: testPeerParameters).retransmissionInterval(transmissionsSoFar: n, peerActive: false, jitterUnit: 0)
    }

    // MARK: - Closing exchanges keep MRP running

    @Test("A closed exchange keeps retransmitting its unacknowledged message; the ack removes it")
    func closeKeepsRetransmittingUntilAcked() async throws {
        let clock = ManualClock()
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: clock)
        var peer = TestPeer(link: link)
        let exchange = await messenger.openExchange(peer: link.b.address)
        let sentAt = clock.now

        try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data([7]))
        let original = try await peer.nextDatagram()
        await exchange.close()
        #expect(await messenger.activeExchangeCount == 0)
        #expect(await messenger.closingExchangeCount == 1)
        await #expect(throws: MessagingError.exchangeClosed) {
            try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data())
        }

        #expect(await clock.waitForSleeper(until: sentAt + idleInterval(1)))
        await clock.advance(by: idleInterval(1))
        #expect(try await peer.nextDatagram() == original)

        let frame = try ScriptedPeer.decodeUnsecured(original)
        try await peer.send(ScriptedPeer.unsecuredAck(for: frame, counter: 40))
        #expect(await eventually { await messenger.closingExchangeCount == 0 })
        #expect(await messenger.activeExchangeCount == 0)

        // Nothing is left to retransmit.
        #expect(await clock.waitForSleepers(1))
        await clock.advance(by: idleInterval(2) + idleInterval(3))
        #expect(link.sent(from: .a).count == 2)
        #expect(clock.quiescenceTimeouts == 0)
        await messenger.stop()
    }

    @Test("Exhaustion of a closed exchange removes it and reports nothing")
    func closingExhaustionIsSilent() async throws {
        let clock = ManualClock()
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: clock, maxRetransmissions: 1)
        var peer = TestPeer(link: link)
        let exchange = await messenger.openExchange(peer: link.b.address)
        let sentAt = clock.now

        try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data())
        _ = try await peer.nextDatagram()
        await exchange.close()

        let firstDeadline = sentAt + idleInterval(1)
        #expect(await clock.waitForSleeper(until: firstDeadline))
        await clock.advance(by: idleInterval(1))
        _ = try await peer.nextDatagram()

        #expect(await clock.waitForSleeper(until: firstDeadline + idleInterval(2)))
        await clock.advance(by: idleInterval(2))
        #expect(await eventually { await messenger.closingExchangeCount == 0 })
        #expect(await messenger.failed.isEmpty)
        #expect(await messenger.ephemeralNodeIDs.isEmpty)
        #expect(link.sent(from: .a).count == 2)
        #expect(clock.quiescenceTimeouts == 0)
        await messenger.stop()
    }

    @Test("A late message on a closed exchange is acknowledged, not delivered, and does not end MRP")
    func lateMessageOnClosingExchangeIsAcked() async throws {
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: ManualClock())
        var peer = TestPeer(link: link)
        let exchange = await messenger.openExchange(peer: link.b.address)

        try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data())
        let request = try await peer.next()
        await exchange.close()

        // Reliable, but carries no ack of our message.
        let late = ScriptedPeer.unsecured(
            exchangeID: request.exchangeHeader.exchangeID, initiator: false,
            protocolID: .echo, opcode: echoResponse, payload: Data([5]), counter: 300
        )
        try await peer.send(late)
        let ack = try await peer.next()
        #expect(ack.isStandaloneAck)
        #expect(ack.exchangeHeader.acknowledgedMessageCounter == 300)
        #expect(await messenger.closingExchangeCount == 1)
        #expect(await messenger.inbound.isEmpty)

        // Its duplicate is acknowledged again.
        try await peer.send(late)
        let again = try await peer.next()
        #expect(again.isStandaloneAck)
        #expect(again.exchangeHeader.acknowledgedMessageCounter == 300)
        #expect(await messenger.closingExchangeCount == 1)

        // A late reply that also acknowledges our message: acked (still with
        // the exchange's ephemeral source ID), and the exchange is done.
        try await peer.send(ScriptedPeer.unsecuredReply(to: request, protocolID: .echo, opcode: echoResponse, counter: 301))
        let finalAck = try await peer.next()
        #expect(finalAck.isStandaloneAck)
        #expect(finalAck.exchangeHeader.acknowledgedMessageCounter == 301)
        #expect(finalAck.messageHeader.sourceNodeID == request.messageHeader.sourceNodeID)
        #expect(await messenger.closingExchangeCount == 0)
        await messenger.stop()
    }

    // MARK: - Ephemeral initiator node ID

    @Test("Unsecured frames carry an ephemeral source node ID, stable per exchange, distinct across exchanges")
    func ephemeralSourceNodeID() async throws {
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: ManualClock())
        var peer = TestPeer(link: link)

        let first = await messenger.openExchange(peer: link.b.address)
        async let reply = first.request(protocolID: .echo, opcode: echoRequest, payload: Data(), timeout: .seconds(5))
        let request = try await peer.next()
        try await peer.send(ScriptedPeer.unsecuredReply(to: request, protocolID: .echo, opcode: echoResponse, counter: 60))
        _ = try await reply
        await first.close()
        let flushedAck = try await peer.next()

        let source = try #require(request.messageHeader.sourceNodeID)
        #expect(flushedAck.isStandaloneAck)
        #expect(flushedAck.messageHeader.sourceNodeID == source)

        let second = await messenger.openExchange(peer: link.b.address)
        try await second.send(protocolID: .echo, opcode: echoRequest, payload: Data(), reliable: false)
        try await second.send(protocolID: .echo, opcode: echoRequest, payload: Data(), reliable: false)
        let secondFrame = try await peer.next()
        let secondFollowUp = try await peer.next()
        let secondSource = try #require(secondFrame.messageHeader.sourceNodeID)
        #expect(secondFollowUp.messageHeader.sourceNodeID == secondSource)
        #expect(secondSource != source)
        await messenger.stop()
    }

    @Test("A re-ack after the exchange is gone still carries our ephemeral ID, taken from the reply's destination")
    func reAckAfterCloseEchoesDestination() async throws {
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: ManualClock())
        var peer = TestPeer(link: link)
        let exchange = await messenger.openExchange(peer: link.b.address)

        async let reply = exchange.request(protocolID: .echo, opcode: echoRequest, payload: Data(), timeout: .seconds(5))
        let request = try await peer.next()
        let replyBytes = ScriptedPeer.unsecuredReply(to: request, protocolID: .echo, opcode: echoResponse, counter: 70)
        try await peer.send(replyBytes)
        _ = try await reply
        await exchange.close()
        let flushedAck = try await peer.next()
        #expect(await messenger.ephemeralNodeIDs.isEmpty)

        // Our flushed ack was lost: the peer retransmits its reply.
        try await peer.send(replyBytes)
        let reAck = try await peer.next()
        let ephemeral = try #require(request.messageHeader.sourceNodeID)
        #expect(reAck.isStandaloneAck)
        #expect(reAck.exchangeHeader.acknowledgedMessageCounter == 70)
        #expect(flushedAck.messageHeader.sourceNodeID == ephemeral)
        #expect(reAck.messageHeader.sourceNodeID == ephemeral)
        await messenger.stop()
    }

    @Test("Acks on a peer-initiated unsecured exchange are addressed to the peer's ephemeral ID")
    func peerInitiatedAcksEchoSource() async throws {
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: ManualClock())
        var peer = TestPeer(link: link)
        await messenger.start()
        let peerEphemeral = NodeID(rawValue: 0x1234_5678_9ABC_DEF0)

        // No handler: acknowledged and closed at once.
        let unsolicited = ScriptedPeer.unsecured(
            exchangeID: 0x4242, initiator: true, protocolID: .echo, opcode: echoRequest,
            counter: 500, sourceNodeID: peerEphemeral
        )
        try await peer.send(unsolicited)
        let ack = try await peer.next()
        #expect(ack.isStandaloneAck)
        #expect(ack.exchangeHeader.acknowledgedMessageCounter == 500)
        #expect(ack.messageHeader.destinationNodeID == peerEphemeral)
        #expect(ack.messageHeader.sourceNodeID == nil)

        // Its duplicate, after the exchange is gone, is addressed the same way.
        try await peer.send(unsolicited)
        let reAck = try await peer.next()
        #expect(reAck.isStandaloneAck)
        #expect(reAck.messageHeader.destinationNodeID == peerEphemeral)
        #expect(await messenger.activeExchangeCount == 0)
        await messenger.stop()
    }

    // MARK: - Waiter tokens

    @Test("A cancellation hop that lost the race to delivery does not fail a later receive")
    func staleCancellationIsIgnored() async throws {
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: ManualClock())
        var peer = TestPeer(link: link)
        let exchange = await messenger.openExchange(peer: link.b.address)
        try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data(), reliable: false)
        let request = try await peer.next()

        let firstReceive = Task { try await exchange.receive(timeout: .seconds(5)) }
        #expect(await eventually { await messenger.pendingReceiveCount == 1 })
        let staleToken = try #require(await messenger.waiters[exchange.key]?.token)
        try await peer.send(ScriptedPeer.unsecuredReply(to: request, protocolID: .echo, opcode: echoResponse, payload: Data([1]), counter: 80, reliable: false))
        #expect(try await firstReceive.value.payload == Data([1]))

        let secondReceive = Task { try await exchange.receive(timeout: .seconds(5)) }
        #expect(await eventually { await messenger.pendingReceiveCount == 1 })
        // The first receive's cancellation hop arriving late.
        await messenger.cancelReceive(exchange.key, token: staleToken)
        #expect(await messenger.pendingReceiveCount == 1)
        #expect(await messenger.activeExchangeCount == 1)

        try await peer.send(ScriptedPeer.unsecuredReply(to: request, protocolID: .echo, opcode: echoResponse, payload: Data([2]), counter: 81, reliable: false))
        #expect(try await secondReceive.value.payload == Data([2]))
        await messenger.stop()
    }

    // MARK: - One reliable message at a time

    @Test("A second reliable send while one is unacknowledged is refused")
    func sendAlreadyPending() async throws {
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: ManualClock())
        var peer = TestPeer(link: link)
        let exchange = await messenger.openExchange(peer: link.b.address)

        try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data([1]))
        let request = try await peer.next()
        await #expect(throws: MessagingError.sendAlreadyPending) {
            try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data([2]))
        }
        // An unreliable message does not disturb the tracked one.
        try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data([3]), reliable: false)
        _ = try await peer.next()
        #expect(await messenger.manager.exchange(for: exchange.key)?.pendingMessageCounter == request.counter)

        try await peer.send(ScriptedPeer.unsecuredAck(for: request, counter: 90))
        #expect(await eventually { await messenger.manager.exchange(for: exchange.key)?.pendingMessage == nil })
        try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data([4]))
        #expect(try await peer.next().payload == Data([4]))
        await messenger.stop()
    }

    // MARK: - Idle timer

    @Test("Re-arming with nothing pending keeps the idle timer rather than replacing it")
    func idleTimerIsNotReplaced() async throws {
        let clock = ManualClock()
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: clock)
        await messenger.start()
        #expect(await clock.waitForSleepers(1))
        let idleDeadline = try #require(clock.nextSleeperDeadline)

        await clock.advance(by: .seconds(1))
        let exchange = await messenger.openExchange(peer: link.b.address)
        await exchange.close()
        #expect(clock.nextSleeperDeadline == idleDeadline)
        #expect(clock.sleeperCount == 1)
        #expect(clock.quiescenceTimeouts == 0)
        await messenger.stop()
    }
}
