// MessengerSessionTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterProtocol
import MatterTransport
import MatterTestSupport
@testable import MatterController

@Suite("ControllerMessenger secure sessions and routing", .timeLimit(.minutes(1)))
struct MessengerSessionTests {

    struct Rig {
        let clock: ManualClock
        let link: FaultInjectingLink
        let messenger: ControllerMessenger
        let controllerSession: SecureSession
        let peerSession: SecureSession
    }

    func makeRig() async -> Rig {
        let clock = ManualClock()
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: clock)
        let (controllerSession, peerSession) = ScriptedPeer.mirroredSessions(controllerSessionID: 10, peerSessionID: 20)
        await messenger.registerSession(controllerSession, peerAddress: link.b.address)
        return Rig(clock: clock, link: link, messenger: messenger, controllerSession: controllerSession, peerSession: peerSession)
    }

    /// Retransmission interval after `n` transmissions to a peer that spoke within SAT, zero jitter.
    func activeInterval(_ n: Int) -> Duration {
        MRPConfig(peer: testPeerParameters).retransmissionInterval(transmissionsSoFar: n, peerActive: true, jitterUnit: 0)
    }

    // MARK: - Request / response

    @Test("An encrypted request is answered on its secure exchange")
    func securedRequestResponse() async throws {
        let rig = await makeRig()
        var peer = TestPeer(link: rig.link)
        let exchange = try await rig.messenger.openExchange(sessionID: 10)
        #expect(exchange.key.scope == .secured(localSessionID: 10))

        async let reply = exchange.request(
            protocolID: .interactionModel, opcode: InteractionModelOpcode.readRequest.rawValue,
            payload: Data([1]), timeout: .seconds(5)
        )
        let request = try await peer.nextSecured(session: rig.peerSession)
        #expect(request.messageHeader.sessionID == 20)
        #expect(request.exchangeHeader.flags.initiator)
        #expect(request.payload == Data([1]))

        try await peer.send(ScriptedPeer.securedReply(
            to: request, session: rig.peerSession,
            protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue, payload: Data([2])
        ))
        let message = try await reply
        #expect(message.key == exchange.key)
        #expect(message.payload == Data([2]))
        #expect(message.acknowledgedCounter == request.counter)
        await exchange.close()
        await rig.messenger.stop()
    }

    @Test("A duplicate on a secure session is acked again and dropped")
    func securedDuplicate() async throws {
        let rig = await makeRig()
        var peer = TestPeer(link: rig.link)
        let exchange = try await rig.messenger.openExchange(sessionID: 10)

        async let first = exchange.request(protocolID: .interactionModel, opcode: InteractionModelOpcode.readRequest.rawValue, payload: Data(), timeout: .seconds(5))
        let request = try await peer.nextSecured(session: rig.peerSession)
        let reply = try ScriptedPeer.securedReply(
            to: request, session: rig.peerSession,
            protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue, payload: Data([1])
        )
        let replyCounter = try MessageHeader.decode(from: reply).header.messageCounter
        try await peer.send(reply)
        _ = try await first

        try await peer.send(reply)
        let ack = try await peer.nextSecured(session: rig.peerSession)
        #expect(ack.isStandaloneAck)
        #expect(ack.exchangeHeader.acknowledgedMessageCounter == replyCounter)
        #expect(await rig.messenger.pendingReceiveCount == 0)
        await rig.messenger.stop()
    }

    @Test("A reliable message more than 32 counters below the session's highest is acked and never delivered")
    func outOfWindowIsAckedNotDelivered() async throws {
        let rig = await makeRig()
        var peer = TestPeer(link: rig.link)
        let handled = LockedValue(0)
        await rig.messenger.setUnsolicitedHandler { _, _ in
            handled.withLock { $0 += 1 }
        }

        // Encoding consumes the peer session's counter: hold this frame back.
        let stale = try ScriptedPeer.secured(
            session: rig.peerSession, exchangeID: 0x4600, initiator: true,
            protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue,
            payload: ReportData(subscriptionID: SubscriptionID(rawValue: 5)).tlvEncode()
        )
        let staleCounter = try MessageHeader.decode(from: stale).header.messageCounter

        // Unreliable standalone acks move the window and have no other effect.
        for index in 0..<34 {
            try await peer.send(try ScriptedPeer.secured(
                session: rig.peerSession, exchangeID: UInt16(0x5000 + index), initiator: true,
                protocolID: .secureChannel, opcode: SecureChannelOpcode.standaloneAck.rawValue,
                reliable: false
            ))
        }
        // In-order processing: once this marker is acked, every filler was processed.
        let marker = try ScriptedPeer.secured(
            session: rig.peerSession, exchangeID: 0x4601, initiator: true,
            protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue,
            payload: ReportData(subscriptionID: SubscriptionID(rawValue: 5)).tlvEncode()
        )
        let markerCounter = try MessageHeader.decode(from: marker).header.messageCounter
        #expect(markerCounter - staleCounter > CounterDeduplication.windowSize)
        try await peer.send(marker)
        let markerAck = try await peer.nextSecured(session: rig.peerSession)
        #expect(markerAck.exchangeHeader.acknowledgedMessageCounter == markerCounter)
        #expect(handled.value == 1)

        try await peer.send(stale)
        let staleAck = try await peer.nextSecured(session: rig.peerSession)
        #expect(staleAck.isStandaloneAck)
        #expect(staleAck.exchangeHeader.exchangeID == 0x4600)
        #expect(staleAck.exchangeHeader.acknowledgedMessageCounter == staleCounter)
        #expect(handled.value == 1, "an out-of-window message is never handled")
        #expect(await rig.messenger.activeExchangeCount == 0)
        #expect(await rig.messenger.manager.exchange(for: ExchangeKey(scope: .secured(localSessionID: 10), exchangeID: 0x4600, initiatedLocally: false)) == nil)
        await rig.messenger.stop()
    }

    @Test("A reply from a new source port moves the session's peer address")
    func peerAddressFollowsSender() async throws {
        let rig = await makeRig()
        var peer = TestPeer(link: rig.link)
        let moved = MatterAddress(host: "10.0.0.2", port: 6000)
        let exchange = try await rig.messenger.openExchange(sessionID: 10)

        async let reply = exchange.request(protocolID: .interactionModel, opcode: InteractionModelOpcode.readRequest.rawValue, payload: Data(), timeout: .seconds(5))
        let request = try await peer.nextSecured(session: rig.peerSession)
        try await peer.send(
            ScriptedPeer.securedReply(to: request, session: rig.peerSession, protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue),
            from: moved
        )
        #expect(try await reply.peerAddress == moved)
        #expect(await rig.messenger.peerAddress(forSession: 10) == moved)
        let next = try await rig.messenger.openExchange(sessionID: 10)
        #expect(next.peerAddress == moved)
        await rig.messenger.stop()
    }

    // MARK: - Unsolicited routing

    @Test("ReportData is routed by subscription ID; the StatusResponse piggybacks the ack; chunks follow on the exchange")
    func reportRoutedBySubscription() async throws {
        let rig = await makeRig()
        var peer = TestPeer(link: rig.link)
        let chunks = LockedValue<[Bool]>([])
        let returned = LockedValue(false)
        await rig.messenger.setSubscriptionHandler({ message, exchange in
            var current = message
            while let report = try? ReportData.fromTLV(current.payload) {
                chunks.withLock { $0.append(report.moreChunkedMessages) }
                try? await exchange.send(
                    protocolID: .interactionModel,
                    opcode: InteractionModelOpcode.statusResponse.rawValue,
                    payload: IMStatusResponse(status: 0).tlvEncode()
                )
                guard report.moreChunkedMessages, let next = try? await exchange.receive(timeout: .seconds(5)) else { break }
                current = next
            }
            returned.withLock { $0 = true }
        }, for: SubscriptionID(rawValue: 7))

        let chunk1 = try ScriptedPeer.secured(
            session: rig.peerSession, exchangeID: 0x4000, initiator: true,
            protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue,
            payload: ReportData(subscriptionID: SubscriptionID(rawValue: 7), moreChunkedMessages: true).tlvEncode()
        )
        let chunk1Counter = try MessageHeader.decode(from: chunk1).header.messageCounter
        try await peer.send(chunk1)
        let status1 = try await peer.nextSecured(session: rig.peerSession)
        #expect(status1.exchangeHeader.protocolOpcode == InteractionModelOpcode.statusResponse.rawValue)
        #expect(!status1.exchangeHeader.flags.initiator)
        #expect(status1.exchangeHeader.exchangeID == 0x4000)
        #expect(status1.exchangeHeader.acknowledgedMessageCounter == chunk1Counter)

        let chunk2 = try ScriptedPeer.secured(
            session: rig.peerSession, exchangeID: 0x4000, initiator: true,
            protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue,
            payload: ReportData(subscriptionID: SubscriptionID(rawValue: 7)).tlvEncode(),
            ack: status1.counter
        )
        let chunk2Counter = try MessageHeader.decode(from: chunk2).header.messageCounter
        try await peer.send(chunk2)
        let status2 = try await peer.nextSecured(session: rig.peerSession)
        #expect(status2.exchangeHeader.protocolOpcode == InteractionModelOpcode.statusResponse.rawValue)
        #expect(status2.exchangeHeader.acknowledgedMessageCounter == chunk2Counter)

        #expect(await eventually { returned.value })
        #expect(await eventually { await rig.messenger.activeExchangeCount == 0 })
        // status2 is not yet acknowledged: the exchange keeps it under MRP.
        #expect(await rig.messenger.closingExchangeCount == 1)
        #expect(chunks.value == [true, false])
        #expect(rig.link.sent(from: .a).count == 2, "both acks were piggybacked; closing owed nothing")
        await rig.messenger.stop()
    }

    @Test("A StatusResponse lost after the subscription handler returned is retransmitted until acked")
    func lostStatusResponseRetransmittedAfterHandlerReturned() async throws {
        let rig = await makeRig()
        let origin = rig.clock.now
        var peer = TestPeer(link: rig.link)
        let returned = LockedValue(false)
        await rig.messenger.setSubscriptionHandler({ _, exchange in
            try? await exchange.send(
                protocolID: .interactionModel,
                opcode: InteractionModelOpcode.statusResponse.rawValue,
                payload: IMStatusResponse(status: 0).tlvEncode()
            )
            returned.withLock { $0 = true }
        }, for: SubscriptionID(rawValue: 7))

        rig.link.dropNext(1, from: .a)                       // the StatusResponse
        try await peer.send(try ScriptedPeer.secured(
            session: rig.peerSession, exchangeID: 0x4700, initiator: true,
            protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue,
            payload: ReportData(subscriptionID: SubscriptionID(rawValue: 7)).tlvEncode()
        ))
        #expect(await eventually { returned.value })
        #expect(await eventually { await rig.messenger.closingExchangeCount == 1 })
        #expect(await rig.messenger.activeExchangeCount == 0)

        // The peer has just spoken: SAI spacing.
        #expect(await rig.clock.waitForSleeper(until: origin + activeInterval(1)))
        await rig.clock.advance(by: activeInterval(1))
        let retransmitted = try await peer.nextSecured(session: rig.peerSession)
        let lost = try ScriptedPeer.decodeSecured(rig.link.sent(from: .a)[0], session: rig.peerSession)
        #expect(retransmitted.exchangeHeader.protocolOpcode == InteractionModelOpcode.statusResponse.rawValue)
        #expect(retransmitted.exchangeHeader.exchangeID == 0x4700)
        #expect(retransmitted.counter == lost.counter)
        #expect(rig.link.sent(from: .a)[1] == rig.link.sent(from: .a)[0], "the same bytes, not a re-encoding")

        try await peer.send(try ScriptedPeer.secured(
            session: rig.peerSession, exchangeID: 0x4700, initiator: true,
            protocolID: .secureChannel, opcode: SecureChannelOpcode.standaloneAck.rawValue,
            ack: retransmitted.counter, reliable: false
        ))
        #expect(await eventually { await rig.messenger.closingExchangeCount == 0 })
        #expect(await rig.clock.waitForSleeper(until: rig.clock.now + ControllerMessenger.idleTimerHorizon))
        #expect(rig.clock.quiescenceTimeouts == 0)
        await rig.messenger.stop()
    }

    @Test("A report for an unknown subscription goes to the fallback handler and is acked when it returns")
    func unknownSubscriptionFallsBack() async throws {
        let rig = await makeRig()
        var peer = TestPeer(link: rig.link)
        let fallbackCalls = LockedValue(0)
        await rig.messenger.setUnsolicitedHandler { _, _ in
            fallbackCalls.withLock { $0 += 1 }
        }

        let report = try ScriptedPeer.secured(
            session: rig.peerSession, exchangeID: 0x4100, initiator: true,
            protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue,
            payload: ReportData(subscriptionID: SubscriptionID(rawValue: 9)).tlvEncode()
        )
        let reportCounter = try MessageHeader.decode(from: report).header.messageCounter
        try await peer.send(report)
        let ack = try await peer.nextSecured(session: rig.peerSession)
        #expect(ack.isStandaloneAck)
        #expect(ack.exchangeHeader.acknowledgedMessageCounter == reportCounter)
        #expect(fallbackCalls.value == 1)
        await rig.messenger.stop()
    }

    @Test("With no handler at all, an unsolicited message is acked and its exchange closed")
    func noHandlerAcksAndCloses() async throws {
        let rig = await makeRig()
        var peer = TestPeer(link: rig.link)
        let message = try ScriptedPeer.secured(
            session: rig.peerSession, exchangeID: 0x4200, initiator: true,
            protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue,
            payload: ReportData(subscriptionID: SubscriptionID(rawValue: 3)).tlvEncode()
        )
        try await peer.send(message)
        let ack = try await peer.nextSecured(session: rig.peerSession)
        #expect(ack.isStandaloneAck)
        #expect(await rig.messenger.activeExchangeCount == 0)
        await rig.messenger.stop()
    }

    @Test("A message for an unregistered session is dropped without a reply")
    func unknownSessionDropped() async throws {
        let rig = await makeRig()
        var peer = TestPeer(link: rig.link)
        let (_, stranger) = ScriptedPeer.mirroredSessions(controllerSessionID: 99, peerSessionID: 98)
        try await peer.send(try ScriptedPeer.secured(
            session: stranger, exchangeID: 1, initiator: true,
            protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue
        ))
        // The loop handles datagrams in order: once this one is acked, the stranger was processed.
        try await peer.send(try ScriptedPeer.secured(
            session: rig.peerSession, exchangeID: 2, initiator: true,
            protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue
        ))
        let ack = try await peer.nextSecured(session: rig.peerSession)
        #expect(ack.isStandaloneAck)
        #expect(ack.exchangeHeader.exchangeID == 2)
        #expect(rig.link.sent(from: .a).count == 1)
        await rig.messenger.stop()
    }

    // MARK: - Unregistering

    @Test("Unregistering a session fails its pending receives with .sessionClosed")
    func unregisterFailsReceives() async throws {
        let rig = await makeRig()
        let exchange = try await rig.messenger.openExchange(sessionID: 10)
        try await exchange.send(protocolID: .interactionModel, opcode: InteractionModelOpcode.readRequest.rawValue, payload: Data())
        let receiving = Task { try await exchange.receive(timeout: .seconds(5)) }
        #expect(await eventually { await rig.messenger.pendingReceiveCount == 1 })

        await rig.messenger.unregisterSession(localSessionID: 10)
        await #expect(throws: MessagingError.sessionClosed) { try await receiving.value }
        await #expect(throws: MessagingError.unknownSession(10)) { try await rig.messenger.openExchange(sessionID: 10) }
        #expect(await rig.messenger.peerAddress(forSession: 10) == nil)
        #expect(await rig.messenger.activeExchangeCount == 0)
        #expect(await rig.messenger.closingExchangeCount == 0)
        #expect(await rig.messenger.failed.isEmpty, "the waiter was told; nothing is left to report")
        await rig.messenger.stop()
    }

    @Test("Unregistering drops a closing exchange outright: no further retransmission, count never negative")
    func unregisterDropsClosingExchange() async throws {
        let rig = await makeRig()
        let origin = rig.clock.now
        var peer = TestPeer(link: rig.link)
        let exchange = try await rig.messenger.openExchange(sessionID: 10)
        try await exchange.send(protocolID: .interactionModel, opcode: InteractionModelOpcode.readRequest.rawValue, payload: Data())
        _ = try await peer.nextSecured(session: rig.peerSession)
        await exchange.close()
        #expect(await rig.messenger.closingExchangeCount == 1)
        #expect(await rig.messenger.activeExchangeCount == 0)
        // Armed for the retransmission (idle peer: never heard from).
        let retransmitAt = origin + MRPConfig(peer: testPeerParameters).retransmissionInterval(transmissionsSoFar: 1, peerActive: false, jitterUnit: 0)
        #expect(await rig.clock.waitForSleeper(until: retransmitAt))

        await rig.messenger.unregisterSession(localSessionID: 10)
        #expect(await rig.messenger.closingExchangeCount == 0)
        #expect(await rig.messenger.activeExchangeCount == 0)
        #expect(await rig.messenger.manager.count == 0)
        #expect(await rig.messenger.failed.isEmpty, "its owner already closed it; nothing to report")
        // The retransmission deadline is gone: only the idle timer remains.
        #expect(await rig.clock.waitForSleeper(until: origin + ControllerMessenger.idleTimerHorizon))
        #expect(rig.clock.sleeperCount == 1)
        await rig.clock.advance(by: retransmitAt - origin)
        #expect(await rig.clock.waitForSleepers(1))
        #expect(rig.link.sent(from: .a).count == 1)
        #expect(rig.clock.quiescenceTimeouts == 0)
        await rig.messenger.stop()
    }

    @Test("An initiator exchange with nothing waiting reports .sessionClosed on its next send and receive")
    func unregisterReportsToIdleInitiator() async throws {
        let rig = await makeRig()
        var peer = TestPeer(link: rig.link)
        let exchange = try await rig.messenger.openExchange(sessionID: 10)
        try await exchange.send(protocolID: .interactionModel, opcode: InteractionModelOpcode.readRequest.rawValue, payload: Data())
        _ = try await peer.nextSecured(session: rig.peerSession)

        await rig.messenger.unregisterSession(localSessionID: 10)
        #expect(await rig.messenger.activeExchangeCount == 0)
        #expect(await rig.messenger.closingExchangeCount == 0)
        await #expect(throws: MessagingError.sessionClosed) {
            try await exchange.send(protocolID: .interactionModel, opcode: InteractionModelOpcode.readRequest.rawValue, payload: Data())
        }
        await #expect(throws: MessagingError.sessionClosed) { try await exchange.receive(timeout: .seconds(5)) }
        await exchange.close()
        #expect(await rig.messenger.failed.isEmpty)
        #expect(rig.link.sent(from: .a).count == 1)
        #expect(rig.clock.quiescenceTimeouts == 0)
        await rig.messenger.stop()
    }

    @Test("Unregistering clears a responder exchange's queued messages and owed ack; its handler sees .sessionClosed")
    func unregisterClearsResponderState() async throws {
        let rig = await makeRig()
        var peer = TestPeer(link: rig.link)
        let (gate, release) = AsyncStream<Void>.makeStream()
        let handlerError = LockedValue<MessagingError?>(nil)
        let returned = LockedValue(false)
        await rig.messenger.setUnsolicitedHandler { _, exchange in
            for await _ in gate {}
            do {
                try await exchange.send(
                    protocolID: .interactionModel,
                    opcode: InteractionModelOpcode.statusResponse.rawValue,
                    payload: IMStatusResponse(status: 0).tlvEncode()
                )
            } catch let error as MessagingError {
                handlerError.withLock { $0 = error }
            } catch {}
            returned.withLock { $0 = true }
        }

        let first = try ScriptedPeer.secured(
            session: rig.peerSession, exchangeID: 0x4800, initiator: true,
            protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue,
            payload: ReportData(subscriptionID: SubscriptionID(rawValue: 3), moreChunkedMessages: true).tlvEncode()
        )
        let firstCounter = try MessageHeader.decode(from: first).header.messageCounter
        try await peer.send(first)
        // A second reliable message while the first's ack is owed: the first
        // is acked standalone at once, the second queued with its ack owed.
        try await peer.send(try ScriptedPeer.secured(
            session: rig.peerSession, exchangeID: 0x4800, initiator: true,
            protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue,
            payload: ReportData(subscriptionID: SubscriptionID(rawValue: 3)).tlvEncode()
        ))
        let firstAck = try await peer.nextSecured(session: rig.peerSession)
        #expect(firstAck.isStandaloneAck)
        #expect(firstAck.exchangeHeader.acknowledgedMessageCounter == firstCounter)
        let key = ExchangeKey(scope: .secured(localSessionID: 10), exchangeID: 0x4800, initiatedLocally: false)
        #expect(await rig.messenger.inbound[key]?.count == 1)
        #expect(await rig.messenger.responderKeys.contains(key))

        await rig.messenger.unregisterSession(localSessionID: 10)
        #expect(await rig.messenger.inbound.isEmpty)
        #expect(await rig.messenger.responderKeys.isEmpty)
        #expect(await rig.messenger.activeExchangeCount == 0)
        #expect(await rig.messenger.closingExchangeCount == 0)
        // The owed ack is dropped: no standalone-ack deadline, nothing sent past it.
        let origin = rig.clock.now
        #expect(await rig.clock.waitForSleeper(until: origin + ControllerMessenger.idleTimerHorizon))
        await rig.clock.advance(by: .seconds(1))
        #expect(await rig.clock.waitForSleepers(1))
        #expect(rig.link.sent(from: .a).count == 1)

        release.finish()
        #expect(await eventually { returned.value })
        #expect(handlerError.value == .sessionClosed)
        #expect(await eventually { await rig.messenger.failed.isEmpty }, "cleared when the handler's exchange closes")
        #expect(rig.clock.quiescenceTimeouts == 0)
        await rig.messenger.stop()
    }

    // MARK: - Idle responders

    @Test("A responder exchange left idle is closed after responderIdleTimeout")
    func responderIdleTimeout() async throws {
        let clock = ManualClock()
        let origin = clock.now
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: clock)
        let (controllerSession, peerSession) = ScriptedPeer.mirroredSessions(controllerSessionID: 10, peerSessionID: 20)
        await messenger.registerSession(controllerSession, peerAddress: link.b.address)
        var peer = TestPeer(link: link)

        // The handler answers, then stays busy without receiving: the
        // exchange is open but idle once its StatusResponse is acknowledged.
        let (gate, release) = AsyncStream<Void>.makeStream()
        await messenger.setUnsolicitedHandler { _, exchange in
            try? await exchange.send(
                protocolID: .interactionModel,
                opcode: InteractionModelOpcode.statusResponse.rawValue,
                payload: IMStatusResponse(status: 0).tlvEncode()
            )
            for await _ in gate {}
        }
        try await peer.send(try ScriptedPeer.secured(
            session: peerSession, exchangeID: 0x4400, initiator: true,
            protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue,
            payload: ReportData(subscriptionID: SubscriptionID(rawValue: 3)).tlvEncode()
        ))
        let status = try await peer.nextSecured(session: peerSession)
        try await peer.send(try ScriptedPeer.secured(
            session: peerSession, exchangeID: 0x4400, initiator: true,
            protocolID: .secureChannel, opcode: SecureChannelOpcode.standaloneAck.rawValue,
            ack: status.counter, reliable: false
        ))

        #expect(await clock.waitForSleeper(until: origin + .seconds(5)))
        #expect(await messenger.activeExchangeCount == 1)
        await clock.advance(by: .seconds(5))
        #expect(await messenger.activeExchangeCount == 0)
        release.finish()
        #expect(clock.quiescenceTimeouts == 0)
        await messenger.stop()
    }

    // MARK: - Re-registration

    @Test("Re-registering the same session keeps its counter window")
    func reregisterKeepsWindow() async throws {
        let rig = await makeRig()
        var peer = TestPeer(link: rig.link)
        let handled = LockedValue(0)
        await rig.messenger.setUnsolicitedHandler { _, _ in
            handled.withLock { $0 += 1 }
        }
        let first = try ScriptedPeer.secured(
            session: rig.peerSession, exchangeID: 0x4300, initiator: true,
            protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue
        )
        try await peer.send(first)
        let firstAck = try await peer.nextSecured(session: rig.peerSession)   // sent when the handler returns
        #expect(firstAck.isStandaloneAck)
        #expect(handled.value == 1)

        await rig.messenger.registerSession(rig.controllerSession, peerAddress: rig.link.b.address, mrp: testPeerParameters)
        try await peer.send(first)                                             // replay after re-registration
        let replayAck = try await peer.nextSecured(session: rig.peerSession)
        #expect(replayAck.isStandaloneAck)
        #expect(handled.value == 1, "the replay was recognised as a duplicate, not handled again")
        await rig.messenger.stop()
    }

    @Test("Re-registering the same session updates its address and MRP parameters")
    func reregisterUpdatesAddressAndMRP() async throws {
        let rig = await makeRig()
        let moved = MatterAddress(host: "10.0.0.3", port: 6001)
        let sleepy = MRPParameters(
            sessionIdleInterval: .milliseconds(5000),
            sessionActiveInterval: .milliseconds(300),
            sessionActiveThreshold: .milliseconds(4000)
        )
        await rig.messenger.registerSession(rig.controllerSession, peerAddress: moved, mrp: sleepy)
        #expect(await rig.messenger.peerAddress(forSession: 10) == moved)
        let exchange = try await rig.messenger.openExchange(sessionID: 10)
        #expect(exchange.peerAddress == moved)
        #expect(await rig.messenger.manager.exchange(for: exchange.key)?.config.peer == sleepy)
        await rig.messenger.stop()
    }

    @Test("Registering a different session under a registered ID first closes the old session's exchanges")
    func registerReplacementSessionClosesOld() async throws {
        let rig = await makeRig()
        let exchange = try await rig.messenger.openExchange(sessionID: 10)
        let receiving = Task { try await exchange.receive(timeout: .seconds(5)) }
        #expect(await eventually { await rig.messenger.pendingReceiveCount == 1 })

        let (replacement, replacementPeer) = ScriptedPeer.mirroredSessions(controllerSessionID: 10, peerSessionID: 21)
        await rig.messenger.registerSession(replacement, peerAddress: rig.link.b.address)
        await #expect(throws: MessagingError.sessionClosed) { try await receiving.value }
        #expect(await rig.messenger.activeExchangeCount == 0)

        // The replacement is live, with its own counter window.
        var peer = TestPeer(link: rig.link)
        try await peer.send(try ScriptedPeer.secured(
            session: replacementPeer, exchangeID: 0x4900, initiator: true,
            protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue
        ))
        let ack = try await peer.nextSecured(session: replacementPeer)
        #expect(ack.isStandaloneAck)
        #expect(ack.messageHeader.sessionID == 21)
        await rig.messenger.stop()
    }
}
