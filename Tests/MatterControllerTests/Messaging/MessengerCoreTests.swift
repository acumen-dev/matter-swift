// MessengerCoreTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterProtocol
import MatterTransport
import MatterTestSupport
@testable import MatterController

@Suite("ControllerMessenger core", .timeLimit(.minutes(1)))
struct MessengerCoreTests {

    @Test("A request is answered on its own exchange")
    func requestResponse() async throws {
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: ManualClock())
        var peer = TestPeer(link: link)
        let exchange = await messenger.openExchange(peer: link.b.address)

        async let reply = exchange.request(protocolID: .echo, opcode: echoRequest, payload: Data([1, 2, 3]), timeout: .seconds(5))
        let request = try await peer.next()
        #expect(request.exchangeHeader.flags.initiator)
        #expect(request.exchangeHeader.flags.reliableDelivery)
        #expect(request.exchangeHeader.exchangeID == exchange.key.exchangeID)
        #expect(request.exchangeHeader.acknowledgedMessageCounter == nil)
        #expect(request.payload == Data([1, 2, 3]))

        try await peer.send(ScriptedPeer.unsecuredReply(to: request, protocolID: .echo, opcode: echoResponse, payload: Data([9]), counter: 1000))
        let message = try await reply
        #expect(message.key == exchange.key)
        #expect(message.opcode == echoResponse)
        #expect(message.payload == Data([9]))
        #expect(message.messageCounter == 1000)
        #expect(message.acknowledgedCounter == request.counter)
        #expect(message.requiresAck)
        #expect(message.peerAddress == link.b.address)

        await exchange.close()
        await messenger.stop()
    }

    @Test("Owed acks ride on the next request; close() flushes the last one at once")
    func piggybackAndCloseFlush() async throws {
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: ManualClock())
        var peer = TestPeer(link: link)
        let exchange = await messenger.openExchange(peer: link.b.address)

        var lastReplyCounter: UInt32?
        for round in 0..<3 {
            async let reply = exchange.request(protocolID: .echo, opcode: echoRequest, payload: Data([UInt8(round)]), timeout: .seconds(5))
            let request = try await peer.next()
            #expect(request.exchangeHeader.acknowledgedMessageCounter == lastReplyCounter)
            let counter = UInt32(500 + round)
            try await peer.send(ScriptedPeer.unsecuredReply(to: request, protocolID: .echo, opcode: echoResponse, counter: counter))
            _ = try await reply
            lastReplyCounter = counter
        }
        #expect(link.sent(from: .a).count == 3)

        await exchange.close()
        let ack = try await peer.next()
        #expect(ack.isStandaloneAck)
        #expect(ack.exchangeHeader.acknowledgedMessageCounter == lastReplyCounter)
        #expect(ack.exchangeHeader.exchangeID == exchange.key.exchangeID)
        #expect(link.sent(from: .a).count == 4)
        #expect(await messenger.activeExchangeCount == 0)
        await messenger.stop()
    }

    @Test("A reply to a closed exchange is acked and never reaches a later exchange")
    func staleReplyIsNotDelivered() async throws {
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: ManualClock())
        var peer = TestPeer(link: link)

        let first = await messenger.openExchange(peer: link.b.address)
        try await first.send(protocolID: .echo, opcode: echoRequest, payload: Data([1]))
        let firstRequest = try await peer.next()
        await first.close()

        try await peer.send(ScriptedPeer.unsecuredReply(to: firstRequest, protocolID: .echo, opcode: echoResponse, payload: Data([0xEE]), counter: 700))
        let staleAck = try await peer.next()
        #expect(staleAck.isStandaloneAck)
        #expect(staleAck.exchangeHeader.acknowledgedMessageCounter == 700)
        #expect(staleAck.exchangeHeader.exchangeID == firstRequest.exchangeHeader.exchangeID)

        let second = await messenger.openExchange(peer: link.b.address)
        async let reply = second.request(protocolID: .echo, opcode: echoRequest, payload: Data([2]), timeout: .seconds(5))
        let secondRequest = try await peer.next()
        try await peer.send(ScriptedPeer.unsecuredReply(to: secondRequest, protocolID: .echo, opcode: echoResponse, payload: Data([0x22]), counter: 701))
        #expect(try await reply.payload == Data([0x22]))
        #expect(await messenger.activeExchangeCount == 1)
        await messenger.stop()
    }

    @Test("An I=0 message for an unknown exchange is acked and creates nothing")
    func responderMessageNeverCreatesExchange() async throws {
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: ManualClock())
        var peer = TestPeer(link: link)
        await messenger.start()

        try await peer.send(ScriptedPeer.unsecured(exchangeID: 0x7777, initiator: false, protocolID: .echo, opcode: echoResponse, counter: 900))
        let ack = try await peer.next()
        #expect(ack.isStandaloneAck)
        #expect(ack.exchangeHeader.acknowledgedMessageCounter == 900)
        #expect(ack.exchangeHeader.flags.initiator)
        #expect(await messenger.activeExchangeCount == 0)
        await messenger.stop()
    }

    @Test("Six concurrent requests to two peers each get their own reply, whatever the reply order")
    func concurrentRequestsShuffledReplies() async throws {
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: ManualClock())
        var peer = TestPeer(link: link)
        let peers = [link.b.address, MatterAddress(host: "10.0.0.3", port: 5540)]

        var exchanges: [ControllerExchange] = []
        for index in 0..<6 {
            exchanges.append(await messenger.openExchange(peer: peers[index % 2]))
        }
        let peerByExchangeID = Dictionary(uniqueKeysWithValues: exchanges.map { ($0.key.exchangeID, $0.peerAddress) })

        try await withThrowingTaskGroup(of: (Int, InboundMessage).self) { group in
            for (index, exchange) in exchanges.enumerated() {
                group.addTask {
                    let reply = try await exchange.request(protocolID: .echo, opcode: echoRequest, payload: Data([UInt8(index)]), timeout: .seconds(5))
                    return (index, reply)
                }
            }

            var requests: [PeerFrame] = []
            for _ in 0..<6 {
                requests.append(try await peer.next())
            }
            var counters: [MatterAddress: UInt32] = [peers[0]: 100, peers[1]: 100]
            for position in [3, 0, 5, 1, 4, 2] {
                let request = requests[position]
                let source = try #require(peerByExchangeID[request.exchangeHeader.exchangeID])
                let counter = try #require(counters[source]) + 1
                counters[source] = counter
                try await peer.send(
                    ScriptedPeer.unsecuredReply(to: request, protocolID: .echo, opcode: echoResponse, payload: request.payload, counter: counter),
                    from: source
                )
            }

            for try await (index, reply) in group {
                #expect(reply.payload == Data([UInt8(index)]))
                #expect(reply.peerAddress == peers[index % 2])
                #expect(reply.key == exchanges[index].key)
            }
        }
        #expect(await messenger.activeExchangeCount == 6)
        await messenger.stop()
    }

    @Test("A duplicate is acked again and not delivered")
    func duplicateIsAckedAndDropped() async throws {
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: ManualClock())
        var peer = TestPeer(link: link)
        let exchange = await messenger.openExchange(peer: link.b.address)

        async let first = exchange.request(protocolID: .echo, opcode: echoRequest, payload: Data(), timeout: .seconds(5))
        let request = try await peer.next()
        let reply = ScriptedPeer.unsecuredReply(to: request, protocolID: .echo, opcode: echoResponse, payload: Data([1]), counter: 50)
        try await peer.send(reply)
        #expect(try await first.payload == Data([1]))

        try await peer.send(reply)
        let ack = try await peer.next()
        #expect(ack.isStandaloneAck)
        #expect(ack.exchangeHeader.acknowledgedMessageCounter == 50)

        // The next distinct message is the next thing delivered: the duplicate was not queued.
        try await peer.send(ScriptedPeer.unsecured(
            exchangeID: request.exchangeHeader.exchangeID, initiator: false,
            protocolID: .echo, opcode: echoResponse, payload: Data([2]), counter: 51
        ))
        #expect(try await exchange.receive(timeout: .seconds(5)).payload == Data([2]))
        await messenger.stop()
    }

    @Test("Cancelling a receive closes the exchange and leaves no waiter")
    func cancellationClosesExchange() async throws {
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: ManualClock())
        let exchange = await messenger.openExchange(peer: link.b.address)
        try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data())

        let receiving = Task { try await exchange.receive(timeout: .seconds(5)) }
        #expect(await eventually { await messenger.pendingReceiveCount == 1 })
        receiving.cancel()
        await #expect(throws: CancellationError.self) { try await receiving.value }
        #expect(await eventually { await messenger.activeExchangeCount == 0 })
        #expect(await messenger.pendingReceiveCount == 0)
        await #expect(throws: MessagingError.exchangeClosed) {
            try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data())
        }
        await messenger.stop()
    }

    @Test("A second concurrent receive on one exchange is refused")
    func receiveAlreadyPending() async throws {
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: ManualClock())
        let exchange = await messenger.openExchange(peer: link.b.address)
        let receiving = Task { try await exchange.receive(timeout: .seconds(5)) }
        #expect(await eventually { await messenger.pendingReceiveCount == 1 })
        await #expect(throws: MessagingError.receiveAlreadyPending) {
            try await exchange.receive(timeout: .seconds(5))
        }
        await exchange.close()
        await #expect(throws: MessagingError.exchangeClosed) { try await receiving.value }
        await messenger.stop()
    }

    @Test("stop() fails pending receives and later sends with .stopped")
    func stopFailsPendingReceives() async throws {
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: ManualClock())
        let exchange = await messenger.openExchange(peer: link.b.address)

        let receiving = Task { try await exchange.receive(timeout: .seconds(5)) }
        #expect(await eventually { await messenger.pendingReceiveCount == 1 })
        await messenger.stop()
        await #expect(throws: MessagingError.stopped) { try await receiving.value }
        await #expect(throws: MessagingError.stopped) {
            try await exchange.send(protocolID: .echo, opcode: echoRequest, payload: Data())
        }
    }

    // MARK: - Address Forms

    /// The transports report a sender in `inet_ntop`'s canonical form; an
    /// exchange opened with any other text for the same address must still
    /// receive its reply (it used to be dropped as stale on Linux, where
    /// discovery wrote IPv6 hosts uncompressed).
    @Test(
        "An exchange opened with non-canonical IP text receives the reply from the canonical sender",
        arguments: [
            ("0:0:0:0:0:0:0:1", "::1"),
            ("[0:0:0:0:0:0:0:1]", "::1"),
            ("FD00:0000::0005", "fd00::5"),
            ("[fd00::5]", "fd00::5"),
        ]
    )
    func nonCanonicalPeerReceivesReply(opened: String, sender: String) async throws {
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: ManualClock())
        var peer = TestPeer(link: link)
        let canonical = MatterAddress(host: sender, port: 5540)
        let exchange = await messenger.openExchange(peer: MatterAddress(host: opened, port: 5540))
        #expect(exchange.peerAddress == canonical)

        async let reply = exchange.request(protocolID: .echo, opcode: echoRequest, payload: Data([1]), timeout: .seconds(5))
        let request = try await peer.next()
        #expect(link.sent(from: .a, to: canonical).count == 1)
        try await peer.send(
            ScriptedPeer.unsecuredReply(to: request, protocolID: .echo, opcode: echoResponse, payload: Data([9]), counter: 1000),
            from: canonical
        )
        // Hang guard: a dropped reply never resolves `reply` (it is acked as
        // stale instead); the suite's time limit ends the test.
        let message = try await reply
        #expect(message.key == exchange.key)
        #expect(message.payload == Data([9]))
        #expect(message.peerAddress == canonical)

        await exchange.close()
        await messenger.stop()
    }

    @Test("A datagram from a non-canonical sender text is matched to the exchange opened with the canonical one")
    func nonCanonicalSenderIsMatched() async throws {
        let link = FaultInjectingLink(seed: 1)
        let messenger = makeMessenger(link: link, clock: ManualClock())
        var peer = TestPeer(link: link)
        let exchange = await messenger.openExchange(peer: MatterAddress(host: "fd00::5", port: 5540))

        async let reply = exchange.request(protocolID: .echo, opcode: echoRequest, payload: Data([1]), timeout: .seconds(5))
        let request = try await peer.next()
        try await peer.send(
            ScriptedPeer.unsecuredReply(to: request, protocolID: .echo, opcode: echoResponse, payload: Data([9]), counter: 1000),
            from: MatterAddress(host: "FD00:0:0:0:0:0:0:0005", port: 5540)
        )
        let message = try await reply
        #expect(message.peerAddress == MatterAddress(host: "fd00::5", port: 5540))

        await exchange.close()
        await messenger.stop()
    }
}
