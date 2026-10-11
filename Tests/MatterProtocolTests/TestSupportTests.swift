// TestSupportTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterProtocol
import MatterTransport
import MatterTestSupport

@Suite("MatterTestSupport", .timeLimit(.minutes(1)))
struct TestSupportTests {

    // MARK: - ManualClock

    @Test("advance steps through each deadline and returns once the sleeper has re-armed")
    func advanceQuiesces() async throws {
        let clock = ManualClock()
        let origin = clock.now
        let wakes = LockedValue<[Duration]>([])
        let ticker = Task {
            var deadline = origin + .milliseconds(100)
            while true {
                try await clock.sleep(until: deadline)
                wakes.withLock { $0.append(clock.now - origin) }
                deadline = deadline + .milliseconds(100)
            }
        }
        await clock.waitForSleepers(1)

        await clock.advance(by: .milliseconds(350))
        #expect(wakes.value == [.milliseconds(100), .milliseconds(200), .milliseconds(300)])
        #expect(clock.now == origin + .milliseconds(350))
        #expect(clock.nextSleeperDeadline == origin + .milliseconds(400))
        #expect(await clock.waitForSleeper(until: origin + .milliseconds(400)))

        ticker.cancel()
        await #expect(throws: CancellationError.self) { try await ticker.value }
        #expect(clock.sleeperCount == 0)
    }

    @Test("A deadline already reached returns at once; a cancelled sleep throws and leaves no sleeper")
    func pastDeadlineAndCancellation() async throws {
        let clock = ManualClock()
        try await clock.sleep(until: clock.now)
        #expect(clock.sleeperCount == 0)

        let sleeping = Task { try await clock.sleep(until: clock.now + .seconds(1)) }
        await clock.waitForSleepers(1)
        sleeping.cancel()
        await #expect(throws: CancellationError.self) { try await sleeping.value }
        #expect(clock.sleeperCount == 0)
    }

    // MARK: - SeededJitter

    @Test("Seeded jitter repeats per seed and stays in 0..<1")
    func seededJitter() {
        let first = SeededJitter(seed: 9)
        let second = SeededJitter(seed: 9)
        let a = (0..<20).map { _ in first() }
        let b = (0..<20).map { _ in second() }
        #expect(a == b)
        #expect(a.allSatisfy { $0 >= 0 && $0 < 1 })
        #expect(Set(a).count > 1)
    }

    // MARK: - FaultInjectingLink

    @Test("A seeded link drops the same datagrams on every run")
    func seededDropsAreReproducible() async throws {
        func survivors(seed: UInt64) async throws -> [UInt8] {
            let link = FaultInjectingLink(seed: seed)
            link.setDropProbability(0.3, from: .a)
            for value in 0..<50 {
                try await link.a.send(Data([UInt8(value)]), to: link.b.address)
            }
            #expect(link.sent(from: .a).count == 50)
            await link.b.close()
            var received: [UInt8] = []
            for await (data, sender) in link.b.receive() {
                #expect(sender == link.a.address)
                received.append(data[data.startIndex])
            }
            return received
        }
        let first = try await survivors(seed: 42)
        let second = try await survivors(seed: 42)
        #expect(first == second)
        #expect(first.count > 0 && first.count < 50)
    }

    @Test("dropNext drops exactly the next datagrams from that side")
    func dropNext() async throws {
        let link = FaultInjectingLink(seed: 1)
        link.dropNext(2, from: .a)
        for value: UInt8 in [1, 2, 3] {
            try await link.a.send(Data([value]), to: link.b.address)
        }
        try await link.b.send(Data([9]), to: link.a.address)
        #expect(link.deliveredCount(to: .b) == 1)
        #expect(link.deliveredCount(to: .a) == 1)
        var inbox = link.b.receive().makeAsyncIterator()
        let delivered = await inbox.next()
        #expect(delivered?.0 == Data([3]))
    }

    @Test("Interceptor delays and duplicates are delivered by the injected clock")
    func interceptorDelayUsesClock() async throws {
        let clock = ManualClock()
        let link = FaultInjectingLink(seed: 1, clock: clock)
        link.setInterceptor { _, _ in .deliver(after: .milliseconds(100)) }
        try await link.a.send(Data([7]), to: link.b.address)
        #expect(link.deliveredCount(to: .b) == 0)

        await clock.advance(by: .milliseconds(99))
        #expect(link.deliveredCount(to: .b) == 0)
        await clock.advance(by: .milliseconds(1))
        #expect(link.deliveredCount(to: .b) == 1)

        link.setInterceptor { _, _ in .duplicate(after: .milliseconds(50)) }
        try await link.a.send(Data([7]), to: link.b.address)
        #expect(link.deliveredCount(to: .b) == 2)
        await clock.advance(by: .milliseconds(50))
        #expect(link.deliveredCount(to: .b) == 3)

        var inbox = link.b.receive().makeAsyncIterator()
        let firstCopy = await inbox.next()
        let secondCopy = await inbox.next()
        #expect(firstCopy?.0 == Data([7]))
        #expect(secondCopy?.0 == Data([7]))
    }

    @Test("A spoofed source is what the receiver sees")
    func spoofedSource() async throws {
        let link = FaultInjectingLink(seed: 1)
        let moved = MatterAddress(host: "10.0.0.2", port: 6000)
        try await link.b.send(Data([1]), to: link.a.address, from: moved)
        var inbox = link.a.receive().makeAsyncIterator()
        let received = await inbox.next()
        #expect(received?.1 == moved)
    }

    // MARK: - ScriptedPeer

    @Test("Mirrored sessions decrypt each other's frames; replies flip I and piggyback the ack")
    func mirroredSessions() throws {
        let (controller, peer) = ScriptedPeer.mirroredSessions(controllerSessionID: 10, peerSessionID: 20)
        let request = try ScriptedPeer.secured(
            session: controller, exchangeID: 5, initiator: true,
            protocolID: .interactionModel, opcode: InteractionModelOpcode.readRequest.rawValue,
            payload: Data([1, 2])
        )
        let frame = try ScriptedPeer.decodeSecured(request, session: peer)
        #expect(frame.messageHeader.sessionID == 20)
        #expect(frame.payload == Data([1, 2]))
        #expect(frame.exchangeHeader.flags.initiator)

        let reply = try ScriptedPeer.securedReply(
            to: frame, session: peer,
            protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue
        )
        let replyFrame = try ScriptedPeer.decodeSecured(reply, session: controller)
        #expect(replyFrame.messageHeader.sessionID == 10)
        #expect(!replyFrame.exchangeHeader.flags.initiator)
        #expect(replyFrame.exchangeHeader.acknowledgedMessageCounter == frame.counter)

        let unsecured = ScriptedPeer.unsecured(exchangeID: 3, initiator: true, protocolID: .echo, opcode: 1, counter: 77)
        let ack = ScriptedPeer.unsecuredAck(for: try ScriptedPeer.decodeUnsecured(unsecured), counter: 78)
        let ackFrame = try ScriptedPeer.decodeUnsecured(ack)
        #expect(ackFrame.isStandaloneAck)
        #expect(ackFrame.exchangeHeader.acknowledgedMessageCounter == 77)
        #expect(!ackFrame.exchangeHeader.flags.reliableDelivery)
    }
}
