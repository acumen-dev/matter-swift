// TestSupportTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterProtocol
import MatterTransport
import MatterTestSupport

@Suite("MatterTestSupport", .timeLimit(.minutes(5)))
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
        #expect(clock.quiescenceTimeouts == 0)
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

    @Test("Cancellation before the sleep is reached is remembered and never counts")
    func cancelBeforeRegistration() async throws {
        let clock = ManualClock()
        let gate = LockedValue(false)
        let task = Task {
            while !gate.value { await Task.yield() }
            try await clock.sleep(until: clock.now + .seconds(1))
        }
        task.cancel()
        gate.withLock { $0 = true }
        await #expect(throws: CancellationError.self) { try await task.value }
        #expect(clock.sleeperCount == 0)
    }

    @Test("A woken sleeper that does not re-arm is counted and costs little")
    func nonRearmingSleeperTimesOut() async throws {
        let clock = ManualClock(quiescenceYieldLimit: 200)
        let once = Task { try await clock.sleep(until: clock.now + .milliseconds(10)) }
        #expect(await clock.waitForSleepers(1))
        await clock.advance(by: .milliseconds(10))
        try await once.value
        #expect(clock.quiescenceTimeouts == 1)
    }

    @Test("Same-deadline scheduled actions run in registration order and all same-deadline sleepers wake")
    func sameDeadlineOrder() async throws {
        // Sleepers are resumed in registration order, but where each woken
        // task then runs is up to the executor, so only the synchronous
        // scheduled actions can assert order deterministically.
        // These sleepers do not re-arm, so advance times out: keep the bound small.
        let clock = ManualClock(quiescenceYieldLimit: 200)
        let deadline = clock.now + .milliseconds(10)
        let order = LockedValue<[Int]>([])
        for index in 0..<8 {
            clock.schedule(at: deadline) { order.withLock { $0.append(index) } }
        }
        let woken = LockedValue(0)
        var tasks: [Task<Void, any Error>] = []
        for index in 0..<8 {
            tasks.append(Task {
                try await clock.sleep(until: deadline)
                woken.withLock { $0 += 1 }
            })
            await clock.waitForSleepers(index + 1)
        }
        await clock.advance(by: .milliseconds(10))
        for task in tasks { try await task.value }
        #expect(order.value == Array(0..<8))
        #expect(woken.value == 8)
    }

    @Test("awaitSleepers / awaitSleeper return once a sleeper registers, and at once if one already has")
    func awaitSleeperRegistration() async throws {
        let clock = ManualClock(quiescenceYieldLimit: 0)
        let deadline = clock.now + .seconds(5)
        let waiter = Task {
            try await clock.awaitSleeper(until: deadline)
            try await clock.awaitSleepers(atLeast: 1)
        }
        let sleeper = Task { try await clock.sleep(until: deadline) }
        try await waiter.value
        #expect(clock.sleeperCount == 1)
        try await clock.awaitSleeper(until: deadline)

        await clock.advance(by: .seconds(5))
        try await sleeper.value
        #expect(clock.sleeperCount == 0)
    }

    @Test("A sleeper that fires or is cancelled no longer satisfies awaitSleeper")
    func awaitSleeperForgetsEndedSleepers() async throws {
        let clock = ManualClock(quiescenceYieldLimit: 0)
        let first = clock.now + .seconds(1)

        // Cancelled: once its task has ended, nothing of it is left.
        let cancelled = Task { try await clock.sleep(until: first) }
        try await clock.awaitSleeper(until: first)
        cancelled.cancel()
        await #expect(throws: CancellationError.self) { try await cancelled.value }
        #expect(clock.sleeperCount == 0)
        #expect(clock.nextSleeperDeadline == nil)

        // A waiter for `first` must now suspend; a stale entry would let it
        // return at once. Whichever happens is observed, not raced.
        let returned = LockedValue(false)
        let waiter = Task {
            try await clock.awaitSleeper(until: first)
            returned.withLock { $0 = true }
        }
        try await pollUntil(every: .milliseconds(1)) { clock.sleeperWaiterCount == 1 || returned.value }
        #expect(!returned.value, "awaitSleeper returned for a sleeper that had ended")
        let again = Task { try await clock.sleep(until: first) }
        try await waiter.value

        // Fired: likewise gone once advance has woken it.
        await clock.advance(by: .seconds(1))
        try await again.value
        #expect(clock.sleeperCount == 0)
        #expect(clock.nextSleeperDeadline == nil)
    }

    // MARK: - LockedValue

    @Test("wait(until:) returns when a later update satisfies the predicate, at once when it already holds")
    func lockedValueWait() async throws {
        let value = LockedValue(0)
        let waiter = Task { try await value.wait { $0 >= 3 } }
        for _ in 0..<3 { value.withLock { $0 += 1 } }
        try await waiter.value
        try await value.wait { $0 == 3 }
    }

    @Test("A cancelled wait(until:) throws CancellationError, before or after it registers")
    func lockedValueWaitCancellation() async throws {
        let value = LockedValue(false)
        let early = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            try await value.wait { $0 }
        }
        await #expect(throws: CancellationError.self) { try await early.value }

        let late = Task { try await value.wait { $0 } }
        late.cancel()
        await #expect(throws: CancellationError.self) { try await late.value }
    }

    // MARK: - InMemoryDiscovery

    @Test("waitForActiveBrowse returns once a browse stream is open")
    func waitForActiveBrowse() async throws {
        let discovery = InMemoryDiscovery { _ in nil }
        let waiter = Task { try await discovery.waitForActiveBrowse() }
        let browse = Task {
            for await _ in discovery.browse(serviceType: .commissionable) {}
        }
        try await waiter.value
        #expect(discovery.activeBrowseCount == 1)
        browse.cancel()
        await browse.value
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
        #expect(clock.quiescenceTimeouts == 0)
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
