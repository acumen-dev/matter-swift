// MRPTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
@testable import MatterProtocol
import MatterTransport

private let peer = MatterAddress(host: "192.168.1.50", port: 5540)

private let fiveHundredIdle = MRPParameters(
    sessionIdleInterval: .milliseconds(500),
    sessionActiveInterval: .milliseconds(300),
    sessionActiveThreshold: .milliseconds(4000)
)

// MARK: - MRPParameters

@Suite("MRP parameters")
struct MRPParametersTests {

    @Test("Spec defaults: SII 500 ms, SAI 300 ms, SAT 4000 ms")
    func defaults() {
        let parameters = MRPParameters.default
        #expect(parameters.sessionIdleInterval == .milliseconds(500))
        #expect(parameters.sessionActiveInterval == .milliseconds(300))
        #expect(parameters.sessionActiveThreshold == .milliseconds(4000))
        #expect(MRPParameters() == .default)
    }

    @Test("TXT records SII, SAI and SAT are milliseconds")
    func parsesTXT() {
        let parameters = MRPParameters(txtRecords: ["SII": "5000", "SAI": "300", "SAT": "1000", "T": "0"])
        #expect(parameters.sessionIdleInterval == .milliseconds(5000))
        #expect(parameters.sessionActiveInterval == .milliseconds(300))
        #expect(parameters.sessionActiveThreshold == .milliseconds(1000))
    }

    @Test("Missing, garbage and out-of-range TXT values fall back per key")
    func txtFallbacks() {
        let garbage = MRPParameters(txtRecords: ["SII": "abc", "SAI": "3600001", "SAT": "-5"])
        #expect(garbage == .default)

        let empty = MRPParameters(txtRecords: [:])
        #expect(empty == .default)

        let limit = MRPParameters(txtRecords: ["SII": "3600000"])
        #expect(limit.sessionIdleInterval == .milliseconds(3_600_000))
        #expect(limit.sessionActiveInterval == .milliseconds(300))
    }

    @Test("Parameters round-trip through Codable")
    func codable() throws {
        let data = try JSONEncoder().encode(fiveHundredIdle)
        #expect(try JSONDecoder().decode(MRPParameters.self, from: data) == fiveHundredIdle)
    }
}

// MARK: - Backoff

@Suite("MRP backoff")
struct MRPBackoffTests {

    let config = MRPConfig(peer: fiveHundredIdle)

    @Test("Idle peer: the first interval is SII × 1.1")
    func idleUsesSII() {
        #expect(config.retransmissionInterval(transmissionsSoFar: 1, peerActive: false, jitterUnit: 0) == .milliseconds(550))
    }

    @Test("Active peer: the first interval is SAI × 1.1")
    func activeUsesSAI() {
        #expect(config.retransmissionInterval(transmissionsSoFar: 1, peerActive: true, jitterUnit: 0) == .milliseconds(330))
    }

    @Test("Each further transmission multiplies the interval by 1.6")
    func backoffSchedule() {
        let intervals = (1...5).map {
            config.retransmissionInterval(transmissionsSoFar: $0, peerActive: false, jitterUnit: 0)
        }
        #expect(intervals == [
            .milliseconds(550),
            .milliseconds(880),
            .milliseconds(1408),
            .microseconds(2_252_800),
            .microseconds(3_604_480),
        ])
    }

    @Test("Jitter unit 1 adds the full 25 %")
    func fullJitter() {
        #expect(config.retransmissionInterval(transmissionsSoFar: 1, peerActive: false, jitterUnit: 1) == .microseconds(687_500))
    }

    @Test("The exhaustion horizon is the sum of all five intervals at full jitter")
    func exhaustionHorizon() {
        #expect(config.exhaustionHorizon(peerActive: false) == .microseconds(10_869_100))
        #expect(config.exhaustionHorizon(peerActive: true) == .microseconds(6_521_460))
        let summed = (1...5).reduce(Duration.zero) {
            $0 + config.retransmissionInterval(transmissionsSoFar: $1, peerActive: false, jitterUnit: 1)
        }
        #expect(config.exhaustionHorizon(peerActive: false) == summed)
    }

    @Test("Defaults are the spec's: 4 retransmissions, 200 ms standalone ack, default peer")
    func specDefaults() {
        let config = MRPConfig.default
        #expect(config.maxRetransmissions == 4)
        #expect(config.backoffThreshold == 1)
        #expect(config.backoffBase == 1.6)
        #expect(config.backoffJitter == 0.25)
        #expect(config.backoffMargin == 1.1)
        #expect(config.standaloneAckTimeout == .milliseconds(200))
        #expect(config.peer == .default)
    }
}

// MARK: - Exchange manager

@Suite("Exchange manager")
struct ExchangeManagerTests {

    let t0 = ContinuousClock.now
    let key = ExchangeKey(scope: .unsecured(peer: peer), exchangeID: 7, initiatedLocally: true)

    func makeManager() -> ExchangeManager {
        ExchangeManager(defaultConfig: MRPConfig(peer: fiveHundredIdle), jitterSource: { 0 })
    }

    func message(counter: UInt32) -> Data {
        MatterMessage.encodeUnsecured(
            messageHeader: MessageHeader(sessionID: 0, messageCounter: counter),
            exchangeHeader: ExchangeHeader(
                flags: ExchangeFlags(initiator: true, reliableDelivery: true),
                protocolOpcode: 0x01,
                exchangeID: 7,
                protocolID: MatterProtocolID.echo.rawValue
            ),
            payload: Data([0xAA])
        )
    }

    @Test("The same exchange ID is a different exchange per scope and initiator")
    func keyIdentity() {
        var manager = makeManager()
        let responder = ExchangeKey(scope: .unsecured(peer: peer), exchangeID: 7, initiatedLocally: false)
        let secured = ExchangeKey(scope: .secured(localSessionID: 7), exchangeID: 7, initiatedLocally: true)
        manager.open(key, peerAddress: peer, now: t0)
        manager.open(responder, peerAddress: peer, now: t0)
        manager.open(secured, peerAddress: peer, now: t0)
        #expect(manager.count == 3)

        manager.close(responder)
        #expect(manager.exchange(for: key) != nil)
        #expect(manager.exchange(for: secured) != nil)
        #expect(manager.exchange(for: responder) == nil)
    }

    @Test("An inbound header's initiator flag is flipped into initiatedLocally")
    func inboundKey() {
        let fromResponder = ExchangeHeader(flags: ExchangeFlags(initiator: false), protocolOpcode: 1, exchangeID: 9, protocolID: 0)
        let fromInitiator = ExchangeHeader(flags: ExchangeFlags(initiator: true), protocolOpcode: 1, exchangeID: 9, protocolID: 0)
        #expect(ExchangeKey(scope: .secured(localSessionID: 3), inbound: fromResponder).initiatedLocally)
        #expect(!ExchangeKey(scope: .secured(localSessionID: 3), inbound: fromInitiator).initiatedLocally)
    }

    @Test("open is idempotent")
    func openIdempotent() throws {
        var manager = makeManager()
        manager.open(key, peerAddress: peer, now: t0)
        try manager.trackTransmission(key, message: message(counter: 41), now: t0)
        let again = manager.open(key, peerAddress: peer, now: t0 + .seconds(1))
        #expect(again.pendingMessageCounter == 41)
        #expect(manager.count == 1)
    }

    @Test("trackTransmission reads the counter from the plaintext header and needs an open exchange")
    func trackReadsCounter() throws {
        var manager = makeManager()
        #expect(throws: ExchangeError.unknownExchange(key)) {
            try manager.trackTransmission(key, message: message(counter: 41), now: t0)
        }
        manager.open(key, peerAddress: peer, now: t0)
        try manager.trackTransmission(key, message: message(counter: 41), now: t0)
        let exchange = try #require(manager.exchange(for: key))
        #expect(exchange.pendingMessageCounter == 41)
        #expect(exchange.pendingMessage == message(counter: 41))
        #expect(exchange.transmissions == 1)
        #expect(exchange.nextRetransmitAt == t0 + .milliseconds(550))
    }

    @Test("An ack for another counter is ignored; the matching one clears the retransmission")
    func ackMatchesCounter() throws {
        var manager = makeManager()
        manager.open(key, peerAddress: peer, now: t0)
        try manager.trackTransmission(key, message: message(counter: 41), now: t0)

        let wrongAck = manager.recordAcknowledgment(key, ackedCounter: 40)
        #expect(wrongAck == false)
        #expect(manager.exchange(for: key)?.pendingMessage != nil)

        let rightAck = manager.recordAcknowledgment(key, ackedCounter: 41)
        #expect(rightAck)
        #expect(manager.exchange(for: key)?.pendingMessage == nil)
        #expect(manager.exchange(for: key)?.nextRetransmitAt == nil)
        #expect(manager.nextDeadline() == nil)
    }

    @Test("processDueRetransmissions yields four sends, then exhausts after the fifth interval")
    func exhaustion() throws {
        var manager = makeManager()
        manager.open(key, peerAddress: peer, now: t0)
        try manager.trackTransmission(key, message: message(counter: 41), now: t0)

        let waits: [Duration] = [
            .milliseconds(550), .milliseconds(880), .milliseconds(1408),
            .microseconds(2_252_800), .microseconds(3_604_480),
        ]
        var now = t0
        for retransmission in 1...4 {
            now = now + waits[retransmission - 1]
            let decisions = manager.processDueRetransmissions(now: now)
            #expect(decisions.map(\.0) == [key])
            #expect(decisions.first?.1 == .send(message(counter: 41), to: peer, nextDeadline: now + waits[retransmission]))
        }
        #expect(manager.exchange(for: key)?.transmissions == 5)

        now = now + waits[4]
        #expect(now == t0 + .microseconds(8_695_280))
        let early = manager.processDueRetransmissions(now: now - .nanoseconds(1))
        #expect(early.isEmpty)
        let final = manager.processDueRetransmissions(now: now)
        #expect(final.map(\.0) == [key])
        #expect(final.first?.1 == .exhausted)
        #expect(manager.exchange(for: key) == nil)
    }

    @Test("A peer heard from within SAT is active; SAI then sets the interval")
    func peerActivity() throws {
        var manager = makeManager()
        manager.recordReceived(scope: key.scope, now: t0)
        #expect(manager.isPeerActive(scope: key.scope, now: t0 + .milliseconds(3999)))
        #expect(!manager.isPeerActive(scope: key.scope, now: t0 + .milliseconds(4000)))
        #expect(!manager.isPeerActive(scope: .secured(localSessionID: 1), now: t0))

        manager.open(key, peerAddress: peer, now: t0)
        try manager.trackTransmission(key, message: message(counter: 41), now: t0 + .milliseconds(100))
        #expect(manager.exchange(for: key)?.nextRetransmitAt == t0 + .milliseconds(430))
    }

    @Test("A reliable receipt owes an ack due in 200 ms; takePendingAck hands it over once")
    func pendingAck() throws {
        var manager = makeManager()
        manager.open(key, peerAddress: peer, now: t0)
        manager.recordReliableReceipt(key, counter: 99, now: t0)
        #expect(manager.exchange(for: key)?.standaloneAckDeadline == t0 + .milliseconds(200))
        #expect(manager.exchange(for: key)?.isIdle == false)
        #expect(manager.dueStandaloneAcks(now: t0 + .milliseconds(199)).isEmpty)
        #expect(manager.dueStandaloneAcks(now: t0 + .milliseconds(200)).map(\.key) == [key])

        let taken = manager.takePendingAck(key)
        let takenAgain = manager.takePendingAck(key)
        #expect(taken == 99)
        #expect(takenAgain == nil)
        #expect(manager.exchange(for: key)?.standaloneAckDeadline == nil)
        #expect(manager.exchange(for: key)?.isIdle == true)
    }

    @Test("recordStandaloneAckSent clears the owed ack")
    func standaloneAckSent() {
        var manager = makeManager()
        manager.open(key, peerAddress: peer, now: t0)
        manager.recordReliableReceipt(key, counter: 5, now: t0)
        manager.recordStandaloneAckSent(key)
        #expect(manager.exchange(for: key)?.pendingAckCounter == nil)
        #expect(manager.nextDeadline() == nil)
    }

    @Test("nextDeadline is the earliest retransmission or ack deadline")
    func nextDeadline() throws {
        var manager = makeManager()
        let other = ExchangeKey(scope: .unsecured(peer: peer), exchangeID: 8, initiatedLocally: false)
        manager.open(key, peerAddress: peer, now: t0)
        manager.open(other, peerAddress: peer, now: t0)
        try manager.trackTransmission(key, message: message(counter: 41), now: t0)
        manager.recordReliableReceipt(other, counter: 3, now: t0 + .milliseconds(100))
        #expect(manager.nextDeadline() == t0 + .milliseconds(300))

        _ = manager.takePendingAck(other)
        #expect(manager.nextDeadline() == t0 + .milliseconds(550))
    }

    @Test("allocateExchangeID skips IDs held by locally initiated exchanges")
    func allocationSkipsLiveIDs() {
        var manager = makeManager()
        let first = manager.allocateExchangeID()
        manager.open(ExchangeKey(scope: .unsecured(peer: peer), exchangeID: first &+ 1, initiatedLocally: true), peerAddress: peer, now: t0)
        manager.open(ExchangeKey(scope: .unsecured(peer: peer), exchangeID: first &+ 2, initiatedLocally: false), peerAddress: peer, now: t0)
        let second = manager.allocateExchangeID()
        #expect(second == first &+ 2)
    }

    @Test("idleExchanges lists exchanges with nothing pending past the age")
    func idleExchanges() throws {
        var manager = makeManager()
        let busy = ExchangeKey(scope: .unsecured(peer: peer), exchangeID: 8, initiatedLocally: true)
        manager.open(key, peerAddress: peer, now: t0)
        manager.open(busy, peerAddress: peer, now: t0)
        try manager.trackTransmission(busy, message: message(counter: 41), now: t0)
        #expect(manager.idleExchanges(olderThan: .seconds(5), now: t0 + .milliseconds(4999)).isEmpty)
        #expect(manager.idleExchanges(olderThan: .seconds(5), now: t0 + .seconds(5)).map(\.key) == [key])
    }

    @Test("closeAll(in:) removes only that scope")
    func closeAllInScope() {
        var manager = makeManager()
        let secured = ExchangeKey(scope: .secured(localSessionID: 4), exchangeID: 1, initiatedLocally: true)
        manager.open(key, peerAddress: peer, now: t0)
        manager.open(secured, peerAddress: peer, now: t0)
        let closed = manager.closeAll(in: .secured(localSessionID: 4))
        #expect(closed.map(\.key) == [secured])
        #expect(manager.exchanges(in: .unsecured(peer: peer)).map(\.key) == [key])
        #expect(manager.count == 1)
    }
}

// MARK: - Counter deduplication verdicts

@Suite("Counter deduplication verdicts")
struct CounterDeduplicationVerdictTests {

    @Test("Encrypted: duplicate, late-but-new within the window, and below the window")
    func encrypted() {
        var dedup = CounterDeduplication(encrypted: true)
        #expect(dedup.check(100) == .accepted)
        #expect(dedup.check(100) == .duplicate)
        #expect(dedup.check(98) == .accepted)
        #expect(dedup.check(98) == .duplicate)
        #expect(dedup.check(101) == .accepted)
        #expect(dedup.check(60) == .outOfWindow)
    }

    @Test("Unencrypted: below the window is a peer reboot and is accepted")
    func unencrypted() {
        var dedup = CounterDeduplication(encrypted: false)
        #expect(dedup.check(100) == .accepted)
        #expect(dedup.check(5) == .accepted)
        #expect(dedup.check(5) == .duplicate)
    }

    @Test("accept(_:) is check(_:) == .accepted")
    func acceptAgrees() {
        var viaAccept = CounterDeduplication(encrypted: true)
        var viaCheck = CounterDeduplication(encrypted: true)
        for counter: UInt32 in [10, 20, 10, 15, 15, 1000, 1] {
            #expect(viaAccept.accept(counter) == (viaCheck.check(counter) == .accepted))
        }
    }
}
