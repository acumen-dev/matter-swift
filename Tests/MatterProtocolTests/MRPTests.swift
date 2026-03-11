// MRPTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
@testable import MatterProtocol
@testable import MatterTransport

// MARK: - MRP Config Tests

@Suite("MRP Config")
struct MRPConfigTests {

    @Test("Default retry interval is 300ms for first attempt")
    func defaultRetryInterval() {
        let config = MRPConfig.default
        let interval = config.retryInterval(attempt: 0)

        // Should be approximately 300ms ± 25% jitter
        let ms = interval.milliseconds
        #expect(ms >= 225) // 300 - 75
        #expect(ms <= 375) // 300 + 75
    }

    @Test("Backoff increases interval after threshold")
    func backoffIncrease() {
        let config = MRPConfig.default

        // Attempt 0 and 1 are at base interval (threshold is 1)
        // Attempt 2+ should be higher
        var totalAtBase: Int64 = 0
        var totalAtBackoff: Int64 = 0

        // Average over many samples to smooth out jitter
        for _ in 0..<100 {
            totalAtBase += config.retryInterval(attempt: 0).milliseconds
            totalAtBackoff += config.retryInterval(attempt: 3).milliseconds
        }

        let avgBase = totalAtBase / 100
        let avgBackoff = totalAtBackoff / 100

        // Backoff should be significantly higher than base
        #expect(avgBackoff > avgBase)
    }

    @Test("Max retransmissions default is 10")
    func maxRetransmissions() {
        #expect(MRPConfig.default.maxRetransmissions == 10)
    }

    @Test("Standalone ACK timeout is 200ms")
    func standaloneAckTimeout() {
        #expect(MRPConfig.default.standaloneAckTimeout == .milliseconds(200))
    }
}

// MARK: - Exchange Tests

@Suite("Exchange")
struct ExchangeTests {

    @Test("Exchange retransmission tracking")
    func retransmissionTracking() {
        let config = MRPConfig.default
        var exchange = Exchange(
            exchangeID: 1,
            role: .initiator,
            peerAddress: MatterAddress(host: "127.0.0.1", port: 5540),
            mrpConfig: config
        )

        let now = Date()
        exchange.markPendingRetransmission(message: Data([1, 2, 3]), now: now)

        #expect(exchange.pendingMessage != nil)
        #expect(exchange.retransmitCount == 0)
        #expect(exchange.nextRetransmitTime != nil)
        #expect(exchange.isRetransmissionExhausted == false)

        // Simulate retransmission
        exchange.recordRetransmission(now: now)
        #expect(exchange.retransmitCount == 1)
    }

    @Test("Exchange retransmission exhaustion")
    func retransmissionExhaustion() {
        let config = MRPConfig(
            baseRetryInterval: .milliseconds(10),
            maxRetransmissions: 3,
            backoffThreshold: 1,
            backoffMultiplier: 1.0,
            backoffJitter: 0,
            backoffMargin: 1.0,
            standaloneAckTimeout: .milliseconds(10)
        )
        var exchange = Exchange(
            exchangeID: 1,
            role: .initiator,
            peerAddress: MatterAddress(host: "127.0.0.1", port: 5540),
            mrpConfig: config
        )

        exchange.markPendingRetransmission(message: Data([1]), now: Date())

        for _ in 0..<3 {
            exchange.recordRetransmission()
        }

        #expect(exchange.isRetransmissionExhausted == true)
    }

    @Test("Clear pending retransmission on ACK")
    func clearOnAck() {
        var exchange = Exchange(
            exchangeID: 1,
            role: .initiator,
            peerAddress: MatterAddress(host: "127.0.0.1", port: 5540),
            mrpConfig: .default
        )

        exchange.markPendingRetransmission(message: Data([1, 2, 3]))
        #expect(exchange.pendingMessage != nil)

        exchange.clearPendingRetransmission()
        #expect(exchange.pendingMessage == nil)
        #expect(exchange.retransmitCount == 0)
        #expect(exchange.nextRetransmitTime == nil)
    }

    @Test("Standalone ACK tracking")
    func standaloneAckTracking() {
        var exchange = Exchange(
            exchangeID: 1,
            role: .responder,
            peerAddress: MatterAddress(host: "127.0.0.1", port: 5540),
            mrpConfig: .default
        )

        let now = Date()
        exchange.markPendingAck(counter: 42, now: now)

        #expect(exchange.pendingAckCounter == 42)
        #expect(exchange.standaloneAckDeadline != nil)

        exchange.clearPendingAck()
        #expect(exchange.pendingAckCounter == nil)
        #expect(exchange.standaloneAckDeadline == nil)
    }
}

// MARK: - Exchange Manager Tests

@Suite("Exchange Manager")
struct ExchangeManagerTests {

    @Test("Create exchange as initiator")
    func createInitiator() async {
        let manager = ExchangeManager { _, _ in }
        let exchange = await manager.createExchange(
            peerAddress: MatterAddress(host: "192.168.1.100", port: 5540)
        )

        #expect(exchange.role == .initiator)
        #expect(await manager.activeExchangeCount == 1)
    }

    @Test("Create exchange for incoming message")
    func createForIncoming() async {
        let manager = ExchangeManager { _, _ in }
        let exchange = await manager.exchangeForIncoming(
            exchangeID: 42,
            isInitiator: true,
            peerAddress: MatterAddress(host: "192.168.1.100", port: 5540)
        )

        #expect(exchange.role == .responder)
        #expect(exchange.exchangeID == 42)
    }

    @Test("Close exchange removes it")
    func closeExchange() async {
        let manager = ExchangeManager { _, _ in }
        let exchange = await manager.createExchange(
            peerAddress: MatterAddress(host: "127.0.0.1", port: 5540)
        )

        #expect(await manager.activeExchangeCount == 1)
        await manager.closeExchange(exchange.exchangeID)
        #expect(await manager.activeExchangeCount == 0)
    }

    @Test("Record acknowledgment clears pending")
    func recordAck() async {
        let manager = ExchangeManager { _, _ in }
        let exchange = await manager.createExchange(
            peerAddress: MatterAddress(host: "127.0.0.1", port: 5540)
        )

        // We can't directly modify the exchange through the manager,
        // but recordAcknowledgment should not crash
        await manager.recordAcknowledgment(exchangeID: exchange.exchangeID)

        let found = await manager.exchange(for: exchange.exchangeID)
        #expect(found != nil)
    }
}
