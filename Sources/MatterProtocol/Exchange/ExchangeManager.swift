// ExchangeManager.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

/// Manages Matter message exchanges — request/response pairs with
/// reliable delivery via MRP.
///
/// Each exchange tracks its state (initiator/responder), pending ACKs,
/// and retransmission schedule.
public actor ExchangeManager {
    /// Active exchanges keyed by exchange ID.
    private var exchanges: [UInt16: Exchange] = [:]

    /// Next exchange ID to allocate.
    private var nextExchangeID: UInt16 = 1

    /// MRP configuration.
    public let mrpConfig: MRPConfig

    /// Callback for sending raw messages.
    private let sendHandler: @Sendable (Data, MatterAddress) async throws -> Void

    public init(
        mrpConfig: MRPConfig = .default,
        sendHandler: @escaping @Sendable (Data, MatterAddress) async throws -> Void
    ) {
        self.mrpConfig = mrpConfig
        self.sendHandler = sendHandler
    }

    // MARK: - Exchange Lifecycle

    /// Create a new exchange as initiator.
    public func createExchange(peerAddress: MatterAddress) -> Exchange {
        let id = allocateExchangeID()
        let exchange = Exchange(
            exchangeID: id,
            role: .initiator,
            peerAddress: peerAddress,
            mrpConfig: mrpConfig
        )
        exchanges[id] = exchange
        return exchange
    }

    /// Get or create an exchange for an incoming message.
    public func exchangeForIncoming(
        exchangeID: UInt16,
        isInitiator: Bool,
        peerAddress: MatterAddress
    ) -> Exchange {
        if let existing = exchanges[exchangeID] {
            return existing
        }
        // Create responder exchange for new incoming initiator message
        let exchange = Exchange(
            exchangeID: exchangeID,
            role: .responder,
            peerAddress: peerAddress,
            mrpConfig: mrpConfig
        )
        exchanges[exchangeID] = exchange
        return exchange
    }

    /// Track a sent message for MRP retransmission on an exchange.
    ///
    /// Creates the exchange if it doesn't exist, then stores the raw message bytes
    /// and schedules the first retransmission attempt.
    public func trackMessage(
        exchangeID: UInt16,
        message: Data,
        peerAddress: MatterAddress,
        now: Date = Date()
    ) {
        if exchanges[exchangeID] == nil {
            exchanges[exchangeID] = Exchange(
                exchangeID: exchangeID,
                role: .responder,
                peerAddress: peerAddress,
                mrpConfig: mrpConfig
            )
        }
        exchanges[exchangeID]?.markPendingRetransmission(message: message, now: now)
    }

    /// Close and remove an exchange.
    public func closeExchange(_ exchangeID: UInt16) {
        exchanges.removeValue(forKey: exchangeID)
    }

    /// Get an exchange by ID.
    public func exchange(for id: UInt16) -> Exchange? {
        exchanges[id]
    }

    /// Number of active exchanges.
    public var activeExchangeCount: Int {
        exchanges.count
    }

    // MARK: - Retransmission

    /// Get all exchanges with pending retransmissions that are due.
    public func pendingRetransmissions(now: Date = Date()) -> [Exchange] {
        exchanges.values.filter { exchange in
            guard let nextRetry = exchange.nextRetransmitTime else { return false }
            return nextRetry <= now
        }
    }

    /// Update an exchange after a retransmission attempt.
    public func recordRetransmission(exchangeID: UInt16, now: Date = Date()) {
        guard var exchange = exchanges[exchangeID] else { return }
        exchange.recordRetransmission(now: now)

        if exchange.isRetransmissionExhausted {
            exchanges.removeValue(forKey: exchangeID)
        } else {
            exchanges[exchangeID] = exchange
        }
    }

    /// Record that an ACK was received for an exchange.
    public func recordAcknowledgment(exchangeID: UInt16) {
        guard var exchange = exchanges[exchangeID] else { return }
        exchange.clearPendingRetransmission()
        exchanges[exchangeID] = exchange
    }

    // MARK: - Standalone ACKs

    /// Get exchanges that need a standalone ACK sent.
    public func pendingStandaloneAcks(now: Date = Date()) -> [Exchange] {
        exchanges.values.filter { exchange in
            guard let ackDeadline = exchange.standaloneAckDeadline else { return false }
            return ackDeadline <= now
        }
    }

    /// Record that a standalone ACK was sent for an exchange.
    public func recordStandaloneAckSent(exchangeID: UInt16) {
        guard var exchange = exchanges[exchangeID] else { return }
        exchange.clearPendingAck()
        exchanges[exchangeID] = exchange
    }

    // MARK: - Private

    private func allocateExchangeID() -> UInt16 {
        let id = nextExchangeID
        nextExchangeID &+= 1
        return id
    }
}

// MARK: - Exchange

/// State for a single Matter exchange (request/response pair).
public struct Exchange: Sendable, Identifiable {
    public let id: UInt16

    /// The exchange ID on the wire.
    public let exchangeID: UInt16

    /// Whether we initiated this exchange.
    public let role: Role

    /// Peer network address.
    public let peerAddress: MatterAddress

    /// MRP config for this exchange.
    public let mrpConfig: MRPConfig

    // MARK: - Retransmission State

    /// The last message sent that needs acknowledgment.
    public var pendingMessage: Data?

    /// Number of retransmission attempts made.
    public var retransmitCount: Int = 0

    /// When the next retransmission should be attempted.
    public var nextRetransmitTime: Date?

    // MARK: - ACK State

    /// Counter of the last reliable message received (needs ACK).
    public var pendingAckCounter: UInt32?

    /// Deadline for sending a standalone ACK.
    public var standaloneAckDeadline: Date?

    public init(
        exchangeID: UInt16,
        role: Role,
        peerAddress: MatterAddress,
        mrpConfig: MRPConfig
    ) {
        self.id = exchangeID
        self.exchangeID = exchangeID
        self.role = role
        self.peerAddress = peerAddress
        self.mrpConfig = mrpConfig
    }

    /// Whether retransmissions have been exhausted.
    public var isRetransmissionExhausted: Bool {
        retransmitCount >= mrpConfig.maxRetransmissions
    }

    /// Record that a message was sent and needs acknowledgment.
    public mutating func markPendingRetransmission(message: Data, now: Date = Date()) {
        pendingMessage = message
        retransmitCount = 0
        let interval = mrpConfig.retryInterval(attempt: 0)
        nextRetransmitTime = now.addingTimeInterval(interval.timeInterval)
    }

    /// Record a retransmission attempt.
    public mutating func recordRetransmission(now: Date = Date()) {
        retransmitCount += 1
        let interval = mrpConfig.retryInterval(attempt: retransmitCount)
        nextRetransmitTime = now.addingTimeInterval(interval.timeInterval)
    }

    /// Clear pending retransmission (ACK received).
    public mutating func clearPendingRetransmission() {
        pendingMessage = nil
        retransmitCount = 0
        nextRetransmitTime = nil
    }

    /// Record that a reliable message was received and needs ACK.
    public mutating func markPendingAck(counter: UInt32, now: Date = Date()) {
        pendingAckCounter = counter
        standaloneAckDeadline = now.addingTimeInterval(mrpConfig.standaloneAckTimeout.timeInterval)
    }

    /// Clear pending ACK (piggybacked or standalone ACK sent).
    public mutating func clearPendingAck() {
        pendingAckCounter = nil
        standaloneAckDeadline = nil
    }

    /// Exchange role.
    public enum Role: Sendable, Equatable {
        case initiator
        case responder
    }
}

import MatterTransport
