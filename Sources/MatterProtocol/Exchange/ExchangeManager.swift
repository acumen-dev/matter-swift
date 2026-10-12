// ExchangeManager.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterTransport

// MARK: - Identity

/// The session an exchange runs in: the unsecured session with one peer
/// address, or a secure session named by *our* (local) session ID — the ID
/// the peer puts in the message header.
public enum SessionScope: Hashable, Sendable {
    case unsecured(peer: MatterAddress)
    case secured(localSessionID: UInt16)
}

/// Identity of an exchange (Matter Core §4.10.5.1): session, exchange ID and
/// which side initiated it. Both sides may use the same exchange ID for
/// different exchanges, so the initiator flag is part of the identity.
public struct ExchangeKey: Hashable, Sendable {
    public let scope: SessionScope
    public let exchangeID: UInt16
    /// True when this node initiated the exchange.
    public let initiatedLocally: Bool

    public init(scope: SessionScope, exchangeID: UInt16, initiatedLocally: Bool) {
        self.scope = scope
        self.exchangeID = exchangeID
        self.initiatedLocally = initiatedLocally
    }

    /// The key of the exchange an inbound message belongs to. A message with
    /// the I flag set came from the exchange's initiator, so the exchange
    /// was initiated remotely.
    public init(scope: SessionScope, inbound: ExchangeHeader) {
        self.init(scope: scope, exchangeID: inbound.exchangeID, initiatedLocally: !inbound.flags.initiator)
    }
}

/// Errors from ``ExchangeManager``.
public enum ExchangeError: Error, Sendable, Equatable {
    /// The exchange is not open.
    case unknownExchange(ExchangeKey)
}

// MARK: - Exchange

/// MRP state of one exchange. Values are snapshots; ``ExchangeManager`` owns
/// the live state.
public struct Exchange: Sendable, Identifiable {
    public var id: ExchangeKey { key }
    public let key: ExchangeKey
    /// Address the exchange was opened with.
    public var peerAddress: MatterAddress
    public let config: MRPConfig

    /// Encoded bytes of the unacknowledged reliable message, resent verbatim.
    public private(set) var pendingMessage: Data?
    /// Message counter of ``pendingMessage``; only an ack for this counter clears it.
    public private(set) var pendingMessageCounter: UInt32?
    /// Transmissions of ``pendingMessage`` so far, including the first.
    public private(set) var transmissions: Int = 0
    public private(set) var nextRetransmitAt: ContinuousClock.Instant?

    /// Counter of a received reliable message not yet acknowledged.
    public private(set) var pendingAckCounter: UInt32?
    public private(set) var standaloneAckDeadline: ContinuousClock.Instant?

    /// Last send, retransmission or reliable receipt.
    public private(set) var lastActivityAt: ContinuousClock.Instant

    /// Nothing to retransmit and no ack owed.
    public var isIdle: Bool { pendingMessage == nil && pendingAckCounter == nil }

    init(key: ExchangeKey, peerAddress: MatterAddress, config: MRPConfig, now: ContinuousClock.Instant) {
        self.key = key
        self.peerAddress = peerAddress
        self.config = config
        self.lastActivityAt = now
    }

    mutating func startTransmission(_ message: Data, counter: UInt32, firstInterval: Duration, now: ContinuousClock.Instant) {
        pendingMessage = message
        pendingMessageCounter = counter
        transmissions = 1
        nextRetransmitAt = now + firstInterval
        lastActivityAt = now
    }

    mutating func noteRetransmission(nextInterval: Duration, now: ContinuousClock.Instant) {
        transmissions += 1
        nextRetransmitAt = now + nextInterval
        lastActivityAt = now
    }

    mutating func clearPendingMessage() {
        pendingMessage = nil
        pendingMessageCounter = nil
        nextRetransmitAt = nil
    }

    mutating func setPendingAck(_ counter: UInt32, deadline: ContinuousClock.Instant, now: ContinuousClock.Instant) {
        pendingAckCounter = counter
        standaloneAckDeadline = deadline
        lastActivityAt = now
    }

    mutating func clearPendingAck() {
        pendingAckCounter = nil
        standaloneAckDeadline = nil
    }
}

// MARK: - ExchangeManager

/// MRP bookkeeping for every open exchange, shared by the controller and the
/// device server. Pure state: it performs no I/O and never reads a clock —
/// callers pass `now` and send whatever it says is due.
public struct ExchangeManager: Sendable {

    /// Configuration for exchanges opened without one.
    public let defaultConfig: MRPConfig

    private let jitterSource: @Sendable () -> Double
    private var exchanges: [ExchangeKey: Exchange] = [:]
    private var lastReceived: [SessionScope: ContinuousClock.Instant] = [:]
    private var nextExchangeID: UInt16

    /// - Parameters:
    ///   - defaultConfig: configuration for exchanges opened without one.
    ///   - jitterSource: the `u` in the backoff formula, in `0..<1`.
    public init(
        defaultConfig: MRPConfig = .default,
        jitterSource: @escaping @Sendable () -> Double = { .random(in: 0..<1) }
    ) {
        self.defaultConfig = defaultConfig
        self.jitterSource = jitterSource
        self.nextExchangeID = UInt16.random(in: 0...UInt16.max)
    }

    // MARK: Lifecycle

    /// Next exchange ID for a locally initiated exchange, skipping IDs still
    /// held by one (in any scope). Starts at a random value.
    public mutating func allocateExchangeID() -> UInt16 {
        var candidate = nextExchangeID
        while exchanges.keys.contains(where: { $0.initiatedLocally && $0.exchangeID == candidate }) {
            candidate &+= 1
        }
        nextExchangeID = candidate &+ 1
        return candidate
    }

    /// Open an exchange; returns the existing one unchanged if already open.
    @discardableResult
    public mutating func open(
        _ key: ExchangeKey,
        peerAddress: MatterAddress,
        config: MRPConfig? = nil,
        now: ContinuousClock.Instant
    ) -> Exchange {
        if let existing = exchanges[key] {
            return existing
        }
        let exchange = Exchange(key: key, peerAddress: peerAddress, config: config ?? defaultConfig, now: now)
        exchanges[key] = exchange
        return exchange
    }

    public func exchange(for key: ExchangeKey) -> Exchange? {
        exchanges[key]
    }

    public func exchanges(in scope: SessionScope) -> [Exchange] {
        exchanges.values.filter { $0.key.scope == scope }
    }

    /// Remove an exchange, cancelling its retransmission. Returns its final
    /// state (callers flush ``Exchange/pendingAckCounter``).
    @discardableResult
    public mutating func close(_ key: ExchangeKey) -> Exchange? {
        exchanges.removeValue(forKey: key)
    }

    /// Remove every exchange of a session and forget the session's activity.
    public mutating func closeAll(in scope: SessionScope) -> [Exchange] {
        lastReceived.removeValue(forKey: scope)
        let keys = exchanges.keys.filter { $0.scope == scope }
        return keys.compactMap { exchanges.removeValue(forKey: $0) }
    }

    public var count: Int {
        exchanges.count
    }

    // MARK: Peer activity

    /// Note that a message arrived in `scope` (drives SAI vs SII).
    public mutating func recordReceived(scope: SessionScope, now: ContinuousClock.Instant) {
        lastReceived[scope] = now
    }

    /// Whether a message arrived in `scope` less than the default
    /// configuration's `sessionActiveThreshold` ago.
    public func isPeerActive(scope: SessionScope, now: ContinuousClock.Instant) -> Bool {
        isPeerActive(scope: scope, threshold: defaultConfig.peer.sessionActiveThreshold, now: now)
    }

    private func isPeerActive(scope: SessionScope, threshold: Duration, now: ContinuousClock.Instant) -> Bool {
        guard let last = lastReceived[scope] else { return false }
        return now - last < threshold
    }

    // MARK: Acknowledgements

    /// Apply an inbound ack. Clears the pending retransmission only if
    /// `ackedCounter` is the pending message's counter.
    /// - Returns: whether it acknowledged the pending message.
    @discardableResult
    public mutating func recordAcknowledgment(_ key: ExchangeKey, ackedCounter: UInt32) -> Bool {
        guard var exchange = exchanges[key], exchange.pendingMessageCounter == ackedCounter else {
            return false
        }
        exchange.clearPendingMessage()
        exchanges[key] = exchange
        return true
    }

    /// Note a received reliable message: an ack is owed, due standalone after
    /// `standaloneAckTimeout` unless a message piggybacks it first.
    public mutating func recordReliableReceipt(_ key: ExchangeKey, counter: UInt32, now: ContinuousClock.Instant) {
        guard var exchange = exchanges[key] else { return }
        exchange.setPendingAck(counter, deadline: now + exchange.config.standaloneAckTimeout, now: now)
        exchanges[key] = exchange
    }

    /// Take the owed ack counter (to piggyback or send), clearing its deadline.
    public mutating func takePendingAck(_ key: ExchangeKey) -> UInt32? {
        guard var exchange = exchanges[key], let counter = exchange.pendingAckCounter else {
            return nil
        }
        exchange.clearPendingAck()
        exchanges[key] = exchange
        return counter
    }

    /// Note that the owed ack went out as a standalone ack.
    public mutating func recordStandaloneAckSent(_ key: ExchangeKey) {
        guard var exchange = exchanges[key] else { return }
        exchange.clearPendingAck()
        exchanges[key] = exchange
    }

    // MARK: Retransmission

    /// Track a reliable message just sent. Its counter is read from the
    /// plaintext message header; the bytes are resent verbatim (same counter)
    /// so the peer can de-duplicate.
    public mutating func trackTransmission(_ key: ExchangeKey, message: Data, now: ContinuousClock.Instant) throws {
        guard var exchange = exchanges[key] else {
            throw ExchangeError.unknownExchange(key)
        }
        let (header, _) = try MessageHeader.decode(from: message)
        let interval = exchange.config.retransmissionInterval(
            transmissionsSoFar: 1,
            peerActive: isPeerActive(scope: key.scope, threshold: exchange.config.peer.sessionActiveThreshold, now: now),
            jitterUnit: jitterSource()
        )
        exchange.startTransmission(message, counter: header.messageCounter, firstInterval: interval, now: now)
        exchanges[key] = exchange
    }

    /// Earliest retransmission or standalone-ack deadline, if any.
    public func nextDeadline() -> ContinuousClock.Instant? {
        exchanges.values
            .flatMap { [$0.nextRetransmitAt, $0.standaloneAckDeadline].compactMap { $0 } }
            .min()
    }

    /// What to do for one exchange whose retransmission deadline has passed.
    public enum RetransmitDecision: Sendable, Equatable {
        /// Resend these bytes (same counter) to this address. Already counted
        /// in ``Exchange/transmissions``; the next deadline is scheduled.
        case send(Data, to: MatterAddress, nextDeadline: ContinuousClock.Instant)
        /// `maxRetransmissions` retransmissions went unacknowledged for a full
        /// interval each: the exchange has been removed and nothing is sent.
        case exhausted
    }

    /// Decide, for every exchange whose retransmission is due, earliest
    /// first: exhaust it if `transmissions > maxRetransmissions` (decide
    /// first — the last copy has had its full ack window), otherwise count
    /// one more transmission and schedule the next deadline.
    public mutating func processDueRetransmissions(now: ContinuousClock.Instant) -> [(ExchangeKey, RetransmitDecision)] {
        let due = exchanges.values
            .filter { exchange in exchange.nextRetransmitAt.map { $0 <= now } ?? false }
            .sorted { ($0.nextRetransmitAt ?? now) < ($1.nextRetransmitAt ?? now) }
        var decisions: [(ExchangeKey, RetransmitDecision)] = []
        for var exchange in due {
            guard let message = exchange.pendingMessage else { continue }
            if exchange.transmissions > exchange.config.maxRetransmissions {
                exchanges.removeValue(forKey: exchange.key)
                decisions.append((exchange.key, .exhausted))
                continue
            }
            let interval = exchange.config.retransmissionInterval(
                transmissionsSoFar: exchange.transmissions + 1,
                peerActive: isPeerActive(scope: exchange.key.scope, threshold: exchange.config.peer.sessionActiveThreshold, now: now),
                jitterUnit: jitterSource()
            )
            exchange.noteRetransmission(nextInterval: interval, now: now)
            exchanges[exchange.key] = exchange
            decisions.append((exchange.key, .send(message, to: exchange.peerAddress, nextDeadline: now + interval)))
        }
        return decisions
    }

    // MARK: Standalone acks and idleness

    /// Exchanges whose owed ack has waited `standaloneAckTimeout`.
    public func dueStandaloneAcks(now: ContinuousClock.Instant) -> [Exchange] {
        exchanges.values.filter { exchange in exchange.standaloneAckDeadline.map { $0 <= now } ?? false }
    }

    /// Exchanges with nothing pending whose last activity is at least `olderThan` ago.
    public func idleExchanges(olderThan age: Duration, now: ContinuousClock.Instant) -> [Exchange] {
        exchanges.values.filter { $0.isIdle && now - $0.lastActivityAt >= age }
    }
}
