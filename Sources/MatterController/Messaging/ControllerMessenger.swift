// ControllerMessenger.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Logging
import Metrics
import Tracing
import MatterTypes
import MatterCrypto
import MatterProtocol
import MatterTransport

/// The controller's message layer: the single consumer of the UDP transport.
///
/// One receive loop decodes every datagram, finds its session (the unsecured
/// session of the sender's address, or a registered secure session),
/// drops duplicates by message counter, applies acknowledgements, and hands
/// the message to its exchange. One timer task drives MRP — retransmissions
/// spaced by the peer's SII/SAI (Matter Core §4.12.2.1), standalone acks
/// after 200 ms, receive timeouts, idle responder exchanges — on an
/// injectable ``MRPClock``.
///
/// Guarantees:
/// - a message with I=0 is only ever delivered to an exchange this controller
///   opened and still holds; it never creates one, so a late reply cannot be
///   read as the answer to a later request;
/// - a request is transmitted under one message counter; MRP resends the same
///   bytes and the peer de-duplicates — nothing here re-encodes a request;
/// - every reliable message received is acknowledged: piggybacked on the next
///   message of its exchange, otherwise standalone after the standalone-ack
///   timeout, or at once when the exchange closes;
/// - every frame leaves by a pinned path (``sendPinned(_:to:key:queuedPath:fromOwner:)``): an
///   exchange we open (PASE, CASE) is pinned by its first send, which lets
///   the transport select under ``Configuration/interfaces``, and every later
///   frame of it — Sigma3, acks, MRP copies — leaves the same way; a secure
///   session carries its handshake's path (``SessionEntry/path``). Only a
///   message that decrypted and passed counter de-duplication moves a
///   session's pin (to the allowed interface it arrived on); unsecured
///   traffic never moves one;
/// - a pinned path that loses its route re-selects for a secure session (the
///   message authenticates from any source) and fails an unsecured exchange
///   at once with ``MessagingError/pathLost(_:_:)``. When no allowed interface
///   has a route, an exchange with a reliable message outstanding fails with
///   ``MessagingError/noAllowedRoute(_:peer:)`` rather than leaving MRP to
///   retransmit into nothing.
///
/// ``stop()`` is terminal: a transport's receive stream is consumed once.
public actor ControllerMessenger {

    // MARK: - Configuration

    /// Messenger-wide settings.
    public struct Configuration: Sendable {
        /// MRP behaviour. `mrp.peer` applies to every peer and session not
        /// given parameters of its own.
        public var mrp: MRPConfig = .default
        /// A peer-initiated exchange with nothing pending and no `receive()`
        /// waiting is closed after this long.
        public var responderIdleTimeout: Duration = .seconds(5)
        /// Messages held per exchange while no `receive()` waits; beyond this
        /// a message is dropped (it has already been acknowledged).
        public var inboundQueueLimit: Int = 8
        /// Prefix of every metric label: `<prefix>_controller_messages_total`, … (default `matter`).
        public var metricsLabelPrefix: String = "matter"
        /// Metrics backend; nil uses `MetricsSystem.factory` as it is when the messenger is created.
        public var metricsFactory: (any MetricsFactory)? = nil
        /// Tracer for exchange spans; nil uses `InstrumentationSystem.tracer` at creation.
        public var tracer: (any Tracer)? = nil
        /// Which interfaces traffic may leave by: pushed into the transport once, at
        /// ``ControllerMessenger/start()``, before any send; also decides which arrival
        /// paths a session may re-pin to.
        public var interfaces: InterfacePolicy = .automatic

        public init() {}
    }

    /// Handles the first message of a peer-initiated exchange. The exchange
    /// is closed (owed ack flushed) when the handler returns.
    public typealias UnsolicitedHandler = @Sendable (InboundMessage, ControllerExchange) async -> Void

    // MARK: - Internal types

    struct SessionEntry {
        let session: SecureSession
        var peerAddress: MatterAddress
        var mrp: MRPParameters?
        var dedup = CounterDeduplication(encrypted: true)
        /// The path every frame of the session leaves by; nil until a send selects one (or
        /// when the transport cannot tell).
        var path: MatterPath?
    }

    struct Waiter {
        let continuation: CheckedContinuation<InboundMessage, any Error>
        var deadline: ContinuousClock.Instant
        /// Identifies this `receive()` call, so a cancellation hop that
        /// arrives after the waiter was resumed cannot fail a later one.
        let token: UInt64
    }

    struct Outgoing: Sendable {
        let bytes: Data
        let address: MatterAddress
        let note: String
        /// The exchange the frame belongs to, whose pinned path it leaves by.
        let key: ExchangeKey?
        /// The exchange's pinned path when the frame was queued: it still leaves by it
        /// if the exchange is forgotten before the frame is sent (the ack `close()`
        /// flushes, a frame behind a failure in the same batch).
        let path: MatterPath?
    }

    /// How far ahead the timer parks when nothing is pending. It always
    /// sleeps on the clock (never on a bare continuation), so a manual test
    /// clock sees exactly one sleeper per running messenger.
    static let idleTimerHorizon: Duration = .seconds(86_400)

    // MARK: - Dependencies

    let transport: any MatterUDPTransport
    let localNodeID: NodeID
    let configuration: Configuration
    let clock: any MRPClock
    /// The injected logger per subsystem (label unchanged).
    nonisolated let logger: Logger
    nonisolated let mrpLogger: Logger
    nonisolated let exchangeLogger: Logger
    nonisolated let sessionLogger: Logger
    nonisolated let transportLogger: Logger
    /// Metrics and tracer, shared with the controller and its subscriptions.
    nonisolated let telemetry: ControllerTelemetry

    // MARK: - State

    var manager: ExchangeManager
    var sessions: [UInt16: SessionEntry] = [:]
    var unsecuredDedup: [MatterAddress: CounterDeduplication] = [:]
    var unsecuredCounter: UInt32 = MessageCounter.randomInitialValue()
    var waiters: [ExchangeKey: Waiter] = [:]
    var inbound: [ExchangeKey: [InboundMessage]] = [:]
    /// Failures of exchanges whose owner was not waiting; reported by the next
    /// `send`/`receive` and cleared by `close()`.
    var failed: [ExchangeKey: MessagingError] = [:]
    var responderKeys: Set<ExchangeKey> = []
    /// Closed by their owner while a reliable message was unacknowledged:
    /// still in `manager` so MRP keeps retransmitting until it is acked or
    /// exhausted, but nothing is delivered and no `receive()` may wait.
    var closing: Set<ExchangeKey> = []
    /// Random Ephemeral Initiator Node ID sent as the Source Node ID on every
    /// frame of an unsecured exchange we opened (Matter Core §4.13.2.1).
    var ephemeralNodeIDs: [ExchangeKey: NodeID] = [:]
    /// The peer's ephemeral initiator node ID on an unsecured exchange it
    /// initiated; our frames on that exchange carry it as Destination Node ID.
    var peerEphemeralNodeIDs: [ExchangeKey: NodeID] = [:]
    var nextWaiterToken: UInt64 = 0
    /// Subscription IDs are assigned per device, so handlers are keyed by the
    /// secure session the subscription was established on as well.
    struct SubscriptionRoute: Hashable, Sendable {
        let sessionID: UInt16
        let subscriptionID: SubscriptionID
    }
    var subscriptionHandlers: [SubscriptionRoute: UnsolicitedHandler] = [:]
    var unsolicitedHandler: UnsolicitedHandler?
    var receiveTask: Task<Void, Never>?
    var timerTask: Task<Void, Never>?
    var timerDeadline: ContinuousClock.Instant?
    var timerGeneration: UInt64 = 0
    /// The armed timer is the idle fallback (nothing pending).
    var timerIsIdleFallback = false
    var isStarted = false
    var isStopped = false
    /// `matter.exchange` spans of exchanges opened with a context, until the owner closes them.
    var exchangeSpans: [ExchangeKey: any Span] = [:]
    /// The path each unsecured exchange is pinned to: chosen by the first send of one we
    /// opened, or the (allowed) arrival path of one the peer opened. Secure exchanges use
    /// their session's ``SessionEntry/path``.
    var exchangePaths: [ExchangeKey: MatterPath] = [:]
    /// Pushes ``Configuration/interfaces`` into the transport; every send waits for it, so
    /// the first selection already follows the policy. Nil once it has been awaited.
    var policyApplied: Task<Void, Never>?

    // MARK: - Init

    /// - Parameters:
    ///   - transport: the UDP transport; this messenger becomes its only reader.
    ///   - localNodeID: our operational node ID (CASE nonce).
    ///   - clock: drives every MRP deadline.
    ///   - jitterSource: MRP jitter unit in `0..<1`.
    public init(
        transport: any MatterUDPTransport,
        localNodeID: NodeID,
        configuration: Configuration = .init(),
        clock: any MRPClock = ContinuousClock(),
        jitterSource: @escaping @Sendable () -> Double = { .random(in: 0..<1) },
        logger: Logger = Logger(label: "matter.controller.messaging")
    ) {
        self.transport = transport
        self.localNodeID = localNodeID
        self.configuration = configuration
        self.clock = clock
        self.logger = logger.withSubsystem(.messenger)
        self.mrpLogger = logger.withSubsystem(.mrp)
        self.exchangeLogger = logger.withSubsystem(.exchange)
        self.sessionLogger = logger.withSubsystem(.session)
        self.transportLogger = logger.withSubsystem(.transport)
        self.telemetry = ControllerTelemetry(configuration: configuration)
        self.manager = ExchangeManager(defaultConfig: configuration.mrp, jitterSource: jitterSource)
    }

    deinit {
        receiveTask?.cancel()
        timerTask?.cancel()
    }

    // MARK: - Lifecycle

    /// Start the receive loop and the timer. Idempotent; a no-op after
    /// ``stop()``. Opening an exchange or registering a session starts the
    /// messenger implicitly.
    public func start() {
        guard !isStarted, !isStopped else { return }
        isStarted = true
        let transport = self.transport
        let policy = configuration.interfaces
        let applying = Task.detached { await transport.setInterfacePolicy(policy) }
        policyApplied = applying
        let stream = transport.receiveDatagrams()
        receiveTask = Task.detached { [weak self] in
            await applying.value
            for await datagram in stream {
                guard let self else { return }
                await self.handleDatagram(datagram.data, from: datagram.sender, path: datagram.path)
            }
            await self?.receiveLoopEnded()
        }
        rearmTimer()
    }

    /// Stop for good: cancel both tasks and fail every pending `receive()`
    /// with ``MessagingError/stopped``.
    ///
    /// This permanently ends the transport's receive stream (a stream is
    /// consumed once, and cancelling its reader finishes it): a stopped
    /// messenger cannot be restarted, and a new messenger needs a new
    /// transport.
    public func stop() async {
        guard !isStopped else { return }
        isStopped = true
        receiveTask?.cancel()
        receiveTask = nil
        timerTask?.cancel()
        timerTask = nil
        timerDeadline = nil
        timerIsIdleFallback = false
        for key in Array(waiters.keys) {
            takeWaiter(key)?.resume(throwing: MessagingError.stopped)
        }
        inbound.removeAll()
        failed.removeAll()
        responderKeys.removeAll()
        closing.removeAll()
        ephemeralNodeIDs.removeAll()
        peerEphemeralNodeIDs.removeAll()
        exchangePaths.removeAll()
        for span in exchangeSpans.values { span.end() }
        exchangeSpans.removeAll()
    }

    /// The transport's receive stream finished. Expected only after `stop()`;
    /// otherwise the messenger is deaf from here on.
    func receiveLoopEnded() {
        guard !isStopped else { return }
        logger.error("Transport receive stream ended while the messenger is running; no further messages will be received")
    }

    // MARK: - Exchanges

    /// Open an exchange on the unsecured session with `peer` (PASE and CASE
    /// handshakes). `mrp` is the peer's advertised parameters, if known.
    ///
    /// The unsecured session is keyed by `peer` in canonical form (see
    /// `MatterAddress.canonicalised`), as every inbound sender is, so any
    /// text for the same IP address (`"0:0:0:0:0:0:0:1"`, `"[::1]"`) gets
    /// the reply from `"::1"`. A host name is used as given; the transport
    /// rejects it when the exchange sends.
    ///
    /// `context`, when given, parents a `matter.exchange` span that records each
    /// transmission and retransmission and ends when the exchange is closed. Unlike the
    /// controller's public API it does not default to `ServiceContext.current`: `nil` means
    /// no exchange span.
    public func openExchange(peer: MatterAddress, mrp: MRPParameters? = nil, context: ServiceContext? = nil) -> ControllerExchange {
        let peer = peer.canonicalised
        start()
        let key = ExchangeKey(scope: .unsecured(peer: peer), exchangeID: manager.allocateExchangeID(), initiatedLocally: true)
        manager.open(key, peerAddress: peer, config: mrpConfig(for: mrp), now: clock.now)
        ephemeralNodeIDs[key] = Self.randomEphemeralNodeID()
        startExchangeSpan(key, context: context)
        return ControllerExchange(key: key, peerAddress: peer, messenger: self)
    }

    /// Open exchanges, including peer-initiated ones. Exchanges closed by
    /// their owner but still retransmitting an unacknowledged message are
    /// not counted (see ``closingExchangeCount``).
    public var activeExchangeCount: Int {
        manager.count - closing.count
    }

    /// Exchanges closed by their owner whose last reliable message MRP is
    /// still retransmitting.
    var closingExchangeCount: Int {
        closing.count
    }

    /// Open, and not closing: may send and receive.
    func isOpen(_ key: ExchangeKey) -> Bool {
        manager.exchange(for: key) != nil && !closing.contains(key)
    }

    /// A random 64-bit Ephemeral Initiator Node ID, drawn from the
    /// operational node ID range.
    static func randomEphemeralNodeID() -> NodeID {
        NodeID(rawValue: UInt64.random(in: 1...0xFFFF_FFEF_FFFF_FFFF))
    }

    /// `receive()` calls currently waiting.
    public var pendingReceiveCount: Int {
        waiters.count
    }

    func send(_ key: ExchangeKey, protocolID: MatterProtocolID, opcode: UInt8, payload: Data, reliable: Bool) async throws {
        if isStopped { throw MessagingError.stopped }
        if let error = failed[key] { throw error }
        guard let exchange = manager.exchange(for: key), !closing.contains(key) else { throw MessagingError.exchangeClosed }
        guard let address = address(for: key.scope) else { throw MessagingError.sessionClosed }
        if reliable, exchange.pendingMessage != nil { throw MessagingError.sendAlreadyPending }

        let header = ExchangeHeader(
            flags: ExchangeFlags(initiator: key.initiatedLocally, reliableDelivery: reliable),
            protocolOpcode: opcode,
            exchangeID: key.exchangeID,
            protocolID: protocolID.rawValue,
            acknowledgedMessageCounter: manager.takePendingAck(key)
        )
        let (bytes, counter) = try encode(header, payload: payload, key: key)
        if reliable {
            try manager.trackTransmission(key, message: bytes, now: clock.now)
        }
        recordFrame(.outbound, key: key, header: header, counter: counter, path: pinnedPath(for: key))
        recordExchangeEvent(key, "send", attributes: Self.counterAttributes(counter))
        // State is final: arm the timer before suspending in the send.
        rearmTimer()
        do {
            try await sendPinned(bytes, to: address, key: key, fromOwner: true)
        } catch where reliable {
            transportLogger.warning(
                "Send on exchange \(key.exchangeID) to \(MatterLogValue.address(address)) failed; MRP will retransmit: \(error)",
                metadata: Self.exchangeMetadata(key).merging([MatterLogKey.reason: "send_failed"]) { $1 }
            )
        }
        // A path failure ends the exchange inside `sendPinned`; its owner hears of it now.
        if let error = failed[key] { throw error }
    }

    func receive(_ key: ExchangeKey, timeout: Duration) async throws -> InboundMessage {
        if var queued = inbound[key], !queued.isEmpty {
            let message = queued.removeFirst()
            inbound[key] = queued
            return message
        }
        if let error = failed.removeValue(forKey: key) { throw error }
        if isStopped { throw MessagingError.stopped }
        guard isOpen(key) else { throw MessagingError.exchangeClosed }
        guard waiters[key] == nil else { throw MessagingError.receiveAlreadyPending }

        // Never shorter than MRP's exhaustion horizon: a silent (sleepy) peer
        // surfaces as peerUnreachable, not as a premature responseTimeout.
        let deadline = clock.now + max(timeout, exhaustionHorizon(for: key))
        let token = nextWaiterToken
        nextWaiterToken &+= 1
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<InboundMessage, any Error>) in
                waiters[key] = Waiter(continuation: continuation, deadline: deadline, token: token)
                rearmTimer()
            }
        } onCancel: {
            Task { await self.cancelReceive(key, token: token) }
        }
    }

    func closeExchange(_ key: ExchangeKey) async {
        var outgoing: [Outgoing] = []
        finishExchange(key, failing: .exchangeClosed, into: &outgoing)
        rearmTimer()
        await transmit(outgoing)
    }

    /// The task waiting in `receive` (the call identified by `token`) was
    /// cancelled: fail it and close the exchange as `close()` does (flushing
    /// any owed ack; an unacknowledged reliable message stays under MRP until
    /// acked or exhausted). A
    /// hop that arrives after that waiter was already resumed — by a delivery,
    /// a timeout or a close — finds a different token, or none, and does
    /// nothing.
    func cancelReceive(_ key: ExchangeKey, token: UInt64) async {
        guard waiters[key]?.token == token, let continuation = takeWaiter(key) else { return }
        continuation.resume(throwing: CancellationError())
        var outgoing: [Outgoing] = []
        finishExchange(key, failing: .exchangeClosed, into: &outgoing)
        rearmTimer()
        await transmit(outgoing)
    }

    /// Close an exchange: fail its waiter with `error`, drop queued
    /// messages, and queue a standalone ack for any ack still owed. If a
    /// reliable message of ours is still unacknowledged the exchange moves to
    /// `closing` instead of being removed — MRP keeps retransmitting it until
    /// it is acked or exhausted — so a lost final message (say a
    /// StatusResponse) is not abandoned.
    func finishExchange(_ key: ExchangeKey, failing error: MessagingError, into outgoing: inout [Outgoing]) {
        takeWaiter(key)?.resume(throwing: error)
        inbound[key] = nil
        failed[key] = nil
        responderKeys.remove(key)
        if let counter = manager.takePendingAck(key), let ack = standaloneAck(key: key, ackCounter: counter) {
            outgoing.append(ack)
        }
        // The owner's view of the exchange ends here, even if MRP keeps retransmitting in `closing`.
        endExchangeSpan(key, failing: error == .exchangeClosed ? nil : error)
        if manager.exchange(for: key)?.pendingMessage != nil {
            closing.insert(key)
        } else {
            removeExchange(key)
        }
    }

    /// The path exchange `key` is pinned to: its session's for a secure
    /// exchange, its own for an unsecured one; nil when none is pinned yet.
    func pinnedPath(for key: ExchangeKey) -> MatterPath? {
        switch key.scope {
        case .unsecured: return exchangePaths[key]
        case .secured(let localSessionID): return sessions[localSessionID]?.path
        }
    }

    /// Forget an exchange entirely.
    func removeExchange(_ key: ExchangeKey) {
        manager.close(key)
        closing.remove(key)
        ephemeralNodeIDs[key] = nil
        peerEphemeralNodeIDs[key] = nil
        exchangePaths[key] = nil
        endExchangeSpan(key, failing: nil)
    }

    /// The single place a waiter leaves `waiters`; only the caller that gets
    /// the continuation may resume it, so it is resumed exactly once.
    func takeWaiter(_ key: ExchangeKey) -> CheckedContinuation<InboundMessage, any Error>? {
        waiters.removeValue(forKey: key)?.continuation
    }

    // MARK: - Receive path

    /// `path` is the path the datagram arrived on, nil when the transport cannot tell.
    func handleDatagram(_ data: Data, from sender: MatterAddress, path: MatterPath? = nil) async {
        guard !isStopped else { return }
        // Transports report senders as inet_ntop writes them; canonicalise
        // anyway, so a key never depends on which transport produced it.
        let sender = sender.canonicalised
        var outgoing: [Outgoing] = []
        do {
            try process(data, from: sender, arrival: path, now: clock.now, into: &outgoing)
        } catch {
            logger.debug("Dropping datagram from \(MatterLogValue.address(sender)): \(error)", metadata: [
                MatterLogKey.reason: "undecodable",
            ])
        }
        rearmTimer()
        await transmit(outgoing)
    }

    /// Everything a datagram changes, synchronously; sends are queued in
    /// `outgoing` and performed by the caller afterwards. `arrival` is the
    /// path it arrived on: it pins a peer-initiated unsecured exchange, and
    /// moves a secure session's pin only once the message has authenticated
    /// and passed de-duplication.
    func process(
        _ data: Data,
        from sender: MatterAddress,
        arrival: MatterPath? = nil,
        now: ContinuousClock.Instant,
        into outgoing: inout [Outgoing]
    ) throws {
        let (messageHeader, headerLength) = try MessageHeader.decode(from: data)
        let scope: SessionScope
        let exchangeHeader: ExchangeHeader
        let payload: Data
        let verdict: CounterDeduplication.Verdict

        if messageHeader.isUnsecured {
            let rest = Data(data.dropFirst(headerLength))
            let (header, exchangeLength) = try ExchangeHeader.decode(from: rest)
            exchangeHeader = header
            payload = Data(rest.dropFirst(exchangeLength))
            scope = .unsecured(peer: sender)
            var dedup = unsecuredDedup[sender] ?? CounterDeduplication(encrypted: false)
            verdict = dedup.check(messageHeader.messageCounter)
            unsecuredDedup[sender] = dedup
        } else if messageHeader.securityFlags.sessionType == .unicast, var entry = sessions[messageHeader.sessionID] {
            // Decrypt first: a forged header must not move the counter window.
            let decoded: (messageHeader: MessageHeader, exchangeHeader: ExchangeHeader, payload: Data)
            do {
                decoded = try SecureMessageCodec.decode(data: data, session: entry.session)
            } catch CryptoError.authenticationFailed, CryptoError.invalidCiphertext {
                logger.debug("Dropping message on session \(messageHeader.sessionID) from \(MatterLogValue.address(sender)): decryption failed", metadata: [
                    MatterLogKey.session: MatterLogValue.hex(messageHeader.sessionID),
                    MatterLogKey.counter: MatterLogValue.decimal(messageHeader.messageCounter),
                    MatterLogKey.reason: "decrypt_failed",
                ])
                return
            }
            exchangeHeader = decoded.exchangeHeader
            payload = decoded.payload
            scope = .secured(localSessionID: messageHeader.sessionID)
            verdict = entry.dedup.check(messageHeader.messageCounter)
            if verdict == .accepted, entry.peerAddress != sender {
                sessionLogger.info("Session peer address changed: \(MatterLogValue.address(entry.peerAddress)) → \(MatterLogValue.address(sender))", metadata: [
                    MatterLogKey.session: MatterLogValue.hex(messageHeader.sessionID),
                ])
                entry.peerAddress = sender
            }
            if verdict == .accepted, let arrival, arrival != entry.path {
                repinOnArrival(&entry, sessionID: messageHeader.sessionID, arrival: arrival)
            }
            sessions[messageHeader.sessionID] = entry
        } else {
            logger.trace("Dropping message for unknown session \(messageHeader.sessionID) from \(MatterLogValue.address(sender))", metadata: [
                MatterLogKey.session: MatterLogValue.hex(messageHeader.sessionID),
                MatterLogKey.counter: MatterLogValue.decimal(messageHeader.messageCounter),
                MatterLogKey.reason: "unknown_session",
            ])
            return
        }

        let key = ExchangeKey(scope: scope, inbound: exchangeHeader)
        let counter = messageHeader.messageCounter
        let requiresAck = exchangeHeader.flags.reliableDelivery
        if let ephemeral = ephemeralNodeIDs[key], let destination = messageHeader.destinationNodeID, destination != ephemeral {
            // Matched by (peer, exchange, I flag) regardless; only noted.
            logger.debug("Unsecured message on exchange \(key.exchangeID) addressed to \(destination), not our ephemeral ID \(ephemeral)")
        }

        switch verdict {
        case .outOfWindow, .duplicate:
            // Matter Core §4.6.5: acknowledge again if asked, never process twice.
            let duplicate = verdict == .duplicate
            logger.trace(
                "Dropping \(duplicate ? "duplicate" : "out-of-window") counter \(counter) on exchange \(key.exchangeID)",
                metadata: frameMetadata(key: key, header: exchangeHeader, counter: counter, reason: duplicate ? "duplicate" : "out_of_window")
            )
            if requiresAck, let ack = standaloneAck(key: key, ackCounter: counter, inbound: messageHeader) {
                outgoing.append(ack)
            }
            return
        case .accepted:
            break
        }

        manager.recordReceived(scope: scope, now: now)
        recordFrame(.inbound, key: key, header: exchangeHeader, counter: counter, path: arrival)
        let wasClosing = closing.contains(key)
        var acknowledgedOurs = false
        if let acked = exchangeHeader.acknowledgedMessageCounter {
            acknowledgedOurs = manager.recordAcknowledgment(key, ackedCounter: acked)
            if acknowledgedOurs {
                mrpLogger.trace("Ack received", metadata: Self.exchangeMetadata(key).merging([MatterLogKey.ack: MatterLogValue.decimal(acked)]) { $1 })
                recordExchangeEvent(key, "ack", attributes: [MatterLogKey.ack: .int64(Int64(acked))])
            }
        }
        if wasClosing {
            // Closed by its owner: acknowledge if asked, deliver nothing, and
            // never let a late message re-open it as a new exchange. The ack
            // is encoded while the exchange (and its ephemeral ID) still exists.
            if requiresAck, !isStandaloneAck(exchangeHeader), let ack = standaloneAck(key: key, ackCounter: counter, inbound: messageHeader) {
                outgoing.append(ack)
            }
            if acknowledgedOurs {
                // The last message of a closed exchange is acknowledged: done.
                removeExchange(key)
            }
            return
        }
        if exchangeHeader.protocolID == MatterProtocolID.secureChannel.rawValue,
           exchangeHeader.protocolOpcode == SecureChannelOpcode.standaloneAck.rawValue {
            return
        }

        let message = InboundMessage(
            key: key,
            peerAddress: sender,
            messageCounter: counter,
            protocolID: exchangeHeader.protocolID,
            opcode: exchangeHeader.protocolOpcode,
            payload: payload,
            requiresAck: requiresAck,
            acknowledgedCounter: exchangeHeader.acknowledgedMessageCounter
        )

        if key.initiatedLocally {
            // I=0: only ever a message on an exchange we opened and still hold.
            guard manager.exchange(for: key) != nil else {
                logger.trace(
                    "Stale message on closed exchange \(key.exchangeID) (counter \(counter)); acknowledging and dropping",
                    metadata: frameMetadata(key: key, header: exchangeHeader, counter: counter, reason: "stale_exchange")
                )
                if requiresAck, let ack = standaloneAck(key: key, ackCounter: counter, inbound: messageHeader) {
                    outgoing.append(ack)
                }
                return
            }
            if requiresAck { recordOwedAck(key, counter: counter, now: now, into: &outgoing) }
            deliver(message)
            return
        }

        // I=1: the peer initiated this exchange.
        if manager.exchange(for: key) != nil {
            if requiresAck { recordOwedAck(key, counter: counter, now: now, into: &outgoing) }
            deliver(message)
            return
        }
        let peerAddress = address(for: scope) ?? sender
        manager.open(key, peerAddress: peerAddress, config: mrpConfig(for: parameters(for: scope)), now: now)
        if case .unsecured = scope, let peerEphemeral = messageHeader.sourceNodeID {
            peerEphemeralNodeIDs[key] = peerEphemeral
        }
        if case .unsecured = scope, let arrival, configuration.interfaces.allows(arrival.interfaceName) {
            // The peer's handshake: answer from the address and interface it came in on.
            exchangePaths[key] = arrival
        }
        responderKeys.insert(key)
        if requiresAck { recordOwedAck(key, counter: counter, now: now, into: &outgoing) }

        guard let handler = routeHandler(for: message) else {
            logger.debug(
                "No handler for unsolicited protocol \(message.protocolID) opcode \(message.opcode); acknowledging and closing",
                metadata: frameMetadata(key: key, header: exchangeHeader, counter: counter, reason: "no_handler")
            )
            finishExchange(key, failing: .exchangeClosed, into: &outgoing)
            return
        }
        let exchange = ControllerExchange(key: key, peerAddress: peerAddress, messenger: self)
        Task.detached {
            await handler(message, exchange)
            await exchange.close()
        }
    }

    func isStandaloneAck(_ header: ExchangeHeader) -> Bool {
        header.protocolID == MatterProtocolID.secureChannel.rawValue
            && header.protocolOpcode == SecureChannelOpcode.standaloneAck.rawValue
    }

    /// `ReportData` carrying a subscription ID goes to that subscription's
    /// handler; everything else to the fallback handler.
    func routeHandler(for message: InboundMessage) -> UnsolicitedHandler? {
        if message.protocolID == MatterProtocolID.interactionModel.rawValue,
           message.opcode == InteractionModelOpcode.reportData.rawValue,
           let report = try? ReportData.fromTLV(message.payload),
           let subscriptionID = report.subscriptionID,
           case .secured(let localSessionID) = message.key.scope,
           let handler = subscriptionHandlers[SubscriptionRoute(sessionID: localSessionID, subscriptionID: subscriptionID)] {
            return handler
        }
        return unsolicitedHandler
    }

    /// Resume the waiting `receive()`, or queue the message for the next one.
    func deliver(_ message: InboundMessage) {
        if let continuation = takeWaiter(message.key) {
            continuation.resume(returning: message)
            return
        }
        var queue = inbound[message.key, default: []]
        guard queue.count < configuration.inboundQueueLimit else {
            logger.warning(
                "Inbound queue full on exchange \(message.key.exchangeID); dropping counter \(message.messageCounter)",
                metadata: Self.exchangeMetadata(message.key).merging([
                    MatterLogKey.counter: MatterLogValue.decimal(message.messageCounter),
                    MatterLogKey.reason: "queue_full",
                ]) { $1 }
            )
            return
        }
        queue.append(message)
        inbound[message.key] = queue
    }

    /// Owe an ack for `counter`; an ack already owed for an earlier message
    /// on the exchange is sent standalone now rather than lost.
    func recordOwedAck(_ key: ExchangeKey, counter: UInt32, now: ContinuousClock.Instant, into outgoing: inout [Outgoing]) {
        if let previous = manager.takePendingAck(key), previous != counter,
           let ack = standaloneAck(key: key, ackCounter: previous) {
            outgoing.append(ack)
        }
        manager.recordReliableReceipt(key, counter: counter, now: now)
    }

    // MARK: - Timer

    /// The single timer sleeps until the earliest of: a retransmission, a
    /// standalone ack, a receive timeout, a responder exchange going idle.
    func nextTimerDeadline() -> ContinuousClock.Instant? {
        var deadlines = waiters.values.map(\.deadline)
        if let mrpDeadline = manager.nextDeadline() {
            deadlines.append(mrpDeadline)
        }
        for key in responderKeys where waiters[key] == nil {
            if let exchange = manager.exchange(for: key), exchange.isIdle {
                deadlines.append(exchange.lastActivityAt + configuration.responderIdleTimeout)
            }
        }
        return deadlines.min()
    }

    /// Point the timer at the current earliest deadline. Called after every
    /// state change; cancels and replaces the sleeping task only when the
    /// deadline moved.
    func rearmTimer() {
        guard isStarted, !isStopped else { return }
        let next = nextTimerDeadline()
        // An idle fallback moves with `now`; replacing one idle sleep with
        // another would only churn tasks on a real clock.
        if timerTask != nil, next == nil, timerIsIdleFallback { return }
        let deadline = next ?? clock.now + Self.idleTimerHorizon
        if timerTask != nil, timerDeadline == deadline { return }
        timerTask?.cancel()
        timerGeneration &+= 1
        let generation = timerGeneration
        timerDeadline = deadline
        timerIsIdleFallback = next == nil
        let clock = self.clock
        timerTask = Task.detached { [weak self] in
            do {
                try await clock.sleep(until: deadline)
            } catch {
                return
            }
            await self?.timerFired(generation: generation)
        }
    }

    func timerFired(generation: UInt64) async {
        guard generation == timerGeneration, !isStopped else { return }
        timerTask = nil
        timerDeadline = nil
        timerIsIdleFallback = false
        let now = clock.now
        var outgoing: [Outgoing] = []
        collectRetransmissions(now: now, into: &outgoing)
        collectStandaloneAcks(now: now, into: &outgoing)
        expireWaiters(now: now, into: &outgoing)
        closeIdleResponders(now: now, into: &outgoing)
        rearmTimer()
        await transmit(outgoing)
    }

    /// Decide-first MRP: the manager either counts one more transmission
    /// (resend the stored bytes, same counter) or, after the last copy's full
    /// ack window, exhausts the exchange — nothing is sent then.
    func collectRetransmissions(now: ContinuousClock.Instant, into outgoing: inout [Outgoing]) {
        for (key, decision) in manager.processDueRetransmissions(now: now) {
            switch decision {
            case .send(let message, let recordedAddress, let nextDeadline):
                // A secure session follows its peer's current address.
                let address = address(for: key.scope) ?? recordedAddress
                // `transmissions` already counts this copy: retransmission n is transmission n + 1.
                let attempt = (manager.exchange(for: key)?.transmissions ?? 1) - 1
                telemetry.metrics.mrpRetransmits.increment()
                mrpLogger.trace(
                    "MRP retransmit \(attempt), next in \(MatterLogValue.milliseconds(nextDeadline - now)) ms",
                    metadata: Self.exchangeMetadata(key).merging([
                        MatterLogKey.counter: Self.messageCounter(of: message).map { MatterLogValue.decimal($0) } ?? "unknown",
                        MatterLogKey.attempt: MatterLogValue.decimal(attempt),
                    ]) { $1 }
                )
                recordExchangeEvent(key, "retransmit", attributes: [MatterLogKey.attempt: .int64(Int64(attempt))])
                outgoing.append(Outgoing(bytes: message, address: address, note: "retransmission on exchange \(key.exchangeID)", key: key, path: pinnedPath(for: key)))
            case .exhausted where closing.contains(key):
                // The owner already closed the exchange; nobody to tell.
                telemetry.metrics.mrpGiveUps.increment()
                mrpLogger.info("Final message on closed exchange \(key.exchangeID) went unacknowledged", metadata: Self.exchangeMetadata(key))
                removeExchange(key)
            case .exhausted:
                // Exhaustion happens only once transmissions > maxRetransmissions,
                // i.e. exactly maxRetransmissions + 1 copies went unacknowledged.
                let transmissions = configuration.mrp.maxRetransmissions + 1
                let error = MessagingError.peerUnreachable(key, transmissions: transmissions)
                telemetry.metrics.mrpGiveUps.increment()
                mrpLogger.info(
                    "Peer unreachable: \(transmissions) transmissions unacknowledged on exchange \(key.exchangeID)",
                    metadata: Self.exchangeMetadata(key).merging([MatterLogKey.attempt: MatterLogValue.decimal(transmissions)]) { $1 }
                )
                let hadWaiter = waiters[key] != nil
                finishExchange(key, failing: error, into: &outgoing)
                if !hadWaiter {
                    failed[key] = error
                }
            }
        }
    }

    func collectStandaloneAcks(now: ContinuousClock.Instant, into outgoing: inout [Outgoing]) {
        for exchange in manager.dueStandaloneAcks(now: now) {
            guard let counter = manager.takePendingAck(exchange.key) else { continue }
            if let ack = standaloneAck(key: exchange.key, ackCounter: counter) {
                outgoing.append(ack)
            }
        }
    }

    /// A receive whose deadline passed fails with `responseTimeout` and its
    /// exchange closes through the same path as `close()` (owed ack flushed;
    /// an unacknowledged reliable message stays under MRP in `closing`).
    func expireWaiters(now: ContinuousClock.Instant, into outgoing: inout [Outgoing]) {
        let expired = waiters.filter { $0.value.deadline <= now }.map(\.key)
        for key in expired {
            telemetry.metrics.exchangeTimeouts.increment()
            exchangeLogger.debug("Exchange response timeout on exchange \(key.exchangeID)", metadata: Self.exchangeMetadata(key))
            finishExchange(key, failing: .responseTimeout(key), into: &outgoing)
        }
    }

    /// The longest MRP may keep the exchange's message unacknowledged: the
    /// larger of its idle and active horizons (the peer may change state).
    /// For a sleepy peer with a long SII that is tens of seconds;
    /// subscription liveness, not command failure, is the fast signal.
    func exhaustionHorizon(for key: ExchangeKey) -> Duration {
        let config = manager.exchange(for: key)?.config ?? configuration.mrp
        return max(config.exhaustionHorizon(peerActive: false), config.exhaustionHorizon(peerActive: true))
    }

    func closeIdleResponders(now: ContinuousClock.Instant, into outgoing: inout [Outgoing]) {
        for exchange in manager.idleExchanges(olderThan: configuration.responderIdleTimeout, now: now)
        where responderKeys.contains(exchange.key) && waiters[exchange.key] == nil {
            finishExchange(exchange.key, failing: .exchangeClosed, into: &outgoing)
        }
    }

    // MARK: - Encoding and sending

    func transmit(_ outgoing: [Outgoing]) async {
        for item in outgoing {
            do {
                try await sendPinned(item.bytes, to: item.address, key: item.key, queuedPath: item.path)
            } catch {
                transportLogger.warning("Send failed (\(item.note)) to \(MatterLogValue.address(item.address)): \(error)", metadata: [
                    MatterLogKey.reason: "send_failed",
                ])
            }
        }
    }

    /// A standalone ack on exchange `key`. `inbound` is the header of the
    /// frame being acknowledged, used for unsecured node IDs when the
    /// exchange is no longer held (see ``unsecuredNodeIDs(for:inbound:)``).
    func standaloneAck(key: ExchangeKey, ackCounter: UInt32, inbound: MessageHeader? = nil) -> Outgoing? {
        guard let address = address(for: key.scope) else { return nil }
        let header = ExchangeHeader(
            flags: ExchangeFlags(initiator: key.initiatedLocally, reliableDelivery: false),
            protocolOpcode: SecureChannelOpcode.standaloneAck.rawValue,
            exchangeID: key.exchangeID,
            protocolID: MatterProtocolID.secureChannel.rawValue,
            acknowledgedMessageCounter: ackCounter
        )
        do {
            let (bytes, counter) = try encode(header, payload: Data(), key: key, inbound: inbound)
            telemetry.metrics.message(.outbound, protocolID: header.protocolID)
            mrpLogger.trace("standalone ack", metadata: frameMetadata(key: key, header: header, counter: counter, path: pinnedPath(for: key)))
            return Outgoing(bytes: bytes, address: address, note: "standalone ack \(ackCounter)", key: key, path: pinnedPath(for: key))
        } catch {
            mrpLogger.warning("Cannot encode standalone ack on exchange \(key.exchangeID): \(error)", metadata: Self.exchangeMetadata(key))
            return nil
        }
    }

    /// Encode one frame of exchange `key`, with the message counter it was given; `inbound`
    /// is the header of the frame it answers, if any (see ``unsecuredNodeIDs(for:inbound:)``).
    func encode(_ header: ExchangeHeader, payload: Data, key: ExchangeKey, inbound: MessageHeader? = nil) throws -> (bytes: Data, counter: UInt32) {
        switch key.scope {
        case .unsecured:
            unsecuredCounter &+= 1
            let nodeIDs = unsecuredNodeIDs(for: key, inbound: inbound)
            let bytes = MatterMessage.encodeUnsecured(
                messageHeader: MessageHeader(
                    sessionID: 0,
                    messageCounter: unsecuredCounter,
                    sourceNodeID: nodeIDs.source,
                    destinationNodeID: nodeIDs.destination
                ),
                exchangeHeader: header,
                payload: payload
            )
            return (bytes, unsecuredCounter)
        case .secured(let localSessionID):
            guard let entry = sessions[localSessionID] else {
                throw MessagingError.unknownSession(localSessionID)
            }
            let encoded = try SecureMessageCodec.encodeCounted(exchangeHeader: header, payload: payload, session: entry.session, sourceNodeID: localNodeID, logger: transportLogger)
            return (encoded.message, encoded.counter)
        }
    }

    /// Node IDs for an unsecured frame (Matter Core §4.13.2.1): on an
    /// exchange we initiated, our ephemeral initiator ID as Source; on one
    /// the peer initiated, its ephemeral ID as Destination. Once the exchange
    /// is gone (a re-ack after close, a stale reply) the IDs come from the
    /// frame being acknowledged — its Destination is our ID, its Source the
    /// peer's — so the ack still names the exchange's initiator.
    func unsecuredNodeIDs(for key: ExchangeKey, inbound: MessageHeader?) -> (source: NodeID?, destination: NodeID?) {
        if key.initiatedLocally {
            return (ephemeralNodeIDs[key] ?? inbound?.destinationNodeID, nil)
        }
        return (nil, peerEphemeralNodeIDs[key] ?? inbound?.sourceNodeID)
    }

    /// Where to send for a scope: the unsecured peer, or the secure session's
    /// current address (updated when the peer's source address moves).
    func address(for scope: SessionScope) -> MatterAddress? {
        switch scope {
        case .unsecured(let peer):
            return peer
        case .secured(let localSessionID):
            return sessions[localSessionID]?.peerAddress
        }
    }

    func parameters(for scope: SessionScope) -> MRPParameters? {
        guard case .secured(let localSessionID) = scope else { return nil }
        return sessions[localSessionID]?.mrp
    }

    func mrpConfig(for parameters: MRPParameters?) -> MRPConfig {
        var config = configuration.mrp
        if let parameters {
            config.peer = parameters
        }
        return config
    }

    // MARK: - Telemetry

    /// Start the exchange's `matter.exchange` span as a child of `context` (none without one).
    func startExchangeSpan(_ key: ExchangeKey, context: ServiceContext?) {
        guard let context else { return }
        let span = telemetry.tracer.startSpan("matter.exchange", context: context, ofKind: .client)
        // A span that records nothing is not kept: its events would be built for nobody.
        guard span.isRecording else {
            span.end()
            return
        }
        span.attributes[MatterLogKey.session] = Self.sessionText(key.scope)
        span.attributes[MatterLogKey.exchange] = MatterLogValue.hexString(key.exchangeID)
        exchangeSpans[key] = span
    }

    /// End the exchange's span, recording `error` (give-up, timeout, session closed) as its status.
    func endExchangeSpan(_ key: ExchangeKey, failing error: MessagingError?) {
        guard let span = exchangeSpans.removeValue(forKey: key) else { return }
        if let error {
            span.recordError(error)
            span.setStatus(SpanStatus(code: .error, message: String(describing: error)))
        }
        span.end()
    }

    /// An event on the exchange's span, if it has one and it is recording.
    /// `attributes` are built only when the exchange is traced.
    func recordExchangeEvent(_ key: ExchangeKey, _ name: String, attributes: @autoclosure () -> SpanAttributes = [:]) {
        guard let span = exchangeSpans[key], span.isRecording else { return }
        span.addEvent(SpanEvent(name: name, attributes: attributes()))
    }

    /// Count one frame sent or received, and trace it: `send|receive <secured|unsecured> I= R=`,
    /// with the path it leaves by (when pinned) or arrived on (when the transport tells).
    func recordFrame(_ direction: MessageDirection, key: ExchangeKey, header: ExchangeHeader, counter: UInt32?, path: MatterPath? = nil) {
        telemetry.metrics.message(direction, protocolID: header.protocolID)
        let verb = direction == .outbound ? "send" : "receive"
        logger.trace(
            "\(verb) \(Self.scopeName(key.scope)) I=\(header.flags.initiator ? 1 : 0) R=\(header.flags.reliableDelivery ? 1 : 0)",
            metadata: frameMetadata(key: key, header: header, counter: counter, path: path)
        )
    }

    /// The static frame metadata plus, on a secure session, its peer's `matter.node` (none
    /// for a PASE session, whose peer has no operational node ID yet), and `path` as
    /// `matter.interface` / `matter.local_address`. Call it only inside a log call's
    /// metadata autoclosure.
    func frameMetadata(key: ExchangeKey, header: ExchangeHeader, counter: UInt32?, reason: String? = nil, path: MatterPath? = nil) -> Logger.Metadata {
        var metadata = Self.frameMetadata(key: key, header: header, counter: counter, reason: reason)
        if let path { metadata.merge(Self.pathMetadata(path)) { $1 } }
        if case .secured(let localSessionID) = key.scope,
           let peer = sessions[localSessionID]?.session.peerNodeID, peer != .unspecified {
            metadata[MatterLogKey.node] = MatterLogValue.hex(peer.rawValue)
        }
        return metadata
    }

    /// `matter.session` and `matter.exchange` of `key`.
    static func exchangeMetadata(_ key: ExchangeKey) -> Logger.Metadata {
        [
            MatterLogKey.session: sessionMetadata(key.scope),
            MatterLogKey.exchange: MatterLogValue.hex(key.exchangeID),
        ]
    }

    /// The exchange's metadata plus the frame's protocol, opcode, counter and ack, and the
    /// drop `reason` if any.
    static func frameMetadata(key: ExchangeKey, header: ExchangeHeader, counter: UInt32?, reason: String? = nil) -> Logger.Metadata {
        var metadata = exchangeMetadata(key)
        metadata[MatterLogKey.protocolID] = MatterLogValue.hex(header.protocolID)
        metadata[MatterLogKey.opcode] = MatterLogValue.hex(header.protocolOpcode)
        if let counter { metadata[MatterLogKey.counter] = MatterLogValue.decimal(counter) }
        if let ack = header.acknowledgedMessageCounter { metadata[MatterLogKey.ack] = MatterLogValue.decimal(ack) }
        if let reason { metadata[MatterLogKey.reason] = .string(reason) }
        return metadata
    }

    /// `unsecured`, or the local session ID in hex.
    static func sessionText(_ scope: SessionScope) -> String {
        switch scope {
        case .unsecured: return "unsecured"
        case .secured(let localSessionID): return MatterLogValue.hexString(localSessionID)
        }
    }

    static func sessionMetadata(_ scope: SessionScope) -> Logger.MetadataValue {
        .string(sessionText(scope))
    }

    static func scopeName(_ scope: SessionScope) -> String {
        switch scope {
        case .unsecured: return "unsecured"
        case .secured: return "secured"
        }
    }

    /// The message counter of an encoded frame (its plaintext header).
    static func messageCounter(of bytes: Data) -> UInt32? {
        try? MessageHeader.decode(from: bytes).0.messageCounter
    }

    static func counterAttributes(_ counter: UInt32?) -> SpanAttributes {
        guard let counter else { return [:] }
        return [MatterLogKey.counter: .int64(Int64(counter))]
    }
}
