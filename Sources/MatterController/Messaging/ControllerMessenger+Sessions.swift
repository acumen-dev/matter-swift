// ControllerMessenger+Sessions.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterProtocol
import MatterTransport

extension ControllerMessenger {

    // MARK: - Secure sessions

    /// Make a secure session's traffic routable. Register before the first
    /// request on it, so the reply can be decrypted and demultiplexed.
    ///
    /// Registering the same session object again updates its address and MRP
    /// parameters (for exchanges opened from then on) but keeps its
    /// received-counter window, so a replay is still recognised. Passing
    /// `mrp: nil` when re-registering clears the parameters to the messenger
    /// default.
    ///
    /// A *different* session under a registered local session ID is refused
    /// with ``MessagingError/sessionIDInUse(_:)``, leaving the registered one
    /// untouched: replacing it would send its owner's later requests under
    /// the newcomer's keys, to the newcomer's peer. Unregister the old
    /// session first if replacing it is really meant.
    ///
    /// To change only the MRP parameters of a session that may have been
    /// unregistered concurrently, use ``updateSession(localSessionID:mrp:)``:
    /// it never registers.
    ///
    /// - Throws: ``MessagingError/sessionIDInUse(_:)``.
    public func registerSession(_ session: SecureSession, peerAddress: MatterAddress, mrp: MRPParameters? = nil) throws {
        if var existing = sessions[session.localSessionID] {
            guard existing.session === session else {
                throw MessagingError.sessionIDInUse(session.localSessionID)
            }
            start()
            existing.peerAddress = peerAddress
            existing.mrp = mrp
            sessions[session.localSessionID] = existing
            return
        }
        start()
        sessions[session.localSessionID] = SessionEntry(session: session, peerAddress: peerAddress, mrp: mrp)
    }

    /// Local session IDs currently registered.
    var registeredSessionIDs: Set<UInt16> {
        Set(sessions.keys)
    }

    /// Change the MRP parameters of a registered session, keeping its tracked
    /// peer address and counter window. Exchanges already open keep the
    /// parameters they were opened with; `nil` means the messenger default.
    ///
    /// - Returns: `false`, changing nothing, if no session is registered
    ///   under `localSessionID` (for instance it was unregistered meanwhile).
    @discardableResult
    public func updateSession(localSessionID: UInt16, mrp: MRPParameters?) -> Bool {
        guard var entry = sessions[localSessionID] else { return false }
        entry.mrp = mrp
        sessions[localSessionID] = entry
        return true
    }

    /// Forget a session. Every exchange on it ends at once: a pending
    /// `receive()` fails with ``MessagingError/sessionClosed``, an open
    /// exchange with nothing waiting reports it on its next `send`/`receive`,
    /// queued messages and owed acks are dropped (they can no longer be
    /// encrypted), and an exchange already closed but still retransmitting is
    /// dropped too — its keys are gone. Later datagrams for the session are
    /// dropped. A retransmission already collected by a timer wake that is
    /// in flight may still be sent once; nothing further is scheduled.
    /// A no-op once the messenger is stopped.
    public func unregisterSession(localSessionID: UInt16) {
        guard !isStopped else { return }
        // Removed first, so `finishExchange` finds no address and queues no ack.
        guard sessions.removeValue(forKey: localSessionID) != nil else { return }
        subscriptionHandlers = subscriptionHandlers.filter { $0.key.sessionID != localSessionID }
        let scope = SessionScope.secured(localSessionID: localSessionID)
        var unsendable: [Outgoing] = []
        for exchange in manager.exchanges(in: scope) {
            let key = exchange.key
            let wasClosing = closing.contains(key)
            let hadWaiter = waiters[key] != nil
            finishExchange(key, failing: .sessionClosed, into: &unsendable)
            // Out of `closing` as well as the manager: no further MRP.
            removeExchange(key)
            if !wasClosing && !hadWaiter {
                // Its owner (or the handler's closing task) still holds it.
                failed[key] = .sessionClosed
            }
        }
        // The exchanges are gone; this forgets the scope's peer activity.
        _ = manager.closeAll(in: scope)
        rearmTimer()
    }

    /// The session's current peer address (follows the peer's source address).
    public func peerAddress(forSession localSessionID: UInt16) -> MatterAddress? {
        sessions[localSessionID]?.peerAddress
    }

    /// Open an exchange on a registered secure session.
    public func openExchange(sessionID localSessionID: UInt16) throws -> ControllerExchange {
        if isStopped { throw MessagingError.stopped }
        guard let entry = sessions[localSessionID] else {
            throw MessagingError.unknownSession(localSessionID)
        }
        start()
        let key = ExchangeKey(
            scope: .secured(localSessionID: localSessionID),
            exchangeID: manager.allocateExchangeID(),
            initiatedLocally: true
        )
        manager.open(key, peerAddress: entry.peerAddress, config: mrpConfig(for: entry.mrp), now: clock.now)
        return ControllerExchange(key: key, peerAddress: entry.peerAddress, messenger: self)
    }

    // MARK: - Unsolicited messages

    /// Route peer-initiated `ReportData` carrying subscription `id` on local
    /// session `sessionID` to `handler` (nil removes it). Routes are per
    /// (session, subscription ID): IDs are only unique per device. The handler runs in its own task, answers
    /// on the exchange it is given (its `StatusResponse` piggybacks the ack)
    /// and may `receive()` further chunks there; the exchange closes when it
    /// returns — a reliable message still unacknowledged then keeps being
    /// retransmitted until acknowledged or exhausted.
    public func setSubscriptionHandler(_ handler: UnsolicitedHandler?, for id: SubscriptionID, sessionID: UInt16) {
        subscriptionHandlers[SubscriptionRoute(sessionID: sessionID, subscriptionID: id)] = handler
    }

    /// Fallback for peer-initiated messages no subscription handler claims.
    /// Without one, such a message is acknowledged and its exchange closed.
    public func setUnsolicitedHandler(_ handler: UnsolicitedHandler?) {
        unsolicitedHandler = handler
    }
}
