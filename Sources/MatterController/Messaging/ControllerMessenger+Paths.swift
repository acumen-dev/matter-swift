// ControllerMessenger+Paths.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Logging
import MatterProtocol
import MatterTransport

extension ControllerMessenger {

    // MARK: - Pinned sends

    /// The single way a frame leaves: by the path exchange `key` is pinned to, or, when none
    /// is pinned yet, by the path the transport selects under ``Configuration/interfaces`` —
    /// which then becomes the pin (an unsecured exchange's, or its secure session's). So a
    /// selection runs once per exchange or session, never per frame.
    ///
    /// Path failures are handled here, not thrown:
    /// - `pathUnavailable` on a secure session re-selects and resends once (the peer accepts
    ///   the new source, since the message authenticates); on an unsecured exchange (a
    ///   handshake) it fails the exchange at once with ``MessagingError/pathLost(_:_:)``;
    /// - `noAllowedRoute` fails the exchange with ``MessagingError/noAllowedRoute(_:peer:)``
    ///   when the frame is its owner's (`fromOwner`) or a reliable message is outstanding on
    ///   it, and drops anything else (an ack the messenger sends on its own).
    ///
    /// Any other transport error is thrown.
    ///
    /// The exchange's current pin wins; `queuedPath`, the pin when the frame was queued, is
    /// used once the exchange is forgotten (so the ack `close()` flushes still leaves by the
    /// handshake's path, and a secure ack still follows an arrival re-pin).
    func sendPinned(
        _ bytes: Data,
        to address: MatterAddress,
        key: ExchangeKey?,
        queuedPath: MatterPath? = nil,
        fromOwner: Bool = false
    ) async throws {
        await awaitInterfacePolicy()
        let pinned = key.flatMap(pinnedPath(for:)) ?? queuedPath
        do {
            let result = try await transport.send(bytes, to: address, via: pinned)
            if pinned == nil, let key, let result {
                recordSelection(result, key: key)
            }
        } catch let error as TransportPathError {
            guard let key else { throw error }
            switch error {
            case .pathUnavailable(let lost, _):
                switch key.scope {
                case .secured(let localSessionID):
                    try await reselect(bytes, to: address, key: key, sessionID: localSessionID, lost: lost, fromOwner: fromOwner)
                case .unsecured:
                    handshakePathLost(key, lost: lost, peer: address)
                }
            case .noAllowedRoute:
                noAllowedRoute(key, peer: address, fromOwner: fromOwner)
            }
        }
    }

    /// Wait, once, for ``Configuration/interfaces`` to reach the transport.
    func awaitInterfacePolicy() async {
        guard let applying = policyApplied else { return }
        await applying.value
        policyApplied = nil
    }

    /// Pin exchange `key` (or its session) to the path a send selected, and count the
    /// selection. Nothing is pinned — or counted — for an exchange or session that went away
    /// while the send was in flight (an ack of a stale exchange), nor over a pin another send
    /// set meanwhile (the first selection holds). Returns whether it pinned.
    @discardableResult
    func recordSelection(_ result: MatterSendResult, key: ExchangeKey) -> Bool {
        switch key.scope {
        case .unsecured:
            guard manager.exchange(for: key) != nil, exchangePaths[key] == nil else { return false }
            exchangePaths[key] = result.path
            transportLogger.debug(
                "Exchange \(key.exchangeID) pinned to \(result.path)",
                metadata: Self.exchangeMetadata(key).merging(Self.pathMetadata(result.path)) { $1 }
            )
        case .secured(let localSessionID):
            guard var entry = sessions[localSessionID], entry.path == nil else { return false }
            entry.path = result.path
            sessions[localSessionID] = entry
            sessionLogger.debug(
                "Session \(MatterLogValue.hexString(localSessionID)) pinned to \(result.path)",
                metadata: Self.pathMetadata(result.path).merging([MatterLogKey.session: MatterLogValue.hex(localSessionID)]) { $1 }
            )
        }
        if let outcome = result.selection {
            telemetry.metrics.pathSelections[outcome]?.increment()
        }
        return true
    }

    /// A secure session's pinned path lost its route: unpin, resend once by a fresh
    /// selection, and pin the session to what it chose. If another send already re-pinned
    /// the session meanwhile, resend by that path instead.
    func reselect(
        _ bytes: Data, to address: MatterAddress, key: ExchangeKey, sessionID: UInt16, lost: MatterPath, fromOwner: Bool
    ) async throws {
        let session = MatterLogValue.hexString(sessionID)
        if var entry = sessions[sessionID], entry.path == lost {
            entry.path = nil
            sessions[sessionID] = entry
            sessionLogger.info(
                "Session \(session): \(lost.interfaceName) lost its route to \(MatterLogValue.address(address)); re-selecting",
                metadata: Self.pathMetadata(lost).merging([
                    MatterLogKey.session: MatterLogValue.hex(sessionID),
                    MatterLogKey.reason: "route_lost",
                ]) { $1 }
            )
        }
        let current = pinnedPath(for: key)
        let result: MatterSendResult?
        do {
            result = try await transport.send(bytes, to: address, via: current)
        } catch TransportPathError.noAllowedRoute {
            noAllowedRoute(key, peer: address, fromOwner: fromOwner)
            return
        }
        guard current == nil, let result, recordSelection(result, key: key) else { return }
        telemetry.metrics.pathRepins[.routeLost]?.increment()
        sessionLogger.info(
            "Session \(session) re-pinned to \(result.path)",
            metadata: Self.pathMetadata(result.path).merging([
                MatterLogKey.session: MatterLogValue.hex(sessionID),
                MatterLogKey.reason: "route_lost",
            ]) { $1 }
        )
    }

    /// An unsecured exchange's pinned path lost its route. A handshake cannot change source
    /// address midway, so it fails at once; the next attempt selects afresh.
    func handshakePathLost(_ key: ExchangeKey, lost: MatterPath, peer: MatterAddress) {
        guard manager.exchange(for: key) != nil else { return }
        transportLogger.info(
            "Exchange \(key.exchangeID): \(lost.interfaceName) lost its route to \(MatterLogValue.address(peer)); failing the handshake",
            metadata: Self.exchangeMetadata(key).merging(Self.pathMetadata(lost)) { $1 }
                .merging([MatterLogKey.reason: "path_lost"]) { $1 }
        )
        failExchange(key, with: .pathLost(key, lost))
    }

    /// No allowed interface has a route to `peer`. The exchange fails now when its owner
    /// sent the frame (reliable or not) or a reliable message is outstanding on it: MRP
    /// retransmitting into no path only delays the same answer. A frame the messenger sends
    /// on its own with nothing outstanding behind it (an ack) is dropped.
    func noAllowedRoute(_ key: ExchangeKey, peer: MatterAddress, fromOwner: Bool) {
        let metadata = Self.exchangeMetadata(key).merging([MatterLogKey.reason: "no_allowed_route"]) { $1 }
        guard let exchange = manager.exchange(for: key), fromOwner || exchange.pendingMessage != nil else {
            transportLogger.warning(
                "No allowed interface has a route to \(MatterLogValue.address(peer)); dropping a frame on exchange \(key.exchangeID)",
                metadata: metadata
            )
            return
        }
        transportLogger.warning(
            "No allowed interface has a route to \(MatterLogValue.address(peer)); failing exchange \(key.exchangeID)",
            metadata: metadata
        )
        failExchange(key, with: .noAllowedRoute(key, peer: peer))
    }

    /// End exchange `key` with `error` and forget it, an unacknowledged reliable message
    /// included: unlike ``finishExchange(_:failing:into:)`` nothing is left for MRP, since
    /// there is no path to retransmit by. Acks owed on it are dropped for the same reason.
    /// An owner not waiting hears of it from its next `send`/`receive`.
    func failExchange(_ key: ExchangeKey, with error: MessagingError) {
        let wasClosing = closing.contains(key)
        let hadWaiter = waiters[key] != nil
        var unsendable: [Outgoing] = []
        finishExchange(key, failing: error, into: &unsendable)
        removeExchange(key)
        if !wasClosing && !hadWaiter {
            failed[key] = error
        }
        rearmTimer()
    }

    // MARK: - Arrival

    /// An authenticated, de-duplicated message on session `sessionID` arrived on `arrival`,
    /// not its pinned path. An allowed interface becomes the session's pin (replies leave by
    /// the address the peer sent to); an excluded one is accepted but never replied through.
    func repinOnArrival(_ entry: inout SessionEntry, sessionID: UInt16, arrival: MatterPath) {
        let session = MatterLogValue.hexString(sessionID)
        guard configuration.interfaces.allows(arrival.interfaceName) else {
            sessionLogger.debug(
                "Session \(session): traffic arrived on excluded \(arrival.interfaceName); keeping \(entry.path?.description ?? "no pin")",
                metadata: Self.pathMetadata(arrival).merging([
                    MatterLogKey.session: MatterLogValue.hex(sessionID),
                    MatterLogKey.reason: "excluded",
                ]) { $1 }
            )
            return
        }
        let old = entry.path
        entry.path = arrival
        sessionLogger.info(
            "Session \(session) re-pinned \(old?.interfaceName ?? "none") → \(arrival.interfaceName) (traffic arrived on \(arrival.interfaceName))",
            metadata: Self.pathMetadata(arrival).merging([
                MatterLogKey.session: MatterLogValue.hex(sessionID),
                MatterLogKey.reason: "arrival",
            ]) { $1 }
        )
        if old != nil {
            telemetry.metrics.pathRepins[.arrival]?.increment()
        }
    }

    // MARK: - Metadata

    /// `matter.interface` and `matter.local_address` of `path`.
    static func pathMetadata(_ path: MatterPath) -> Logger.Metadata {
        [
            MatterLogKey.interface: .string(path.interfaceName),
            MatterLogKey.localAddress: .string(path.localAddress),
        ]
    }
}
