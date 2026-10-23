// ControllerExchange.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterProtocol
import MatterTransport

/// A handle on one exchange run by a ``ControllerMessenger``.
///
/// Messages arriving between ``send(protocolID:opcode:payload:reliable:)``
/// and ``receive(timeout:)`` are queued, never lost. Always ``close()`` the
/// exchange when done: that sends any ack still owed.
public struct ControllerExchange: Sendable {
    public let key: ExchangeKey
    public let peerAddress: MatterAddress
    public let messenger: ControllerMessenger

    /// Send one message on the exchange, piggybacking any owed ack. A
    /// reliable message is retransmitted by MRP (same bytes, same counter)
    /// until acknowledged; a failure to acknowledge surfaces from
    /// ``receive(timeout:)`` as ``MessagingError/peerUnreachable(_:transmissions:)``.
    public func send(protocolID: MatterProtocolID, opcode: UInt8, payload: Data, reliable: Bool = true) async throws {
        try await messenger.send(key, protocolID: protocolID, opcode: opcode, payload: payload, reliable: reliable)
    }

    /// The next message on the exchange. The effective wait is always
    /// `max(timeout, MRP exhaustion horizon)` -- the larger of the idle and
    /// active horizons (up to ~109 s for a peer with SII 5000). On expiry it
    /// fails with ``MessagingError/responseTimeout(_:)`` and closes the
    /// exchange exactly as ``close()`` does (a pending reliable message keeps
    /// retransmitting until acked or exhausted). The deadline is fixed when
    /// `receive` starts: a reliable send issued while a receive is already
    /// waiting can outlive it (intended).
    ///
    /// Cancelling the calling task fails the receive with `CancellationError`
    /// and closes the exchange exactly as ``close()`` does: an
    /// unacknowledged reliable message keeps being retransmitted until
    /// acknowledged or exhausted.
    public func receive(timeout: Duration) async throws -> InboundMessage {
        try await messenger.receive(key, timeout: timeout)
    }

    /// ``send(protocolID:opcode:payload:reliable:)`` (reliable) then ``receive(timeout:)``.
    public func request(protocolID: MatterProtocolID, opcode: UInt8, payload: Data, timeout: Duration) async throws -> InboundMessage {
        try await send(protocolID: protocolID, opcode: opcode, payload: payload)
        return try await receive(timeout: timeout)
    }

    /// The path the exchange's frames leave by: its own for an unsecured
    /// exchange (pinned by its first send, or by the peer's first message),
    /// its session's for a secure one. Nil while none is pinned, when the
    /// transport cannot tell, and once an unsecured exchange is closed — read
    /// a handshake's path before ``close()``.
    public func path() async -> MatterPath? {
        await messenger.pinnedPath(for: key)
    }

    /// Close: send any owed ack now, stop delivering messages, and fail a
    /// pending ``receive(timeout:)`` with ``MessagingError/exchangeClosed``.
    /// An unacknowledged reliable message is *not* abandoned: MRP keeps
    /// retransmitting it until it is acknowledged or exhausted (silently),
    /// and late messages on the exchange are acknowledged but not delivered.
    /// Idempotent.
    public func close() async {
        await messenger.closeExchange(key)
    }
}
