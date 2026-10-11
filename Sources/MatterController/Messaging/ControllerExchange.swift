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

    /// The next message on the exchange. While our last reliable message is
    /// still unacknowledged the wait extends to the MRP exhaustion horizon,
    /// so the effective wait is `max(timeout, horizon)`.
    public func receive(timeout: Duration) async throws -> InboundMessage {
        try await messenger.receive(key, timeout: timeout)
    }

    /// ``send(protocolID:opcode:payload:reliable:)`` (reliable) then ``receive(timeout:)``.
    public func request(protocolID: MatterProtocolID, opcode: UInt8, payload: Data, timeout: Duration) async throws -> InboundMessage {
        try await send(protocolID: protocolID, opcode: opcode, payload: payload)
        return try await receive(timeout: timeout)
    }

    /// Close: send any owed ack now, stop retransmitting, and fail a pending
    /// ``receive(timeout:)`` with ``MessagingError/exchangeClosed``. Idempotent.
    public func close() async {
        await messenger.closeExchange(key)
    }
}
