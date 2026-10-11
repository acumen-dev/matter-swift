// InboundMessage.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterProtocol
import MatterTransport

/// A decoded (and, for secure sessions, decrypted) message delivered to an
/// exchange.
public struct InboundMessage: Sendable, Equatable {
    /// The exchange it belongs to.
    public let key: ExchangeKey
    /// Where it came from (for a secure session, also the session's address now).
    public let peerAddress: MatterAddress
    public let messageCounter: UInt32
    public let protocolID: UInt16
    public let opcode: UInt8
    /// Application payload (after the exchange header).
    public let payload: Data
    /// The sender asked for an ack (R flag); the messenger owes it.
    public let requiresAck: Bool
    /// Counter this message acknowledged (A flag), if any.
    public let acknowledgedCounter: UInt32?
}

/// Failures of the controller message layer.
public enum MessagingError: Error, Sendable, Equatable {
    /// No secure session is registered under this local session ID.
    case unknownSession(UInt16)
    /// The exchange was closed (by its owner, by cancellation, or idle).
    case exchangeClosed
    /// `receive()` is already waiting on this exchange.
    case receiveAlreadyPending
    /// A reliable message sent on this exchange is still unacknowledged; a
    /// second one would replace it and MRP would stop retransmitting the first.
    case sendAlreadyPending
    /// The message was acknowledged but nothing arrived within the timeout.
    case responseTimeout(ExchangeKey)
    /// Every transmission went unacknowledged (MRP exhausted).
    case peerUnreachable(ExchangeKey, transmissions: Int)
    /// The secure session was unregistered while the exchange was open.
    case sessionClosed
    /// The messenger has been stopped.
    case stopped
    /// A reply arrived on an unexpected protocol.
    case unexpectedProtocol(protocolID: UInt16, opcode: UInt8)
}
