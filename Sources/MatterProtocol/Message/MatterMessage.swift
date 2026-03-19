// MatterMessage.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

/// A decoded Matter message with both headers and payload.
///
/// For unsecured sessions (session ID 0), the exchange header and payload
/// are in plaintext. For encrypted sessions, they are encrypted and the
/// `payload` contains the raw ciphertext + MIC tag.
public struct MatterMessage: Sendable {
    /// The unencrypted message header.
    public var messageHeader: MessageHeader

    /// The exchange header (nil if the payload is still encrypted).
    public var exchangeHeader: ExchangeHeader?

    /// Application payload (plaintext or ciphertext depending on session).
    public var payload: Data

    /// MIC authentication tag (16 bytes, present only for encrypted messages).
    public var mic: Data?

    public init(
        messageHeader: MessageHeader,
        exchangeHeader: ExchangeHeader? = nil,
        payload: Data,
        mic: Data? = nil
    ) {
        self.messageHeader = messageHeader
        self.exchangeHeader = exchangeHeader
        self.payload = payload
        self.mic = mic
    }
}

// MARK: - Message Constants

extension MatterMessage {
    /// MIC (Message Integrity Code) tag length for encrypted messages.
    public static let micLength = 16

    /// AES-128-CCM nonce length.
    public static let nonceLength = 13

    /// AES-128-CCM key length.
    public static let keyLength = 16

    /// Default Matter UDP port.
    public static let defaultPort: UInt16 = 5540

    /// Maximum Matter message size over UDP.
    ///
    /// IPv6 minimum MTU is 1280 bytes. Subtract 48 bytes for IPv6 (40) + UDP (8) headers.
    public static let maxUDPPayloadSize = 1232

    /// Overhead added by encryption (message header, exchange header, MIC).
    ///
    /// Budget for worst-case header sizes (matches matter.js MATTER_MESSAGE_OVERHEAD):
    /// - Message header: up to 28 bytes (flags + sessionID + securityFlags + counter
    ///   + sourceNodeID + destinationNodeID). Secured unicast uses only 8, but we
    ///   budget conservatively to match other implementations.
    /// - Exchange header: up to 12 bytes (flags + opcode + exchangeID + vendorID
    ///   + protocolID + ackCounter)
    /// - AES-CCM MIC (MAC tag): 16 bytes
    /// Total: 56 bytes worst-case. Use 54 to match matter.js (known-working with
    /// Apple Home). The CHIP SDK uses a similar conservative budget.
    public static let encryptedMessageOverhead = 54

    /// Maximum usable payload size for Interaction Model messages over UDP.
    ///
    /// This is the max TLV payload that, after adding encrypted message framing,
    /// fits within a single UDP datagram on the minimum IPv6 MTU (1280 bytes).
    /// = maxUDPPayloadSize - encryptedMessageOverhead = 1232 - 54 = 1178
    public static let maxIMPayloadSize = maxUDPPayloadSize - encryptedMessageOverhead
}

// MARK: - Encoding (Unsecured)

extension MatterMessage {
    /// Encode an unsecured message (plaintext exchange header + payload).
    public static func encodeUnsecured(
        messageHeader: MessageHeader,
        exchangeHeader: ExchangeHeader,
        payload: Data
    ) -> Data {
        var buffer = Data()

        buffer.append(messageHeader.encode())
        buffer.append(exchangeHeader.encode())
        buffer.append(payload)

        return buffer
    }
}

// MARK: - Decoding (Unsecured)

extension MatterMessage {
    /// Decode a complete unsecured message from raw bytes.
    ///
    /// For unsecured sessions (session ID 0), both headers and payload
    /// are in plaintext.
    public static func decodeUnsecured(from data: Data) throws -> MatterMessage {
        // Decode message header
        let (msgHeader, msgConsumed) = try MessageHeader.decode(from: data)

        // For unsecured sessions, the rest is plaintext exchange header + payload
        let remaining = data[msgConsumed...]

        let (exchHeader, exchConsumed) = try ExchangeHeader.decode(
            from: Data(remaining)
        )

        let payload = Data(remaining.dropFirst(exchConsumed))

        return MatterMessage(
            messageHeader: msgHeader,
            exchangeHeader: exchHeader,
            payload: payload
        )
    }

    /// Decode only the message header from raw bytes, leaving the payload
    /// as raw data (for encrypted messages that need decryption first).
    public static func decodeHeader(from data: Data) throws -> (header: MessageHeader, payload: Data) {
        let (header, consumed) = try MessageHeader.decode(from: data)
        let payload = Data(data[consumed...])
        return (header, payload)
    }
}
