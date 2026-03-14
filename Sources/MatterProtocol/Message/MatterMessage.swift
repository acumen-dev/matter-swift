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
    public static let maxUDPPayloadSize = 1280

    /// Overhead added by encryption (exchange header, MIC, framing).
    public static let encryptedMessageOverhead = 42

    /// Maximum usable payload size for Interaction Model messages over UDP.
    public static let maxIMPayloadSize = 1232
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
