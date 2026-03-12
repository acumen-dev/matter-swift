// SecureMessageCodec.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterCrypto

/// Encodes and decodes encrypted Matter messages.
///
/// Uses the session's encryption keys and the message header as AAD
/// to encrypt/decrypt the exchange header + application payload.
public enum SecureMessageCodec {

    // MARK: - Encode (Encrypt)

    /// Encode an encrypted Matter message.
    ///
    /// Encrypts the exchange header + payload using the session's encrypt key,
    /// with the message header as AAD.
    ///
    /// - Parameters:
    ///   - exchangeHeader: The exchange header to include in the encrypted portion.
    ///   - payload: The application payload.
    ///   - session: The secure session (must have encryption keys).
    ///   - sourceNodeID: The source node ID for nonce construction.
    /// - Returns: The complete encoded message (header + ciphertext + MIC).
    public static func encode(
        exchangeHeader: ExchangeHeader,
        payload: Data,
        session: SecureSession,
        sourceNodeID: NodeID
    ) throws -> Data {
        guard let encryptKey = session.encryptKey else {
            throw SecureCodecError.missingEncryptionKeys
        }

        let counter = session.nextSendCounter()

        let messageHeader = MessageHeader(
            sessionID: session.peerSessionID,
            securityFlags: MessageHeader.SecurityFlags(),
            messageCounter: counter,
            sourceNodeID: sourceNodeID
        )

        // Plaintext = exchange header + payload
        var plaintext = exchangeHeader.encode()
        plaintext.append(payload)

        // AAD = encoded message header
        let headerBytes = messageHeader.encode()

        // Nonce = securityFlags || counter || sourceNodeID
        let nonce = MessageEncryption.buildNonce(
            securityFlags: messageHeader.securityFlags.rawValue,
            messageCounter: counter,
            sourceNodeID: sourceNodeID.rawValue
        )

        let encrypted = try MessageEncryption.encrypt(
            plaintext: plaintext,
            key: encryptKey,
            nonce: nonce,
            aad: headerBytes
        )

        var result = headerBytes
        result.append(encrypted)
        return result
    }

    // MARK: - Decode (Decrypt)

    /// Decode an encrypted Matter message.
    ///
    /// Parses the message header, then decrypts the remaining bytes
    /// using the session's decrypt key and the header as AAD.
    ///
    /// - Parameters:
    ///   - data: The complete raw message bytes.
    ///   - session: The secure session (must have decryption keys).
    /// - Returns: Tuple of (message header, exchange header, decrypted payload).
    public static func decode(
        data: Data,
        session: SecureSession
    ) throws -> (messageHeader: MessageHeader, exchangeHeader: ExchangeHeader, payload: Data) {
        guard let decryptKey = session.decryptKey else {
            throw SecureCodecError.missingEncryptionKeys
        }

        // Parse message header
        let (messageHeader, headerConsumed) = try MessageHeader.decode(from: data)

        // AAD = raw header bytes
        let headerBytes = Data(data.prefix(headerConsumed))
        let ciphertextWithMIC = Data(data.suffix(from: headerConsumed))

        // Nonce from header fields
        let sourceNodeID = messageHeader.sourceNodeID?.rawValue ?? 0
        let nonce = MessageEncryption.buildNonce(
            securityFlags: messageHeader.securityFlags.rawValue,
            messageCounter: messageHeader.messageCounter,
            sourceNodeID: sourceNodeID
        )

        // Decrypt
        let plaintext = try MessageEncryption.decrypt(
            ciphertextWithMIC: ciphertextWithMIC,
            key: decryptKey,
            nonce: nonce,
            aad: headerBytes
        )

        // Parse exchange header from decrypted plaintext
        let (exchangeHeader, exchConsumed) = try ExchangeHeader.decode(from: plaintext)
        let payload = Data(plaintext.suffix(from: exchConsumed))

        return (messageHeader, exchangeHeader, payload)
    }
}

// MARK: - Errors

/// Errors from secure message encoding/decoding.
public enum SecureCodecError: Error, Sendable, Equatable {
    case missingEncryptionKeys
}
