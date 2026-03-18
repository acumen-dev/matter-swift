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

        // For CASE sessions, the source node ID is used in the nonce but NOT
        // included in the wire header (per CHIP SDK SessionManager.cpp line ~287).
        // For PASE sessions, sourceNodeID=0 and also not in the header.
        // The local node ID is needed for nonce construction so the peer can
        // decrypt using its stored peerNodeID.
        let nonceNodeID: UInt64 = session.establishment == .case
            ? (session.localNodeID?.rawValue ?? sourceNodeID.rawValue)
            : 0

        let messageHeader = MessageHeader(
            sessionID: session.peerSessionID,
            securityFlags: MessageHeader.SecurityFlags(),
            messageCounter: counter,
            sourceNodeID: nil  // Not included in header for secured unicast
        )

        // Plaintext = exchange header + payload
        var plaintext = exchangeHeader.encode()
        plaintext.append(payload)

        // AAD = encoded message header
        let headerBytes = messageHeader.encode()

        // Nonce = securityFlags || counter || localNodeID
        // The node ID in the nonce is the sender's node ID, which the peer
        // uses via its stored peerNodeID to construct the same nonce for decryption.
        let nonce = MessageEncryption.buildNonce(
            securityFlags: messageHeader.securityFlags.rawValue,
            messageCounter: counter,
            sourceNodeID: nonceNodeID
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

        // Nonce construction: the source node ID is NOT taken from the message
        // header — for secured unicast, the source node ID field is absent from
        // the wire format. Instead, use the peer's node ID from the session:
        //   - CASE: peer node ID assigned during commissioning (from NOC)
        //   - PASE: 0 (kUndefinedNodeId, no node identity yet)
        // This matches the CHIP SDK (SessionManager.cpp line ~998):
        //   BuildNonce(secType == kCASE ? GetPeerNodeId() : kUndefinedNodeId)
        let sourceNodeID: UInt64 = session.establishment == .case
            ? session.peerNodeID.rawValue
            : 0
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
