// MessageEncryption.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto

/// AES-128-CCM message encryption and decryption for Matter sessions.
///
/// Matter uses AES-128-CCM with:
/// - 16-byte key
/// - 13-byte nonce (security flags + counter + source node ID)
/// - 16-byte MIC (authentication tag)
/// - AAD = raw message header bytes
public enum MessageEncryption {

    /// AES-128 key length in bytes.
    public static let keyLength = 16

    /// CCM nonce length in bytes.
    public static let nonceLength = 13

    /// MIC (authentication tag) length in bytes.
    public static let micLength = 16

    // MARK: - Nonce Construction

    /// Construct the 13-byte nonce for AES-128-CCM.
    ///
    /// ```
    /// Nonce[0]     = securityFlags  (1 byte)
    /// Nonce[1..4]  = messageCounter (4 bytes, little-endian)
    /// Nonce[5..12] = sourceNodeID   (8 bytes, little-endian)
    /// ```
    ///
    /// - Parameters:
    ///   - securityFlags: The security flags byte from the message header.
    ///   - messageCounter: The message counter (little-endian).
    ///   - sourceNodeID: The source node ID (little-endian). Use 0 for PASE sessions.
    /// - Returns: 13-byte nonce.
    public static func buildNonce(
        securityFlags: UInt8,
        messageCounter: UInt32,
        sourceNodeID: UInt64
    ) -> Data {
        var nonce = Data(capacity: nonceLength)
        nonce.append(securityFlags)
        nonce.appendLittleEndian(messageCounter)
        nonce.appendLittleEndian(sourceNodeID)
        return nonce
    }

    // MARK: - Encrypt

    /// Encrypt a plaintext payload using AES-128-CCM.
    ///
    /// - Parameters:
    ///   - plaintext: The data to encrypt (exchange header + application payload).
    ///   - key: 16-byte encryption key.
    ///   - nonce: 13-byte nonce.
    ///   - aad: Additional authenticated data (message header bytes).
    /// - Returns: Ciphertext with 16-byte MIC appended.
    public static func encrypt(
        plaintext: Data,
        key: SymmetricKey,
        nonce: Data,
        aad: Data
    ) throws -> Data {
        let sealedBox = try AES.GCM.seal(
            plaintext,
            using: key,
            nonce: try AES.GCM.Nonce(data: nonce),
            authenticating: aad
        )

        // AES-GCM output: ciphertext + tag
        var result = Data(sealedBox.ciphertext)
        result.append(contentsOf: sealedBox.tag)
        return result
    }

    /// Decrypt a ciphertext payload using AES-128-CCM.
    ///
    /// - Parameters:
    ///   - ciphertextWithMIC: Encrypted data with 16-byte MIC appended.
    ///   - key: 16-byte decryption key.
    ///   - nonce: 13-byte nonce.
    ///   - aad: Additional authenticated data (message header bytes).
    /// - Returns: Decrypted plaintext.
    public static func decrypt(
        ciphertextWithMIC: Data,
        key: SymmetricKey,
        nonce: Data,
        aad: Data
    ) throws -> Data {
        guard ciphertextWithMIC.count >= micLength else {
            throw CryptoError.invalidCiphertext
        }

        let ciphertext = ciphertextWithMIC.prefix(ciphertextWithMIC.count - micLength)
        let tag = ciphertextWithMIC.suffix(micLength)

        let sealedBox = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: nonce),
            ciphertext: ciphertext,
            tag: tag
        )

        return Data(try AES.GCM.open(sealedBox, using: key, authenticating: aad))
    }
}

// MARK: - Data Extensions

extension Data {
    mutating func appendLittleEndian(_ value: UInt32) {
        append(UInt8(value & 0xFF))
        append(UInt8((value >> 8) & 0xFF))
        append(UInt8((value >> 16) & 0xFF))
        append(UInt8((value >> 24) & 0xFF))
    }

    mutating func appendLittleEndian(_ value: UInt64) {
        for i in 0..<8 {
            append(UInt8((value >> (i * 8)) & 0xFF))
        }
    }
}
