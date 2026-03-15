// MessageEncryption.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import _CryptoExtras

/// AES-128-CCM message encryption and decryption for Matter sessions.
///
/// Matter uses AES-128-CCM (RFC 3610) with:
/// - 16-byte key
/// - 13-byte nonce (L=2, so the length field is 2 bytes)
/// - 16-byte MIC (M=16, authentication tag)
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

    /// Encrypt a plaintext payload using AES-128-CCM (RFC 3610).
    ///
    /// Matter parameters: L=2, M=16, 13-byte nonce.
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
        // Compute CBC-MAC tag over plaintext
        let tag = try cbcMac(plaintext: plaintext, key: key, nonce: nonce, aad: aad)

        // Encrypt tag: encryptedTag = tag XOR AES_K(A_0)
        let a0 = counterBlock(nonce: nonce, counter: 0)
        let s0 = try aesBlock(a0, key: key)
        var encryptedTag = Data(count: micLength)
        for i in 0..<micLength {
            encryptedTag[i] = tag[i] ^ s0[i]
        }

        // Encrypt plaintext: ciphertext[i] = plaintext[i] XOR S_{block+1}
        let ciphertext = try ctrEncrypt(data: plaintext, key: key, nonce: nonce, startCounter: 1)

        var result = ciphertext
        result.append(encryptedTag)
        return result
    }

    // MARK: - Decrypt

    /// Decrypt a ciphertext payload using AES-128-CCM (RFC 3610).
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
        let encryptedTag = ciphertextWithMIC.suffix(micLength)

        // Decrypt plaintext
        let plaintext = try ctrEncrypt(data: Data(ciphertext), key: key, nonce: nonce, startCounter: 1)

        // Decrypt tag: tag = encryptedTag XOR AES_K(A_0)
        let a0 = counterBlock(nonce: nonce, counter: 0)
        let s0 = try aesBlock(a0, key: key)
        var tag = Data(count: micLength)
        for i in 0..<micLength {
            tag[i] = encryptedTag[encryptedTag.startIndex + i] ^ s0[i]
        }

        // Recompute CBC-MAC tag over decrypted plaintext and verify
        let expectedTag = try cbcMac(plaintext: plaintext, key: key, nonce: nonce, aad: aad)

        // Constant-time comparison
        guard constantTimeEqual(tag, expectedTag) else {
            throw CryptoError.authenticationFailed
        }

        return plaintext
    }

    // MARK: - AES-128-CCM Internals

    /// Compute the CBC-MAC authentication tag (RFC 3610 Section 2.2).
    private static func cbcMac(
        plaintext: Data,
        key: SymmetricKey,
        nonce: Data,
        aad: Data
    ) throws -> Data {
        let plaintextLength = plaintext.count

        // B_0 flags: Adata | ((M-2)/2) << 3 | (L-1)
        // M=16 -> (16-2)/2 = 7 -> 7 << 3 = 0x38
        // L=2  -> L-1 = 1 -> 0x01
        // Adata bit (0x40) set when aad is non-empty
        let adataFlag: UInt8 = aad.isEmpty ? 0x00 : 0x40
        let flags: UInt8 = adataFlag | 0x38 | 0x01  // 0x59 with AAD, 0x19 without

        // Format B_0 (16 bytes)
        var b0 = Data(count: 16)
        b0[0] = flags
        // Bytes 1..13: nonce (13 bytes)
        let nonceBytes = Array(nonce)
        for i in 0..<13 {
            b0[1 + i] = nonceBytes[i]
        }
        // Bytes 14..15: plaintext length as big-endian UInt16
        b0[14] = UInt8((plaintextLength >> 8) & 0xFF)
        b0[15] = UInt8(plaintextLength & 0xFF)

        // T = AES_K(B_0)
        var t = try aesBlock(b0, key: key)

        // Process AAD if non-empty
        if !aad.isEmpty {
            // Encode AAD: 2-byte big-endian length prepended, then AAD bytes, padded to 16-byte boundary
            var aadEncoded = Data(count: 2 + aad.count)
            aadEncoded[0] = UInt8((aad.count >> 8) & 0xFF)
            aadEncoded[1] = UInt8(aad.count & 0xFF)
            aadEncoded.replaceSubrange(2..<(2 + aad.count), with: aad)
            let paddedAAD = padToBlockSize(aadEncoded)

            // CBC-MAC over AAD blocks
            for blockStart in stride(from: 0, to: paddedAAD.count, by: 16) {
                let block = paddedAAD[blockStart..<(blockStart + 16)]
                t = try cbcStep(t, Data(block), key: key)
            }
        }

        // Process plaintext: pad to 16-byte boundary
        if plaintextLength > 0 {
            let paddedPlaintext = padToBlockSize(plaintext)
            for blockStart in stride(from: 0, to: paddedPlaintext.count, by: 16) {
                let block = paddedPlaintext[blockStart..<(blockStart + 16)]
                t = try cbcStep(t, Data(block), key: key)
            }
        }

        return t
    }

    /// CTR-mode encryption/decryption: data XOR keystream starting at the given counter.
    private static func ctrEncrypt(
        data: Data,
        key: SymmetricKey,
        nonce: Data,
        startCounter: UInt16
    ) throws -> Data {
        var result = Data(count: data.count)
        var counter = startCounter
        var offset = 0

        while offset < data.count {
            let a = counterBlock(nonce: nonce, counter: counter)
            let s = try aesBlock(a, key: key)

            let blockEnd = min(offset + 16, data.count)
            let blockLen = blockEnd - offset
            for i in 0..<blockLen {
                result[offset + i] = data[data.startIndex + offset + i] ^ s[i]
            }

            offset += blockLen
            counter &+= 1
        }

        return result
    }

    /// Format counter block A_i (16 bytes): flags=L-1=0x01, nonce, counter as big-endian UInt16.
    private static func counterBlock(nonce: Data, counter: UInt16) -> Data {
        var a = Data(count: 16)
        a[0] = 0x01  // L-1 = 2-1 = 1
        let nonceBytes = Array(nonce)
        for i in 0..<13 {
            a[1 + i] = nonceBytes[i]
        }
        a[14] = UInt8((counter >> 8) & 0xFF)
        a[15] = UInt8(counter & 0xFF)
        return a
    }

    /// AES_K(block): encrypt a single 16-byte block using AES-128.
    ///
    /// Implemented via AES-CBC with a zero IV: CBC output[0] = AES_K(IV XOR block) = AES_K(block).
    private static func aesBlock(_ block: Data, key: SymmetricKey) throws -> Data {
        // AES-CBC with zero IV and a single 16-byte block (no padding needed).
        // CBC: output[0] = AES_K(IV XOR block) = AES_K(0 XOR block) = AES_K(block)
        let zeroIV = try AES._CBC.IV(ivBytes: [UInt8](repeating: 0, count: 16))
        let encrypted = try AES._CBC.encrypt(block, using: key, iv: zeroIV)
        return Data(encrypted.prefix(16))
    }

    /// One step of CBC-MAC: T = AES_K(T XOR block).
    private static func cbcStep(_ t: Data, _ block: Data, key: SymmetricKey) throws -> Data {
        var xored = Data(t)
        for i in 0..<16 {
            xored[i] ^= block[i]
        }
        return try aesBlock(xored, key: key)
    }

    /// Pad data to a multiple of 16 bytes with zero bytes.
    private static func padToBlockSize(_ data: Data) -> Data {
        let remainder = data.count % 16
        guard remainder != 0 else { return data }
        var padded = data
        padded.append(contentsOf: [UInt8](repeating: 0, count: 16 - remainder))
        return padded
    }

    /// Constant-time comparison of two Data values to prevent timing attacks.
    private static func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var result: UInt8 = 0
        for i in 0..<a.count {
            result |= a[a.startIndex + i] ^ b[b.startIndex + i]
        }
        return result == 0
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
