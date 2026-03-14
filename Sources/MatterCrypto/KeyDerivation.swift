// KeyDerivation.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto

/// Key derivation functions used in the Matter protocol.
///
/// All key derivation uses HKDF-SHA256 and PBKDF2-HMAC-SHA256.
public enum KeyDerivation {

    // MARK: - Session Key Derivation

    /// Info string for session key derivation from PASE/CASE shared secret.
    public static let sessionKeysInfo = Data("SessionKeys".utf8)

    /// Info string for session resumption key derivation.
    public static let resumptionKeysInfo = Data("SessionResumptionKeys".utf8)

    /// Info string for SPAKE2+ confirmation keys.
    public static let confirmationKeysInfo = Data("ConfirmationKeys".utf8)

    /// Derive session encryption keys from a shared secret (Ke).
    ///
    /// Produces 48 bytes:
    /// - `I2R_Key` (bytes 0-15): Initiator-to-Responder encryption key
    /// - `R2I_Key` (bytes 16-31): Responder-to-Initiator encryption key
    /// - `AttestationKey` (bytes 32-47): Attestation challenge key
    ///
    /// - Parameters:
    ///   - sharedSecret: The shared secret (Ke) from SPAKE2+ or CASE.
    ///   - salt: Optional salt (empty for PASE, session-specific for CASE).
    ///   - info: Info string ("SessionKeys" or "SessionResumptionKeys").
    /// - Returns: `SessionKeys` containing the three derived keys.
    public static func deriveSessionKeys(
        sharedSecret: Data,
        salt: Data = Data(),
        info: Data = sessionKeysInfo
    ) -> SessionKeys {
        let ikm = SymmetricKey(data: sharedSecret)
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm,
            salt: salt,
            info: info,
            outputByteCount: 48
        )

        let bytes = derived.withUnsafeBytes { Data($0) }
        return SessionKeys(
            i2rKey: SymmetricKey(data: bytes[0..<16]),
            r2iKey: SymmetricKey(data: bytes[16..<32]),
            attestationKey: SymmetricKey(data: bytes[32..<48])
        )
    }

    /// Derive a group operational key from an epoch key per Matter spec §4.16.2.2.1.
    ///
    /// Uses HKDF-SHA256 with:
    /// - `salt`: compressedFabricID as 8-byte big-endian Data
    /// - `info`: "GroupKey v1.0" UTF-8
    /// - `outputByteCount`: 16 (128-bit AES key)
    ///
    /// - Parameters:
    ///   - epochKey: The 16-byte epoch key from the GroupKeySet.
    ///   - compressedFabricID: The compressed fabric ID (8 bytes, big-endian).
    /// - Returns: A 16-byte symmetric key suitable for AES-128-CCM group message encryption.
    public static func deriveGroupOperationalKey(epochKey: Data, compressedFabricID: UInt64) -> SymmetricKey {
        let ikm = SymmetricKey(data: epochKey)
        // Salt: compressedFabricID as 8-byte big-endian
        var saltBytes = Data(count: 8)
        saltBytes[0] = UInt8((compressedFabricID >> 56) & 0xFF)
        saltBytes[1] = UInt8((compressedFabricID >> 48) & 0xFF)
        saltBytes[2] = UInt8((compressedFabricID >> 40) & 0xFF)
        saltBytes[3] = UInt8((compressedFabricID >> 32) & 0xFF)
        saltBytes[4] = UInt8((compressedFabricID >> 24) & 0xFF)
        saltBytes[5] = UInt8((compressedFabricID >> 16) & 0xFF)
        saltBytes[6] = UInt8((compressedFabricID >> 8) & 0xFF)
        saltBytes[7] = UInt8(compressedFabricID & 0xFF)
        let info = Data("GroupKey v1.0".utf8)
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm,
            salt: saltBytes,
            info: info,
            outputByteCount: 16
        )
    }

    /// Derive SPAKE2+ confirmation keys from Ka.
    ///
    /// Produces 32 bytes:
    /// - `KcA` (bytes 0-15): Prover confirmation key
    /// - `KcB` (bytes 16-31): Verifier confirmation key
    ///
    /// - Parameters:
    ///   - ka: First half of the transcript hash (16 bytes).
    /// - Returns: Tuple of (KcA, KcB) as `SymmetricKey`.
    public static func deriveConfirmationKeys(
        ka: Data
    ) -> (kcA: SymmetricKey, kcB: SymmetricKey) {
        let ikm = SymmetricKey(data: ka)
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm,
            salt: Data(), // empty salt
            info: confirmationKeysInfo,
            outputByteCount: 32
        )

        let bytes = derived.withUnsafeBytes { Data($0) }
        return (
            kcA: SymmetricKey(data: bytes[0..<16]),
            kcB: SymmetricKey(data: bytes[16..<32])
        )
    }

    // MARK: - PBKDF2

    /// Derive SPAKE2+ w0s and w1s from a passcode using PBKDF2-HMAC-SHA256.
    ///
    /// - Parameters:
    ///   - passcode: The setup passcode (e.g., 20202021).
    ///   - salt: Random salt (16-32 bytes).
    ///   - iterations: PBKDF2 iteration count (1000-100000).
    /// - Returns: 80 bytes: w0s (first 40) and w1s (last 40).
    public static func pbkdf2DeriveWS(
        passcode: UInt32,
        salt: Data,
        iterations: Int
    ) -> Data {
        // Encode passcode as 4-byte little-endian
        var passcodeBytes = Data(count: 4)
        passcodeBytes[0] = UInt8(passcode & 0xFF)
        passcodeBytes[1] = UInt8((passcode >> 8) & 0xFF)
        passcodeBytes[2] = UInt8((passcode >> 16) & 0xFF)
        passcodeBytes[3] = UInt8((passcode >> 24) & 0xFF)

        // PBKDF2-HMAC-SHA256, 80 bytes output
        return pbkdf2HMACSHA256(
            password: passcodeBytes,
            salt: salt,
            iterations: iterations,
            derivedKeyLength: 80
        )
    }

    /// PBKDF2-HMAC-SHA256 implementation.
    ///
    /// Derives a key of `derivedKeyLength` bytes from `password` and `salt`
    /// using `iterations` rounds of HMAC-SHA256.
    static func pbkdf2HMACSHA256(
        password: Data,
        salt: Data,
        iterations: Int,
        derivedKeyLength: Int
    ) -> Data {
        let key = SymmetricKey(data: password)
        let hashLen = 32 // SHA-256 output
        let blockCount = (derivedKeyLength + hashLen - 1) / hashLen

        var derivedKey = Data()

        for blockIndex in 1...blockCount {
            // U_1 = HMAC(password, salt || INT_32_BE(blockIndex))
            var saltWithIndex = salt
            saltWithIndex.append(UInt8((blockIndex >> 24) & 0xFF))
            saltWithIndex.append(UInt8((blockIndex >> 16) & 0xFF))
            saltWithIndex.append(UInt8((blockIndex >> 8) & 0xFF))
            saltWithIndex.append(UInt8(blockIndex & 0xFF))

            var u = Data(HMAC<SHA256>.authenticationCode(
                for: saltWithIndex, using: key
            ))
            var result = u

            // U_2 ... U_iterations
            for _ in 1..<iterations {
                u = Data(HMAC<SHA256>.authenticationCode(
                    for: u, using: key
                ))
                // XOR into result
                for j in 0..<hashLen {
                    result[j] ^= u[j]
                }
            }

            derivedKey.append(result)
        }

        return Data(derivedKey.prefix(derivedKeyLength))
    }
}

// MARK: - Session Keys

/// Derived session encryption keys.
public struct SessionKeys: Sendable {
    /// Initiator-to-Responder encryption key (16 bytes).
    public let i2rKey: SymmetricKey

    /// Responder-to-Initiator encryption key (16 bytes).
    public let r2iKey: SymmetricKey

    /// Attestation challenge key (16 bytes).
    public let attestationKey: SymmetricKey

    /// Get the encryption key for the given role.
    public func encryptKey(isInitiator: Bool) -> SymmetricKey {
        isInitiator ? i2rKey : r2iKey
    }

    /// Get the decryption key for the given role.
    public func decryptKey(isInitiator: Bool) -> SymmetricKey {
        isInitiator ? r2iKey : i2rKey
    }
}

// MARK: - Errors

/// Cryptographic operation errors.
public enum CryptoError: Error, Sendable, Equatable {
    case invalidCiphertext
    case invalidKeyLength
    case invalidNonceLength
    case authenticationFailed
    case invalidPoint
    case verificationFailed
    case invalidPasscode
    case invalidSalt
    case invalidIterations
}
