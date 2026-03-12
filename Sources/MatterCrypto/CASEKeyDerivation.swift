// CASEKeyDerivation.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import MatterTypes

/// Key derivation functions specific to CASE session establishment.
///
/// CASE uses HMAC-SHA256 and HKDF-SHA256 for various key derivation steps:
/// - **Destination ID**: Identifies the target fabric+node without revealing IDs in cleartext
/// - **Sigma keys**: Derives S2K and S3K for encrypting Sigma2/Sigma3 payloads
/// - **Session keys**: Derives I2R/R2I/attestation keys from ECDH shared secret
public enum CASEKeyDerivation {

    // MARK: - Destination ID

    /// Compute the destination identifier for CASE Sigma1.
    ///
    /// DestinationID = HMAC-SHA256(
    ///     key: IPK,
    ///     data: initiatorRandom || rootPublicKey || fabricID || nodeID
    /// )
    ///
    /// The IPK (Identity Protection Key) is derived from the fabric's epoch key.
    /// The result is truncated to 32 bytes (full SHA-256 output).
    ///
    /// - Parameters:
    ///   - initiatorRandom: 32 bytes of initiator random data.
    ///   - rootPublicKey: The fabric's root CA public key (65 bytes, uncompressed).
    ///   - fabricID: The target fabric ID.
    ///   - nodeID: The target node ID.
    ///   - ipk: The Identity Protection Key (16 bytes).
    /// - Returns: 32-byte destination identifier.
    public static func computeDestinationID(
        initiatorRandom: Data,
        rootPublicKey: Data,
        fabricID: FabricID,
        nodeID: NodeID,
        ipk: Data
    ) -> Data {
        let key = SymmetricKey(data: ipk)

        // Concatenate: initiatorRandom || rootPublicKey || fabricID(LE64) || nodeID(LE64)
        var message = Data()
        message.append(initiatorRandom)
        message.append(rootPublicKey)
        message.appendLittleEndian(fabricID.rawValue)
        message.appendLittleEndian(nodeID.rawValue)

        let hmac = HMAC<SHA256>.authenticationCode(for: message, using: key)
        return Data(hmac)
    }

    // MARK: - Sigma Key Derivation

    /// Derive the S2K and S3K keys used to encrypt Sigma2 and Sigma3 payloads.
    ///
    /// Keys are derived via HKDF-SHA256:
    /// - IKM: ECDH shared secret
    /// - Salt: IPK || responderRandom || responderEphPubKey || initiatorEphPubKey
    /// - Info: "Sigma Keys" (ASCII)
    /// - Output: 48 bytes → S2K (0-15), S3K (16-31), unused (32-47)
    ///
    /// Note: The spec actually derives only S2K (16 bytes) and S3K (16 bytes)
    /// from a single 48-byte HKDF output. Bytes 32-47 are not used for Sigma
    /// but we extract them for consistency with the session key pattern.
    ///
    /// - Parameters:
    ///   - sharedSecret: The ECDH shared secret.
    ///   - ipk: The Identity Protection Key (16 bytes).
    ///   - responderRandom: Responder's random data (32 bytes).
    ///   - responderEphPubKey: Responder's ephemeral public key (65 bytes).
    ///   - initiatorEphPubKey: Initiator's ephemeral public key (65 bytes).
    /// - Returns: Tuple of (s2k, s3k) as `SymmetricKey`.
    public static func deriveSigmaKeys(
        sharedSecret: Data,
        ipk: Data,
        responderRandom: Data,
        responderEphPubKey: Data,
        initiatorEphPubKey: Data
    ) -> (s2k: SymmetricKey, s3k: SymmetricKey) {
        // Salt = IPK || responderRandom || responderEphPubKey || initiatorEphPubKey
        var salt = Data()
        salt.append(ipk)
        salt.append(responderRandom)
        salt.append(responderEphPubKey)
        salt.append(initiatorEphPubKey)

        let ikm = SymmetricKey(data: sharedSecret)
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm,
            salt: salt,
            info: Data("SEKeys".utf8),
            outputByteCount: 48
        )

        let bytes = derived.withUnsafeBytes { Data($0) }
        return (
            s2k: SymmetricKey(data: bytes[0..<16]),
            s3k: SymmetricKey(data: bytes[16..<32])
        )
    }

    // MARK: - Session Key Derivation (CASE-specific salt)

    /// Derive session keys from the CASE shared secret.
    ///
    /// Uses the same HKDF-SHA256 as PASE but with a CASE-specific salt:
    /// Salt = IPK || responderRandom || responderEphPubKey || initiatorEphPubKey
    ///
    /// - Parameters:
    ///   - sharedSecret: The ECDH shared secret.
    ///   - ipk: The Identity Protection Key (16 bytes).
    ///   - responderRandom: Responder's random data (32 bytes).
    ///   - responderEphPubKey: Responder's ephemeral public key (65 bytes).
    ///   - initiatorEphPubKey: Initiator's ephemeral public key (65 bytes).
    /// - Returns: `SessionKeys` containing I2R, R2I, and attestation keys.
    public static func deriveSessionKeys(
        sharedSecret: Data,
        ipk: Data,
        responderRandom: Data,
        responderEphPubKey: Data,
        initiatorEphPubKey: Data
    ) -> SessionKeys {
        var salt = Data()
        salt.append(ipk)
        salt.append(responderRandom)
        salt.append(responderEphPubKey)
        salt.append(initiatorEphPubKey)

        return KeyDerivation.deriveSessionKeys(
            sharedSecret: sharedSecret,
            salt: salt,
            info: KeyDerivation.sessionKeysInfo
        )
    }
}

