// CASEKeyDerivation.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import MatterTypes

/// CASE sigma key derivation per Matter Core Spec §5.5.2.
///
/// All three sigma functions use HKDF-SHA256 with the ECDH shared secret as IKM.
/// The salt includes a transcript hash (SHA-256 over concatenated Sigma message bytes)
/// to bind the derived keys to the specific handshake transcript.
///
/// Key derivation also includes `computeDestinationID` which is used in Sigma1
/// to identify the target fabric+node without revealing IDs in cleartext.
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

    // MARK: - S2K (Sigma2 encryption key)

    /// Derive the Sigma2 encryption key (S2K).
    ///
    /// Used to encrypt the `TBEData2` payload inside Sigma2.
    ///
    /// Per CHIP SDK `CASESession::ConstructSaltSigma2`:
    ///   salt = IPK || σ2.Responder_Random || σ2.Responder_EPH_Pub_Key || SHA256(σ1)
    ///   info = "Sigma2"
    ///   length = 16 bytes
    ///
    /// Note: the initiator random is NOT in the S2K salt. The CHIP SDK uses only
    /// responderRandom (not initiatorRandom) as the nonce component in the salt.
    ///
    /// - Parameters:
    ///   - sharedSecret: The ECDH shared secret between the ephemeral keys.
    ///   - ipk: The Identity Protection Key (16 bytes).
    ///   - responderRandom: Responder's random data from Sigma2 (32 bytes).
    ///   - responderEphPubKey: Responder's ephemeral public key (65-byte x963).
    ///   - sigma1Bytes: Raw TLV bytes of the Sigma1 message.
    /// - Returns: 16-byte S2K as `SymmetricKey`.
    public static func deriveSigma2Key(
        sharedSecret: SharedSecret,
        ipk: Data,
        responderRandom: Data,
        responderEphPubKey: P256.KeyAgreement.PublicKey,
        sigma1Bytes: Data
    ) -> SymmetricKey {
        let transcriptHash = Data(SHA256.hash(data: sigma1Bytes))
        var salt = Data()
        salt.append(ipk)
        salt.append(responderRandom)
        salt.append(responderEphPubKey.x963Representation)
        salt.append(transcriptHash)

        return sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: Data("Sigma2".utf8),
            outputByteCount: 16
        )
    }

    // MARK: - S3K (Sigma3 encryption key)

    /// Derive the Sigma3 encryption key (S3K).
    ///
    /// Used to encrypt the `TBEData3` payload inside Sigma3.
    ///
    /// salt = IPK || SHA256(sigma1Bytes || sigma2Bytes)
    /// info = "Sigma3"
    /// length = 16 bytes
    ///
    /// - Parameters:
    ///   - sharedSecret: The ECDH shared secret between the ephemeral keys.
    ///   - ipk: The Identity Protection Key (16 bytes).
    ///   - sigma1Bytes: Raw TLV bytes of the Sigma1 message.
    ///   - sigma2Bytes: Raw TLV bytes of the Sigma2 message.
    /// - Returns: 16-byte S3K as `SymmetricKey`.
    public static func deriveSigma3Key(
        sharedSecret: SharedSecret,
        ipk: Data,
        sigma1Bytes: Data,
        sigma2Bytes: Data
    ) -> SymmetricKey {
        var transcript = Data()
        transcript.append(sigma1Bytes)
        transcript.append(sigma2Bytes)
        let transcriptHash = Data(SHA256.hash(data: transcript))

        var salt = Data()
        salt.append(ipk)
        salt.append(transcriptHash)

        return sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: Data("Sigma3".utf8),
            outputByteCount: 16
        )
    }

    // MARK: - Session Keys

    /// Derive the three session keys after Sigma3 is verified.
    ///
    /// salt = IPK || SHA256(sigma1Bytes || sigma2Bytes || sigma3Bytes)
    /// info = "SessionKeys"
    /// length = 48 bytes → I2RKey[0..15], R2IKey[16..31], AttestationKey[32..47]
    ///
    /// - Parameters:
    ///   - sharedSecret: The ECDH shared secret between the ephemeral keys.
    ///   - ipk: The Identity Protection Key (16 bytes).
    ///   - sigma1Bytes: Raw TLV bytes of the Sigma1 message.
    ///   - sigma2Bytes: Raw TLV bytes of the Sigma2 message.
    ///   - sigma3Bytes: Raw TLV bytes of the Sigma3 message.
    /// - Returns: Tuple of (i2rKey, r2iKey, attestationKey), each 16 bytes.
    public static func deriveSessionKeys(
        sharedSecret: SharedSecret,
        ipk: Data,
        sigma1Bytes: Data,
        sigma2Bytes: Data,
        sigma3Bytes: Data
    ) -> (i2rKey: SymmetricKey, r2iKey: SymmetricKey, attestationKey: SymmetricKey) {
        var transcript = Data()
        transcript.append(sigma1Bytes)
        transcript.append(sigma2Bytes)
        transcript.append(sigma3Bytes)
        let transcriptHash = Data(SHA256.hash(data: transcript))

        var salt = Data()
        salt.append(ipk)
        salt.append(transcriptHash)

        let derived = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: Data("SessionKeys".utf8),
            outputByteCount: 48
        )

        let keyBytes = derived.withUnsafeBytes { Data($0) }
        let i2rKey = SymmetricKey(data: keyBytes[0..<16])
        let r2iKey = SymmetricKey(data: keyBytes[16..<32])
        let attestationKey = SymmetricKey(data: keyBytes[32..<48])

        return (i2rKey, r2iKey, attestationKey)
    }
}
