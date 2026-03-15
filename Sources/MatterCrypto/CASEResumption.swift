// CASEResumption.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import MatterTypes

// MARK: - Sigma2ResumeMessage

/// Sigma2Resume message — sent by the responder when resumption succeeds.
///
/// Replaces the full Sigma2/Sigma3 exchange when a valid resumption ticket is found.
///
/// ```
/// Structure {
///   1: resumptionID (octet string, 16 bytes — new ID for next resumption)
///   2: sigma2ResumeMIC (octet string, 16 bytes)
///   3: responderSessionID (unsigned int, 16-bit)
/// }
/// ```
public struct Sigma2ResumeMessage: Sendable, Equatable {

    private enum Tag {
        static let resumptionID: UInt8 = 1
        static let sigma2ResumeMIC: UInt8 = 2
        static let responderSessionID: UInt8 = 3
    }

    /// New resumption ID for the next resumption attempt (16 bytes).
    public let resumptionID: Data

    /// AES-128-CCM authentication tag over responder data (16 bytes).
    public let sigma2ResumeMIC: Data

    /// The responder's proposed session ID.
    public let responderSessionID: UInt16

    public init(resumptionID: Data, sigma2ResumeMIC: Data, responderSessionID: UInt16) {
        self.resumptionID = resumptionID
        self.sigma2ResumeMIC = sigma2ResumeMIC
        self.responderSessionID = responderSessionID
    }

    // MARK: - TLV Encoding

    public func tlvEncode() -> Data {
        TLVEncoder.encode(toTLVElement())
    }

    public func toTLVElement() -> TLVElement {
        .structure([
            .init(tag: .contextSpecific(Tag.resumptionID), value: .octetString(resumptionID)),
            .init(tag: .contextSpecific(Tag.sigma2ResumeMIC), value: .octetString(sigma2ResumeMIC)),
            .init(tag: .contextSpecific(Tag.responderSessionID), value: .unsignedInt(UInt64(responderSessionID)))
        ])
    }

    // MARK: - TLV Decoding

    public static func fromTLV(_ data: Data) throws -> Sigma2ResumeMessage {
        let (_, element) = try TLVDecoder.decode(data)
        return try fromTLVElement(element)
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> Sigma2ResumeMessage {
        guard case .structure(let fields) = element else {
            throw CASEError.invalidMessage("Sigma2Resume: expected structure")
        }

        guard let rid = fields.first(where: { $0.tag == .contextSpecific(Tag.resumptionID) })?.value.dataValue,
              rid.count == 16 else {
            throw CASEError.invalidMessage("Sigma2Resume: missing/invalid resumptionID")
        }

        guard let mic = fields.first(where: { $0.tag == .contextSpecific(Tag.sigma2ResumeMIC) })?.value.dataValue,
              mic.count == 16 else {
            throw CASEError.invalidMessage("Sigma2Resume: missing/invalid sigma2ResumeMIC")
        }

        guard let sessionID = fields.first(where: { $0.tag == .contextSpecific(Tag.responderSessionID) })?.value.uintValue else {
            throw CASEError.invalidMessage("Sigma2Resume: missing responderSessionID")
        }

        return Sigma2ResumeMessage(
            resumptionID: rid,
            sigma2ResumeMIC: mic,
            responderSessionID: UInt16(sessionID)
        )
    }
}

// MARK: - CASEResumption

/// CASE session resumption utilities per Matter spec §4.13.2.3.
///
/// Session resumption allows an abbreviated re-establishment of a CASE session
/// using a stored ticket from a prior full exchange, saving round-trips and
/// avoiding full certificate chain validation.
public enum CASEResumption {

    // MARK: - Key Derivation

    /// Derive the 16-byte resume key using HKDF-SHA256.
    ///
    /// - IKM: sharedSecret (from previous CASE exchange)
    /// - Salt: resumptionID (16 bytes)
    /// - Info: "Sigma2_Resume" (UTF-8)
    /// - Length: 16 bytes
    ///
    /// - Parameters:
    ///   - sharedSecret: The ECDH shared secret from the prior CASE exchange.
    ///   - resumptionID: The 16-byte resumption ID from the stored ticket.
    /// - Returns: A 128-bit symmetric key for MIC computation.
    public static func deriveResumeKey(sharedSecret: Data, resumptionID: Data) throws -> SymmetricKey {
        let ikm = SymmetricKey(data: sharedSecret)
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm,
            salt: resumptionID,
            info: Data("Sigma2_Resume".utf8),
            outputByteCount: 16
        )
    }

    /// Compute the initiator resume MIC.
    ///
    /// AES-128-CCM with empty plaintext — the 16-byte authentication tag serves as the MIC.
    ///
    /// - Key: resumeKey
    /// - Nonce: first 12 bytes of "NCASE_SigmaS1" (AES-GCM requires 12-byte nonces)
    /// - AAD: initiatorRandom || resumptionID || initiatorEphPubKey
    public static func computeInitiatorResumeMIC(
        resumeKey: SymmetricKey,
        initiatorRandom: Data,
        resumptionID: Data,
        initiatorEphPubKey: Data
    ) throws -> Data {
        let nonce = Data("NCASE_SigmaS1".utf8).prefix(12)
        var aad = Data()
        aad.append(initiatorRandom)
        aad.append(resumptionID)
        aad.append(initiatorEphPubKey)
        return try MessageEncryption.encrypt(plaintext: Data(), key: resumeKey, nonce: nonce, aad: aad)
    }

    /// Verify the initiator resume MIC.
    public static func verifyInitiatorResumeMIC(
        resumeKey: SymmetricKey,
        initiatorRandom: Data,
        resumptionID: Data,
        initiatorEphPubKey: Data,
        mic: Data
    ) throws -> Bool {
        let expected = try computeInitiatorResumeMIC(
            resumeKey: resumeKey,
            initiatorRandom: initiatorRandom,
            resumptionID: resumptionID,
            initiatorEphPubKey: initiatorEphPubKey
        )
        return expected == mic
    }

    /// Compute the responder resume MIC.
    ///
    /// AES-128-CCM with empty plaintext — the 16-byte authentication tag serves as the MIC.
    ///
    /// - Key: resumeKey
    /// - Nonce: first 12 bytes of "NCASE_SigmaS2" (AES-GCM requires 12-byte nonces)
    /// - AAD: initiatorRandom || resumptionID
    public static func computeResponderResumeMIC(
        resumeKey: SymmetricKey,
        initiatorRandom: Data,
        resumptionID: Data
    ) throws -> Data {
        let nonce = Data("NCASE_SigmaS2".utf8).prefix(12)
        var aad = Data()
        aad.append(initiatorRandom)
        aad.append(resumptionID)
        return try MessageEncryption.encrypt(plaintext: Data(), key: resumeKey, nonce: nonce, aad: aad)
    }

    // MARK: - Session Keys

    /// Derive session keys for a resumed session.
    ///
    /// HKDF-SHA256:
    /// - IKM: sharedSecret
    /// - Salt: resumptionID
    /// - Info: "SessionResumptionKeys"
    /// - Length: 48 bytes → i2rKey (0-15), r2iKey (16-31), attestationChallenge (32-47)
    ///
    /// - Parameters:
    ///   - sharedSecret: The ECDH shared secret from the prior CASE exchange.
    ///   - resumptionID: The resumption ID from the Sigma2Resume message.
    /// - Returns: Session keys for the resumed session.
    public static func deriveResumedSessionKeys(sharedSecret: Data, resumptionID: Data) throws -> SessionKeys {
        return KeyDerivation.deriveSessionKeys(
            sharedSecret: sharedSecret,
            salt: resumptionID,
            info: KeyDerivation.resumptionKeysInfo
        )
    }
}
