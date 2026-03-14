// PKCS10CSR.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto

/// RFC 2986 PKCS#10 Certificate Signing Request builder for P-256 keys.
///
/// Builds a proper DER-encoded PKCS#10 CSR as required by the Matter spec
/// (§11.17.6.5 — CSRRequest Command) for operational key commissioning.
///
/// ## DER Structure
///
/// ```
/// SEQUENCE {                          -- CertificationRequest
///   SEQUENCE {                        -- CertificationRequestInfo (signed)
///     INTEGER 0                       -- version v1
///     SEQUENCE {                      -- Subject (RDN sequence)
///       SET { SEQUENCE { OID(org), UTF8String } }
///       SET { SEQUENCE { OID(cn),  UTF8String } }
///     }
///     SEQUENCE {                      -- SubjectPublicKeyInfo
///       SEQUENCE { OID(ecPublicKey), OID(prime256v1) }
///       BIT STRING(0x00 + publicKeyBytes)
///     }
///     [0] {}                          -- attributes (empty, context tag 0 CONSTRUCTED)
///   }
///   SEQUENCE { OID(ecdsa-with-SHA256) }  -- signatureAlgorithm
///   BIT STRING(0x00 + derSignature)      -- signature
/// }
/// ```
public enum PKCS10CSRBuilder {

    // MARK: - Public API

    /// Build a DER-encoded PKCS#10 CSR signed with the given P-256 private key.
    ///
    /// - Parameters:
    ///   - privateKey: The P-256 operational private key.
    ///   - subjectOrganization: Organization name for Subject DN (default "CSA").
    ///   - subjectCommonName: Common name for Subject DN (default "Matter Device").
    /// - Returns: DER-encoded PKCS#10 CertificationRequest bytes.
    public static func buildCSR(
        privateKey: P256.Signing.PrivateKey,
        subjectOrganization: String = "CSA",
        subjectCommonName: String = "Matter Device"
    ) throws -> Data {
        // Build CertificationRequestInfo (the part that gets signed)
        let criBytes = buildCertificationRequestInfo(
            publicKey: privateKey.publicKey,
            organization: subjectOrganization,
            commonName: subjectCommonName
        )

        // Sign the CRI with the private key using SHA-256
        let signature = try privateKey.signature(for: criBytes)
        let derSig = Data(signature.derRepresentation)

        // Build the full CertificationRequest
        return buildCertificationRequest(criBytes: criBytes, derSignature: derSig)
    }

    // MARK: - DER Encoding Helpers

    /// Write a DER length value (short or long form).
    static func derLength(_ length: Int) -> [UInt8] {
        if length < 128 {
            return [UInt8(length)]
        } else if length < 256 {
            return [0x81, UInt8(length)]
        } else {
            return [0x82, UInt8(length >> 8), UInt8(length & 0xFF)]
        }
    }

    /// Wrap bytes in a DER TLV with the given tag.
    static func derTLV(tag: UInt8, content: [UInt8]) -> [UInt8] {
        [tag] + derLength(content.count) + content
    }

    /// Encode a DER SEQUENCE (tag 0x30).
    static func derSequence(_ content: [UInt8]) -> [UInt8] {
        derTLV(tag: 0x30, content: content)
    }

    /// Encode a DER SET (tag 0x31).
    static func derSet(_ content: [UInt8]) -> [UInt8] {
        derTLV(tag: 0x31, content: content)
    }

    /// Encode a DER INTEGER (tag 0x02).
    static func derInteger(_ value: UInt8) -> [UInt8] {
        // Single-byte non-negative integer — no leading zero needed for values < 128
        [0x02, 0x01, value]
    }

    /// Encode a DER OID (tag 0x06) from an arc array.
    ///
    /// Encodes per X.690 §8.19:
    /// - First two arcs combined as 40 * arc[0] + arc[1]
    /// - Subsequent arcs encoded as base-128 big-endian
    static func derOID(_ arcs: [UInt64]) -> [UInt8] {
        guard arcs.count >= 2 else { return [0x06, 0x00] }

        var content: [UInt8] = []

        // First two arcs combined
        let first = arcs[0] * 40 + arcs[1]
        content += encodeBase128(first)

        // Remaining arcs
        for arc in arcs.dropFirst(2) {
            content += encodeBase128(arc)
        }

        return derTLV(tag: 0x06, content: content)
    }

    /// Encode a non-negative integer in base-128 (DER OID sub-identifier encoding).
    static func encodeBase128(_ value: UInt64) -> [UInt8] {
        if value == 0 { return [0x00] }
        var remaining = value
        var bytes: [UInt8] = []
        while remaining > 0 {
            bytes.insert(UInt8(remaining & 0x7F), at: 0)
            remaining >>= 7
        }
        // Set continuation bit on all but last byte
        for i in 0..<bytes.count - 1 {
            bytes[i] |= 0x80
        }
        return bytes
    }

    /// Encode a DER UTF8String (tag 0x0C).
    static func derUTF8String(_ string: String) -> [UInt8] {
        let utf8 = [UInt8](string.utf8)
        return derTLV(tag: 0x0C, content: utf8)
    }

    /// Encode a DER BIT STRING (tag 0x03) with zero unused bits prefix.
    static func derBitString(_ bytes: [UInt8]) -> [UInt8] {
        // Prefix with 0x00 = "0 unused bits"
        let content: [UInt8] = [0x00] + bytes
        return derTLV(tag: 0x03, content: content)
    }

    /// Encode a DER context-specific CONSTRUCTED tag (e.g. [0] EXPLICIT).
    static func derContextConstructed(tag: UInt8, content: [UInt8]) -> [UInt8] {
        let tagByte: UInt8 = 0xA0 | tag  // context-specific, constructed
        return derTLV(tag: tagByte, content: content)
    }

    // MARK: - OID Constants

    // ecPublicKey: 1.2.840.10045.2.1
    static let oidECPublicKey: [UInt64] = [1, 2, 840, 10045, 2, 1]

    // prime256v1: 1.2.840.10045.3.1.7
    static let oidPrime256v1: [UInt64] = [1, 2, 840, 10045, 3, 1, 7]

    // ecdsa-with-SHA256: 1.2.840.10045.4.3.2
    static let oidECDSAWithSHA256: [UInt64] = [1, 2, 840, 10045, 4, 3, 2]

    // organizationName: 2.5.4.10
    static let oidOrganizationName: [UInt64] = [2, 5, 4, 10]

    // commonName: 2.5.4.3
    static let oidCommonName: [UInt64] = [2, 5, 4, 3]

    // MARK: - Structure Builders

    /// Build SubjectPublicKeyInfo for the given P-256 public key.
    static func buildSubjectPublicKeyInfo(publicKey: P256.Signing.PublicKey) -> [UInt8] {
        // AlgorithmIdentifier: SEQUENCE { ecPublicKey OID, prime256v1 OID }
        let algID = derSequence(derOID(oidECPublicKey) + derOID(oidPrime256v1))

        // Public key as uncompressed point (04 || X || Y), 65 bytes
        let pubKeyBytes = [UInt8](publicKey.x963Representation)
        let bitString = derBitString(pubKeyBytes)

        return derSequence(algID + bitString)
    }

    /// Build the Subject RDN sequence: O=org, CN=cn.
    static func buildSubjectName(organization: String, commonName: String) -> [UInt8] {
        // RDN for Organization: SET { SEQUENCE { OID(O), UTF8String(org) } }
        let orgAttr = derSequence(derOID(oidOrganizationName) + derUTF8String(organization))
        let orgRDN = derSet(orgAttr)

        // RDN for CommonName: SET { SEQUENCE { OID(CN), UTF8String(cn) } }
        let cnAttr = derSequence(derOID(oidCommonName) + derUTF8String(commonName))
        let cnRDN = derSet(cnAttr)

        return derSequence(orgRDN + cnRDN)
    }

    /// Build the CertificationRequestInfo (the bytes that get signed).
    static func buildCertificationRequestInfo(
        publicKey: P256.Signing.PublicKey,
        organization: String,
        commonName: String
    ) -> Data {
        let version = derInteger(0)
        let subject = buildSubjectName(organization: organization, commonName: commonName)
        let spki = buildSubjectPublicKeyInfo(publicKey: publicKey)
        let attributes = derContextConstructed(tag: 0, content: [])  // [0] {}

        let criContent = version + subject + spki + attributes
        let cri = derSequence(criContent)
        return Data(cri)
    }

    /// Build the full CertificationRequest from the signed CRI and signature.
    static func buildCertificationRequest(criBytes: Data, derSignature: Data) -> Data {
        // signatureAlgorithm: SEQUENCE { ecdsa-with-SHA256 OID }
        let sigAlg = derSequence(derOID(oidECDSAWithSHA256))

        // signature: BIT STRING(0x00 + derSignature)
        let sigBitString = derBitString([UInt8](derSignature))

        let outerContent = [UInt8](criBytes) + sigAlg + sigBitString
        return Data(derSequence(outerContent))
    }
}
