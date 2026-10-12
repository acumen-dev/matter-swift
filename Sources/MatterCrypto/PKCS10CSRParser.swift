// PKCS10CSRParser.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto

// MARK: - PKCS10CSRError

/// Errors raised while parsing or verifying a PKCS#10 CSR.
public enum PKCS10CSRError: Error, Equatable, Sendable {
    /// The DER structure is truncated, mis-tagged, or otherwise not a CertificationRequest.
    case malformed(String)
    /// The signature algorithm or key type is not ecdsa-with-SHA256 over P-256.
    case unsupportedAlgorithm
    /// The self-signature does not verify against the CSR's own public key.
    case badSignature
}

// MARK: - PKCS10CSR

/// A parsed and signature-verified PKCS#10 CertificationRequest (RFC 2986).
///
/// ```
/// CertificationRequest ::= SEQUENCE {
///   certificationRequestInfo  SEQUENCE { version, subject, SubjectPublicKeyInfo, [0] attributes },
///   signatureAlgorithm        AlgorithmIdentifier,
///   signature                 BIT STRING }
/// ```
public struct PKCS10CSR: Sendable {

    /// The P-256 public key from the CSR's SubjectPublicKeyInfo.
    public let publicKey: P256.Signing.PublicKey

    /// Parse a DER CertificationRequest and verify its self-signature
    /// (ecdsa-with-SHA256 over the DER of CertificationRequestInfo).
    public init(der: Data) throws {
        var outer = DERReader(Data(der))
        let request = try outer.read(tag: 0x30, what: "CertificationRequest")
        guard outer.isAtEnd else { throw PKCS10CSRError.malformed("trailing bytes after CertificationRequest") }

        var body = DERReader(request.value)
        let info = try body.read(tag: 0x30, what: "CertificationRequestInfo")
        let algorithm = try body.read(tag: 0x30, what: "signatureAlgorithm")
        let signature = try body.read(tag: 0x03, what: "signature")
        guard body.isAtEnd else { throw PKCS10CSRError.malformed("trailing bytes in CertificationRequest") }

        // Signature algorithm: ecdsa-with-SHA256 (parameters absent per RFC 5758).
        var algReader = DERReader(algorithm.value)
        let algOID = try algReader.read(tag: 0x06, what: "signatureAlgorithm OID")
        guard algOID.value == Self.oidECDSAWithSHA256 else { throw PKCS10CSRError.unsupportedAlgorithm }

        // CertificationRequestInfo: version, subject, SubjectPublicKeyInfo, [0] attributes.
        var infoReader = DERReader(info.value)
        _ = try infoReader.read(tag: 0x02, what: "version")
        _ = try infoReader.read(tag: 0x30, what: "subject")
        let spki = try infoReader.read(tag: 0x30, what: "SubjectPublicKeyInfo")

        var spkiReader = DERReader(spki.value)
        let keyAlg = try spkiReader.read(tag: 0x30, what: "SPKI algorithm")
        let keyBits = try spkiReader.read(tag: 0x03, what: "SPKI subjectPublicKey")
        var keyAlgReader = DERReader(keyAlg.value)
        let keyOID = try keyAlgReader.read(tag: 0x06, what: "SPKI key type")
        let curveOID = try keyAlgReader.read(tag: 0x06, what: "SPKI curve")
        guard keyOID.value == Self.oidECPublicKey, curveOID.value == Self.oidPrime256v1 else {
            throw PKCS10CSRError.unsupportedAlgorithm
        }

        // BIT STRING: leading unused-bits byte (must be 0) then the 65-byte uncompressed point.
        guard keyBits.value.first == 0x00, keyBits.value.count == 66 else {
            throw PKCS10CSRError.malformed("SubjectPublicKey is not a 65-byte uncompressed point")
        }
        let key: P256.Signing.PublicKey
        do {
            key = try P256.Signing.PublicKey(x963Representation: keyBits.value.dropFirst())
        } catch {
            throw PKCS10CSRError.malformed("SubjectPublicKey is not a valid P-256 point")
        }

        // Signature: BIT STRING (0 unused bits) holding a DER ECDSA-Sig-Value.
        guard signature.value.first == 0x00 else { throw PKCS10CSRError.malformed("signature has unused bits") }
        guard let ecdsa = try? P256.Signing.ECDSASignature(derRepresentation: signature.value.dropFirst()) else {
            throw PKCS10CSRError.malformed("signature is not a DER ECDSA-Sig-Value")
        }
        guard key.isValidSignature(ecdsa, for: info.encoded) else { throw PKCS10CSRError.badSignature }

        self.publicKey = key
    }

    // MARK: - OIDs (DER content bytes)

    /// 1.2.840.10045.2.1
    private static let oidECPublicKey = Data([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01])
    /// 1.2.840.10045.3.1.7
    private static let oidPrime256v1 = Data([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])
    /// 1.2.840.10045.4.3.2
    private static let oidECDSAWithSHA256 = Data([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02])
}

// MARK: - DERReader

/// Minimal DER reader: one TLV at a time, definite lengths only (short and long form).
private struct DERReader {

    struct Element {
        /// Tag + length + value, exactly as encoded (what signatures cover).
        let encoded: Data
        let value: Data
    }

    private let data: Data
    private var offset = 0

    init(_ data: Data) { self.data = data }

    var isAtEnd: Bool { offset >= data.count }

    mutating func read(tag expected: UInt8, what: String) throws -> Element {
        let start = offset
        guard offset + 2 <= data.count else { throw PKCS10CSRError.malformed("\(what): truncated") }
        let tag = data[data.startIndex + offset]
        guard tag == expected else {
            throw PKCS10CSRError.malformed("\(what): expected tag 0x\(String(expected, radix: 16)), got 0x\(String(tag, radix: 16))")
        }
        var length = Int(data[data.startIndex + offset + 1])
        offset += 2
        if length & 0x80 != 0 {
            let count = length & 0x7F
            guard count >= 1, count <= 4, offset + count <= data.count else {
                throw PKCS10CSRError.malformed("\(what): bad length encoding")
            }
            length = 0
            for _ in 0..<count {
                length = (length << 8) | Int(data[data.startIndex + offset])
                offset += 1
            }
        }
        guard length <= data.count - offset else { throw PKCS10CSRError.malformed("\(what): truncated") }
        let valueStart = data.startIndex + offset
        let value = Data(data[valueStart..<(valueStart + length)])
        offset += length
        return Element(encoded: Data(data[(data.startIndex + start)..<(data.startIndex + offset)]), value: value)
    }
}
