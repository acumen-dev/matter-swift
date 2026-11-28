// PKCS10CSRParser.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import SwiftASN1
import X509

// MARK: - PKCS10CSRError

/// Errors raised while parsing or verifying a PKCS#10 CSR.
public enum PKCS10CSRError: Error, Equatable, Sendable {
    /// The DER structure is truncated, mis-tagged, or otherwise not a CertificationRequest.
    case malformed(String)
    /// The signature algorithm or key type is not ecdsa-with-SHA256 over P-256. The text
    /// names what was found, so a device's deviation can be read off the failure.
    case unsupportedAlgorithm(String)
    /// The self-signature does not verify against the CSR's own public key.
    case badSignature
}

// MARK: - PKCS10CSR

/// A parsed and signature-verified PKCS#10 CertificationRequest (RFC 2986),
/// decoded with swift-certificates.
public struct PKCS10CSR: Sendable {

    /// The P-256 public key from the CSR's SubjectPublicKeyInfo.
    public let publicKey: P256.Signing.PublicKey

    /// Parse a DER CertificationRequest and verify its self-signature
    /// (ecdsa-with-SHA256 over the DER of CertificationRequestInfo).
    ///
    /// The signature AlgorithmIdentifier may carry an explicit NULL parameter. RFC 5758
    /// §3.2 forbids one, but mbedTLS before 3.x wrote it, and device stacks built on that
    /// mbedTLS still send it; see ``droppingNullSignatureParameter(_:)``.
    public init(der: Data) throws {
        let csr: CertificateSigningRequest
        do {
            csr = try CertificateSigningRequest(derEncoded: Array(Self.droppingNullSignatureParameter(der)))
        } catch let error as X509.CertificateError
                    where error.code == .unsupportedPublicKeyAlgorithm || error.code == .unsupportedSignatureAlgorithm {
            throw PKCS10CSRError.unsupportedAlgorithm("\(error)")
        } catch {
            throw PKCS10CSRError.malformed("\(error)")
        }
        guard csr.signatureAlgorithm == .ecdsaWithSHA256 else {
            throw PKCS10CSRError.unsupportedAlgorithm(
                "signature algorithm \(csr.signatureAlgorithm), not ecdsa-with-SHA256"
            )
        }
        guard let key = P256.Signing.PublicKey(csr.publicKey) else {
            throw PKCS10CSRError.unsupportedAlgorithm("public key \(csr.publicKey), not P-256")
        }
        guard csr.publicKey.isValidSignature(csr.signature, for: csr) else {
            throw PKCS10CSRError.badSignature
        }
        self.publicKey = key
    }
}

// MARK: - Normalisation

extension PKCS10CSR {

    /// ecdsa-with-SHA256. Per RFC 5758 §3.2 its AlgorithmIdentifier has no parameters field.
    static let ecdsaWithSHA256: ASN1ObjectIdentifier = [1, 2, 840, 10045, 4, 3, 2]

    /// `der` with the explicit NULL parameter dropped from its outer signature
    /// AlgorithmIdentifier, when that identifier is ecdsa-with-SHA256 carrying exactly that
    /// parameter; `der` as it is otherwise.
    ///
    /// swift-certificates reads the NULL form as an algorithm it does not know. Only the
    /// outer SEQUENCE is rebuilt: the CertificationRequestInfo and the signature BIT STRING
    /// are copied byte for byte, so the signature is still checked over the bytes the device
    /// signed. Anything the pre-pass does not recognise, every malformed input included, is
    /// passed through unchanged for the parser proper to judge.
    static func droppingNullSignatureParameter(_ der: Data) -> Data {
        guard let request = try? DER.parse(Array(der)),
              request.identifier == .sequence,
              case .constructed(let members) = request.content else { return der }
        var member = members.makeIterator()
        guard let info = member.next(), let algorithm = member.next(), let signature = member.next(),
              member.next() == nil,
              algorithm.identifier == .sequence,
              case .constructed(let fields) = algorithm.content else { return der }
        let field = Array(fields)
        guard field.count == 2,
              field[1].identifier == .null,
              case .primitive(let parameter) = field[1].content, parameter.isEmpty,
              let oid = try? ASN1ObjectIdentifier(derEncoded: field[0]),
              oid == ecdsaWithSHA256 else { return der }
        var serializer = DER.Serializer()
        serializer.appendConstructedNode(identifier: .sequence) { request in
            request.serializeRawBytes(info.encodedBytes)
            request.appendConstructedNode(identifier: .sequence) { identifier in
                identifier.serializeRawBytes(field[0].encodedBytes)
            }
            request.serializeRawBytes(signature.encodedBytes)
        }
        return Data(serializer.serializedBytes)
    }
}
