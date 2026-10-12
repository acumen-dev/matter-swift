// PKCS10CSRParser.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import X509

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

/// A parsed and signature-verified PKCS#10 CertificationRequest (RFC 2986),
/// decoded with swift-certificates.
public struct PKCS10CSR: Sendable {

    /// The P-256 public key from the CSR's SubjectPublicKeyInfo.
    public let publicKey: P256.Signing.PublicKey

    /// Parse a DER CertificationRequest and verify its self-signature
    /// (ecdsa-with-SHA256 over the DER of CertificationRequestInfo).
    public init(der: Data) throws {
        let csr: CertificateSigningRequest
        do {
            csr = try CertificateSigningRequest(derEncoded: Array(der))
        } catch {
            // CertificateError's code is not public API and the error arrives wrapped; its description names it.
            if "\(error)".contains("unsupportedPublicKeyAlgorithm") {
                throw PKCS10CSRError.unsupportedAlgorithm
            }
            throw PKCS10CSRError.malformed("\(error)")
        }
        guard csr.signatureAlgorithm == .ecdsaWithSHA256,
              let key = P256.Signing.PublicKey(csr.publicKey) else {
            throw PKCS10CSRError.unsupportedAlgorithm
        }
        guard csr.publicKey.isValidSignature(csr.signature, for: csr) else {
            throw PKCS10CSRError.badSignature
        }
        self.publicKey = key
    }
}
