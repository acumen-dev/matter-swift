// PKCS10CSRParserTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
@testable import MatterCrypto

@Suite("PKCS10CSRParser Tests")
struct PKCS10CSRParserTests {

    private typealias B = PKCS10CSRBuilder

    @Test("Parsing a built CSR returns the signing key")
    func parsesPublicKey() throws {
        let key = P256.Signing.PrivateKey()
        let der = try B.buildCSR(privateKey: key)
        let csr = try PKCS10CSR(der: der)
        #expect(csr.publicKey.x963Representation == key.publicKey.x963Representation)
    }

    @Test("Flipping a byte inside CertificationRequestInfo fails the signature")
    func tamperedInfoIsBadSignature() throws {
        let key = P256.Signing.PrivateKey()
        var der = try B.buildCSR(privateKey: key)
        // Flip a byte in the subject common name text ("Matter Device"): still well-formed DER.
        let needle = Data("Matter".utf8)
        let range = try #require(der.range(of: needle))
        der[range.lowerBound] ^= 0x01
        #expect(throws: PKCS10CSRError.badSignature) {
            try PKCS10CSR(der: der)
        }
    }

    @Test("A CSR signed by a different key than the one it carries fails the signature")
    func mismatchedKeyIsBadSignature() throws {
        let key = P256.Signing.PrivateKey()
        let other = P256.Signing.PrivateKey()
        let cri = B.buildCertificationRequestInfo(
            publicKey: key.publicKey, organization: "CSA", commonName: "Matter Device"
        )
        let sig = try other.signature(for: cri)
        let der = B.buildCertificationRequest(criBytes: cri, derSignature: Data(sig.derRepresentation))
        #expect(throws: PKCS10CSRError.badSignature) {
            try PKCS10CSR(der: der)
        }
    }

    @Test("Truncated CSR is malformed")
    func truncatedIsMalformed() throws {
        let der = try B.buildCSR(privateKey: P256.Signing.PrivateKey())
        for cut in [0, 1, 3, der.count / 2, der.count - 1] {
            let truncated = der.prefix(cut)
            #expect(throws: PKCS10CSRError.self) {
                try PKCS10CSR(der: Data(truncated))
            }
        }
        do {
            _ = try PKCS10CSR(der: Data(der.prefix(der.count - 1)))
            Issue.record("expected failure")
        } catch let error as PKCS10CSRError {
            guard case .malformed = error else {
                Issue.record("expected .malformed, got \(error)")
                return
            }
        }
    }

    @Test("Garbage is malformed")
    func garbageIsMalformed() {
        #expect(throws: PKCS10CSRError.self) {
            try PKCS10CSR(der: Data([0x04, 0x00]))
        }
    }

    @Test("A non-ECDSA signature algorithm is unsupported")
    func rsaOIDIsUnsupported() throws {
        let key = P256.Signing.PrivateKey()
        let cri = B.buildCertificationRequestInfo(
            publicKey: key.publicKey, organization: "CSA", commonName: "Matter Device"
        )
        let sig = try key.signature(for: cri)
        // sha256WithRSAEncryption 1.2.840.113549.1.1.11
        let sigAlg = B.derSequence(B.derOID([1, 2, 840, 113549, 1, 1, 11]) + [0x05, 0x00])
        let der = Data(B.derSequence(
            [UInt8](cri) + sigAlg + B.derBitString([UInt8](sig.derRepresentation))
        ))
        #expect(throws: PKCS10CSRError.unsupportedAlgorithm) {
            try PKCS10CSR(der: der)
        }
    }

    @Test("Long-form DER lengths parse")
    func longFormLengths() throws {
        // A long common name pushes CertificationRequestInfo past 255 bytes (0x82 length form).
        let key = P256.Signing.PrivateKey()
        let der = try B.buildCSR(
            privateKey: key, subjectOrganization: "CSA",
            subjectCommonName: String(repeating: "x", count: 300)
        )
        let csr = try PKCS10CSR(der: der)
        #expect(csr.publicKey.x963Representation == key.publicKey.x963Representation)
    }
}
