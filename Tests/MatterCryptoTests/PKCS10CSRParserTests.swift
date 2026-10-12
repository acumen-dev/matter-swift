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

    private func expectMalformed(_ der: Data, _ what: String) {
        do {
            _ = try PKCS10CSR(der: der)
            Issue.record("\(what): expected failure")
        } catch let error as PKCS10CSRError {
            if case .malformed = error { return }
            Issue.record("\(what): expected .malformed, got \(error)")
        } catch {
            Issue.record("\(what): unexpected error \(error)")
        }
    }

    @Test("Truncation at every cut is malformed")
    func truncatedIsMalformed() throws {
        let der = try B.buildCSR(privateKey: P256.Signing.PrivateKey())
        for cut in 0..<der.count {
            expectMalformed(Data(der.prefix(cut)), "cut \(cut)")
        }
    }

    @Test("Garbage is malformed")
    func garbageIsMalformed() {
        expectMalformed(Data([0x04, 0x00]), "garbage")
    }

    @Test("Trailing bytes after the outer SEQUENCE are malformed")
    func trailingBytes() throws {
        var der = try B.buildCSR(privateKey: P256.Signing.PrivateKey())
        der.append(0x00)
        expectMalformed(der, "trailing")
    }

    @Test("Indefinite length is malformed")
    func indefiniteLength() throws {
        let der = try B.buildCSR(privateKey: P256.Signing.PrivateKey())
        var hostile = Data([0x30, 0x80])
        hostile.append(contentsOf: der.dropFirst(der[1] & 0x80 != 0 ? 2 + Int(der[1] & 0x7F) : 2))
        hostile.append(contentsOf: [0x00, 0x00])
        expectMalformed(hostile, "indefinite")
    }

    @Test("A nested length longer than the remaining data is malformed")
    func nestedLengthTooLong() {
        expectMalformed(Data([0x30, 0x05, 0x30, 0x7F, 0x01, 0x02, 0x03]), "nested")
    }

    @Test("A 4-byte length of 0xFFFFFFFF is malformed, never a trap")
    func hugeLength() {
        expectMalformed(Data([0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF]), "huge")
    }

    @Test("A non-zero unused-bits byte in the signature BIT STRING never yields a different key")
    func unusedBits() throws {
        // swift-certificates ignores the padding count on the signature BIT STRING and still
        // verifies the signature over the exact CertificationRequestInfo, so a CSR that parses
        // is still genuinely self-signed; we pin that it can only ever yield the signer's key.
        let key = P256.Signing.PrivateKey()
        let cri = B.buildCertificationRequestInfo(
            publicKey: key.publicKey, organization: "CSA", commonName: "Matter Device"
        )
        let sig = [UInt8](try key.signature(for: cri).derRepresentation)
        let sigAlg = B.derSequence(B.derOID(B.oidECDSAWithSHA256))
        let bits = B.derTLV(tag: 0x03, content: [0x01] + sig)
        let der = Data(B.derSequence([UInt8](cri) + sigAlg + bits))
        if let parsed = try? PKCS10CSR(der: der) {
            #expect(parsed.publicKey.x963Representation == key.publicKey.x963Representation)
        }
    }

    private func csr(keyOID: [UInt64], curveOID: [UInt64], key: P256.Signing.PrivateKey) throws -> Data {
        let algID = B.derSequence(B.derOID(keyOID) + B.derOID(curveOID))
        let spki = B.derSequence(algID + B.derBitString([UInt8](key.publicKey.x963Representation)))
        let name = B.buildSubjectName(organization: "CSA", commonName: "Matter Device")
        let cri = Data(B.derSequence(
            B.derInteger(0) + name + spki + B.derContextConstructed(tag: 0, content: [])
        ))
        let sig = try key.signature(for: cri)
        return B.buildCertificationRequest(criBytes: cri, derSignature: Data(sig.derRepresentation))
    }

    @Test("A wrong SPKI key-type or curve OID is unsupported")
    func wrongKeyOIDs() throws {
        let key = P256.Signing.PrivateKey()
        // sanity: the helper with the right OIDs parses
        _ = try PKCS10CSR(der: csr(keyOID: B.oidECPublicKey, curveOID: B.oidPrime256v1, key: key))
        // rsaEncryption key type
        #expect(throws: PKCS10CSRError.unsupportedAlgorithm) {
            try PKCS10CSR(der: csr(keyOID: [1, 2, 840, 113549, 1, 1, 1], curveOID: B.oidPrime256v1, key: key))
        }
        // A genuine P-384 CSR (secp384r1 curve, 97-byte point, ecdsa-with-SHA384)
        let p384 = P384.Signing.PrivateKey()
        let algID = B.derSequence(B.derOID(B.oidECPublicKey) + B.derOID([1, 3, 132, 0, 34]))
        let spki = B.derSequence(algID + B.derBitString([UInt8](p384.publicKey.x963Representation)))
        let cri = Data(B.derSequence(
            B.derInteger(0) + B.buildSubjectName(organization: "CSA", commonName: "x")
                + spki + B.derContextConstructed(tag: 0, content: [])
        ))
        let sigAlg384 = B.derSequence(B.derOID([1, 2, 840, 10045, 4, 3, 3]))
        let sig384 = try p384.signature(for: cri)
        let der384 = Data(B.derSequence(
            [UInt8](cri) + sigAlg384 + B.derBitString([UInt8](sig384.derRepresentation))
        ))
        #expect(throws: PKCS10CSRError.unsupportedAlgorithm) {
            try PKCS10CSR(der: der384)
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
