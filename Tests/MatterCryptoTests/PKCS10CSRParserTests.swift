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

    /// The reason text of the `.unsupportedAlgorithm` that parsing `der` throws, or "" with
    /// an issue recorded when it throws something else or parses.
    private func expectUnsupported(_ der: Data, _ what: String) -> String {
        do {
            _ = try PKCS10CSR(der: der)
            Issue.record("\(what): expected failure")
        } catch PKCS10CSRError.unsupportedAlgorithm(let reason) {
            #expect(!reason.isEmpty, "\(what): the reason names what was found")
            return reason
        } catch {
            Issue.record("\(what): expected .unsupportedAlgorithm, got \(error)")
        }
        return ""
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

    /// A CSR whose signature BIT STRING declares one unused bit, re-signed
    /// until the signature's last byte has its low bit `lowBitSet`.
    private func csrWithOneUnusedBit(lowBitSet: Bool) throws -> (key: P256.Signing.PrivateKey, der: Data) {
        let key = P256.Signing.PrivateKey()
        let cri = B.buildCertificationRequestInfo(
            publicKey: key.publicKey, organization: "CSA", commonName: "Matter Device"
        )
        let sigAlg = B.derSequence(B.derOID(B.oidECDSAWithSHA256))
        // ECDSA signatures are randomised: each try is an even chance.
        for _ in 0..<256 {
            let sig = [UInt8](try key.signature(for: cri).derRepresentation)
            guard let last = sig.last, (last & 0x01 == 0x01) == lowBitSet else { continue }
            let bits = B.derTLV(tag: 0x03, content: [0x01] + sig)
            return (key, Data(B.derSequence([UInt8](cri) + sigAlg + bits)))
        }
        throw PKCS10CSRError.malformed("no signature with the wanted last bit in 256 tries")
    }

    @Test("A signature BIT STRING declaring an unused bit is malformed, whether that bit is clear or set")
    func unusedBitIsMalformed() throws {
        // An ECDSA signature is octet-aligned, so a padding count other than zero is never a
        // valid encoding of one. swift-certificates 1.21.2 refuses it outright, before any
        // verification, so that one signature has one encoding; earlier versions ignored the
        // count, which is why this once parsed with the bit clear.
        let (_, clear) = try csrWithOneUnusedBit(lowBitSet: false)
        expectMalformed(clear, "unused bit clear")
        let (_, set) = try csrWithOneUnusedBit(lowBitSet: true)
        expectMalformed(set, "unused bit set")
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
        _ = expectUnsupported(
            try csr(keyOID: [1, 2, 840, 113549, 1, 1, 1], curveOID: B.oidPrime256v1, key: key), "rsaEncryption key"
        )
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
        #expect(expectUnsupported(der384, "P-384").contains("not ecdsa-with-SHA256"))
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
        _ = expectUnsupported(der, "sha256WithRSAEncryption signature")
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

    // MARK: ecdsa-with-SHA256 with a NULL parameter

    private func standardCRI(for key: P256.Signing.PrivateKey) -> Data {
        B.buildCertificationRequestInfo(publicKey: key.publicKey, organization: "CSA", commonName: "Matter Device")
    }

    /// A CSR as mbedTLS before 3.x writes it: the signature AlgorithmIdentifier carries an
    /// explicit NULL parameter where RFC 5758 §3.2 wants none. Device stacks built on that
    /// mbedTLS still send this form.
    private func csrWithNullSignatureParameter(key: P256.Signing.PrivateKey, cri: Data) throws -> Data {
        let sig = try key.signature(for: cri)
        let sigAlg = B.derSequence(B.derOID(B.oidECDSAWithSHA256) + [0x05, 0x00])
        return Data(B.derSequence([UInt8](cri) + sigAlg + B.derBitString([UInt8](sig.derRepresentation))))
    }

    @Test("ecdsa-with-SHA256 with an explicit NULL parameter, as older mbedTLS writes it, yields the signer's key")
    func nullSignatureParameter() throws {
        let key = P256.Signing.PrivateKey()
        let der = try csrWithNullSignatureParameter(key: key, cri: standardCRI(for: key))
        let csr = try PKCS10CSR(der: der)
        #expect(csr.publicKey.x963Representation == key.publicKey.x963Representation)
    }

    @Test("The NULL-parameter form is still checked over the exact CertificationRequestInfo")
    func nullSignatureParameterTampered() throws {
        let key = P256.Signing.PrivateKey()
        var der = try csrWithNullSignatureParameter(key: key, cri: standardCRI(for: key))
        let range = try #require(der.range(of: Data("Matter".utf8)))
        der[range.lowerBound] ^= 0x01
        #expect(throws: PKCS10CSRError.badSignature) {
            try PKCS10CSR(der: der)
        }
    }

    @Test("A parameter other than NULL on ecdsa-with-SHA256 is unsupported")
    func otherSignatureParameter() throws {
        let key = P256.Signing.PrivateKey()
        let cri = standardCRI(for: key)
        let sig = try key.signature(for: cri)
        let sigAlg = B.derSequence(B.derOID(B.oidECDSAWithSHA256) + B.derOID(B.oidPrime256v1))
        let der = Data(B.derSequence([UInt8](cri) + sigAlg + B.derBitString([UInt8](sig.derRepresentation))))
        _ = expectUnsupported(der, "OID parameter on ecdsa-with-SHA256")
    }

    @Test("The NULL-parameter form with trailing bytes is still malformed: the pre-pass rebuilds nothing it cannot parse whole")
    func nullSignatureParameterTrailingBytes() throws {
        let key = P256.Signing.PrivateKey()
        var der = try csrWithNullSignatureParameter(key: key, cri: standardCRI(for: key))
        der.append(0x00)
        expectMalformed(der, "NULL form, trailing byte")
    }
}
