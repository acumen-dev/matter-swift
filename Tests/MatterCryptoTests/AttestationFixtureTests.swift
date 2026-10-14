// AttestationFixtureTests.swift
// Copyright 2026 Monagle Pty Ltd

// What swift-certificates 1.21.0 offers attestation (settled by a probe before plan 3c):
//
// A. CMS SignedData verification is not public API. `CMS.isValidSignature` and
//    `CMS.isValidAttachedSignature` are `@_spi(CMS)` (Sources/X509/CryptographicMessageSyntax/
//    CMSOperations.swift:215, :246), and `CMSSignedData`, `CMSSignerInfo` and `CMSContentInfo`
//    are internal. Even through the SPI they reject a Matter CD: the signer must sit in
//    SignedData.certificates (CMSOperations.swift:369-370), and a CD names its signer by
//    subject key identifier only. The test CD fails with "Unable to locate signing certificate",
//    and the example CD has the same shape (no certificates field, SKID signer). The CD is
//    therefore parsed with SwiftASN1 and its signature checked with swift-crypto.
//
// B. `Verifier` with a custom `VerifierPolicy` expresses the Matter chain rules. The protocol is
//    public (Verifier/VerifierPolicy.swift:33), `UnverifiedCertificateChain` is a public collection
//    (so depth is `chain.count == 3`), VID/PID come from `String(attribute.value)`
//    (RDNAttribute.swift:364), and P-256 from `P256.Signing.PublicKey(certificate.publicKey)`.
//    Composed with `RFC5280Policy`, the probe accepted the dev chain and rejected a wrong root,
//    an expired DAC and a VID mismatch. Two caveats: `RFC5280Policy(validationTime:)` is
//    deprecated (RFC5280Policy.swift:68-74; the fixed-time initialiser is
//    `@_spi(FixedExpiryValidationTime)`, :118), and `Certificate(derEncoded:)` already throws on
//    ecdsa-with-SHA1 and secp256k1 certificates, so those cases fail at parse, not in a policy.

import Testing
import Foundation
import Crypto
import SwiftASN1
import X509
import MatterTestSupport

@Suite("Attestation Fixtures")
struct AttestationFixtureTests {

    // MARK: - Development Chain

    @Test("dev DAC, PAI and test PAA parse and chain by name")
    func chainParses() throws {
        let dac = try Certificate(derEncoded: Array(AttestationFixtures.devDAC))
        let pai = try Certificate(derEncoded: Array(AttestationFixtures.devPAI))
        let paa = try Certificate(derEncoded: Array(AttestationFixtures.testPAA))

        #expect(dac.issuer == pai.subject)
        #expect(pai.issuer == paa.subject)
        #expect(paa.issuer == paa.subject)
    }

    @Test("the NoVID test PAA is self-issued, has no VID, and issues struct_cd_origin_pid_vid_correct's PAI")
    func noVIDPAAIssuesOriginVectorPAI() throws {
        let paa = try Certificate(derEncoded: Array(AttestationFixtures.testPAANoVID))
        let vector = try #require(try AttestationFixtures.negativeCases.first { $0.name == "struct_cd_origin_pid_vid_correct" }?.vector)
        let pai = try Certificate(derEncoded: Array(vector.paiCert))
        let vidOID: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 37244, 2, 1]

        #expect(paa.issuer == paa.subject)
        #expect(!paa.subject.contains { rdn in rdn.contains { $0.type == vidOID } })
        #expect(pai.issuer == paa.subject)
        let paaSKI = try #require(try paa.extensions.subjectKeyIdentifier?.keyIdentifier)
        let paiAKI = try #require(try pai.extensions.authorityKeyIdentifier?.keyIdentifier)
        #expect(Array(paaSKI) == Array(paiAKI))
        #expect(paa.publicKey.isValidSignature(pai.signature, for: pai))
    }

    @Test("dev DAC private key matches the DAC's public key")
    func dacPrivateKeyMatches() throws {
        let dac = try Certificate(derEncoded: Array(AttestationFixtures.devDAC))
        let key = try P256.Signing.PrivateKey(derRepresentation: AttestationFixtures.devDACPrivateKey)
        let certKey = try #require(P256.Signing.PublicKey(dac.publicKey))
        #expect(key.publicKey.x963Representation == certKey.x963Representation)
    }

    // MARK: - Certification Declarations

    @Test("CDs are single DER SEQUENCEs whose length header covers every byte")
    func cdsLoad() throws {
        for cd in [try AttestationFixtures.testCD, try AttestationFixtures.exampleCD] {
            let bytes = Array(cd)
            #expect(bytes.first == 0x30)
            let declared = try #require(Self.derTotalLength(bytes))
            #expect(declared == bytes.count)
        }
    }

    @Test("the test CD is signed by the test CD signing cert, the example CD by CSA key 001")
    func cdSignerKeyIdentifiers() throws {
        let testCert = try Certificate(derEncoded: Array(AttestationFixtures.testCDSigningCert))
        let key001 = try Certificate(derEncoded: Array(AttestationFixtures.productionCDSigningCerts[0]))
        let testSKID = try #require(try testCert.extensions.subjectKeyIdentifier?.keyIdentifier)
        let key001SKID = try #require(try key001.extensions.subjectKeyIdentifier?.keyIdentifier)

        #expect(try Self.signerKeyIdentifier(AttestationFixtures.testCD) == Array(testSKID))
        #expect(try Self.signerKeyIdentifier(AttestationFixtures.exampleCD) == Array(key001SKID))
        #expect(Array(testSKID) != Array(key001SKID))
    }

    @Test("CD signing certificates parse, and the test CD signing key matches its certificate")
    func cdSigningCertsParse() throws {
        let testCert = try Certificate(derEncoded: Array(AttestationFixtures.testCDSigningCert))
        let pem = try #require(String(data: AttestationFixtures.testCDSigningKey, encoding: .utf8))
        let key = try P256.Signing.PrivateKey(pemRepresentation: pem)
        let certKey = try #require(P256.Signing.PublicKey(testCert.publicKey))
        #expect(key.publicKey.x963Representation == certKey.x963Representation)

        let production = try AttestationFixtures.productionCDSigningCerts
        #expect(production.count == 5)
        for der in production {
            _ = try Certificate(derEncoded: Array(der))
        }
    }

    // MARK: - Helpers

    /// Header plus content length of the outermost DER element, or nil if the header is malformed.
    static func derTotalLength(_ bytes: [UInt8]) -> Int? {
        guard bytes.count >= 2 else { return nil }
        let first = Int(bytes[1])
        if first < 0x80 { return 2 + first }
        let count = first & 0x7F
        guard count > 0, count <= 4, bytes.count >= 2 + count else { return nil }
        let length = bytes[2..<(2 + count)].reduce(0) { $0 << 8 | Int($1) }
        return 2 + count + length
    }

    /// The `subjectKeyIdentifier` naming the only signer of a CMS SignedData ContentInfo.
    static func signerKeyIdentifier(_ cd: Data) throws -> [UInt8]? {
        // ContentInfo ::= SEQUENCE { contentType, [0] EXPLICIT SignedData }
        guard case .constructed(let contentInfo) = try DER.parse(Array(cd)).content,
              let explicit = Array(contentInfo).last,
              case .constructed(let wrapped) = explicit.content,
              let signedData = Array(wrapped).first,
              case .constructed(let fields) = signedData.content,
              // signerInfos is the last field of SignedData.
              let signerInfos = Array(fields).last,
              case .constructed(let infos) = signerInfos.content,
              Array(infos).count == 1,
              case .constructed(let signerInfo) = Array(infos)[0].content
        else { return nil }
        // SignerInfo ::= SEQUENCE { version, sid, ... }; sid is [0] IMPLICIT SubjectKeyIdentifier.
        let sid = Array(signerInfo)[1]
        guard sid.identifier == ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific),
              case .primitive(let keyIdentifier) = sid.content
        else { return nil }
        return Array(keyIdentifier)
    }

    // MARK: - Commissioner DUT Vectors

    @Test("every commissioner DUT vector decodes")
    func vectorsDecode() throws {
        let cases = try AttestationFixtures.negativeCases
        #expect(cases.count == 153)
        #expect(cases.contains { $0.vector.isSuccessCase })
        #expect(cases.contains { !$0.vector.isSuccessCase })
        for (name, vector) in cases {
            #expect(!vector.dacCert.isEmpty, "\(name)")
            #expect(!vector.paiCert.isEmpty, "\(name)")
            #expect(!vector.certificationDeclaration.isEmpty, "\(name)")
            #expect(vector.dacPrivateKey.count == 32, "\(name)")
            #expect(vector.dacPublicKey.count == 65, "\(name)")
        }
    }
}
