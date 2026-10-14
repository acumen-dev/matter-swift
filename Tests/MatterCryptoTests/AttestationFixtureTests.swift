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

    @Test("dev DAC private key matches the DAC's public key")
    func dacPrivateKeyMatches() throws {
        let dac = try Certificate(derEncoded: Array(AttestationFixtures.devDAC))
        let key = try P256.Signing.PrivateKey(derRepresentation: AttestationFixtures.devDACPrivateKey)
        let certKey = try #require(P256.Signing.PublicKey(dac.publicKey))
        #expect(key.publicKey.x963Representation == certKey.x963Representation)
    }

    // MARK: - Certification Declarations

    @Test("CDs load as DER SEQUENCEs")
    func cdsLoad() throws {
        for cd in [try AttestationFixtures.testCD, try AttestationFixtures.exampleCD] {
            #expect(cd.first == 0x30)
            #expect(cd.count > 100)
        }
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
