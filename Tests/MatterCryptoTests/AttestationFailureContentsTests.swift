// AttestationFailureContentsTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
import X509
import SwiftASN1
import MatterTypes
import MatterCrypto
import MatterTestSupport

/// A failure carries the DAC's key and subject VID/PID from the verifier's own parse of the
/// DAC whose fingerprint it names: what a commissioner approving it binds the device to.
@Suite("AttestationFailure carries the DAC's unverified contents")
struct AttestationFailureContentsTests {

    static let challenge = Data(repeating: 0x11, count: 16)
    static let nonce = Data(repeating: 0x22, count: 32)
    static let now = SyntheticAttestationChain.date(2024, month: 7, day: 1)

    static func failure(dac: Data) async throws -> AttestationFailure {
        let store = try AttestationTrustStore(
            paas: [], cdSigningKeys: [], provenance: TrustStoreProvenance(source: "empty"))
        let result = await DeviceAttestationVerifier(trustStore: store).verify(
            dac: dac, pai: try AttestationFixtures.devPAI,
            attestationElements: Data(), attestationSignature: Data(count: 64),
            attestationChallenge: challenge, sentNonce: nonce,
            basicInformation: (0xFFF1, 0x8000), now: now)
        guard case .failed(let failure) = result else {
            Issue.record("expected a failure, got \(result)")
            throw CancellationError()
        }
        return failure
    }

    /// A self-signed certificate with `subject` and `key`, for use as a DAC.
    static func certificate(
        subject: DistinguishedName, key: Certificate.PrivateKey, algorithm: Certificate.SignatureAlgorithm
    ) throws -> Data {
        let certificate = try Certificate(
            version: .v3, serialNumber: .init(), publicKey: key.publicKey,
            notValidBefore: SyntheticAttestationChain.date(2022), notValidAfter: SyntheticAttestationChain.date(2038),
            issuer: subject, subject: subject,
            signatureAlgorithm: algorithm,
            extensions: Certificate.Extensions(), issuerPrivateKey: key)
        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        return Data(serializer.serializedBytes)
    }

    static let vendorIDOID: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 37244, 2, 1]

    @Test("an untrusted-root failure carries the DAC's own key, VID and PID")
    func untrustedRootCarriesDAC() async throws {
        let failure = try await Self.failure(dac: try AttestationFixtures.devDAC)
        #expect(failure.reason == .untrustedRoot)
        #expect(failure.dacFingerprint == Data(SHA256.hash(data: try AttestationFixtures.devDAC)))
        let key = try P256.Signing.PrivateKey(derRepresentation: AttestationFixtures.devDACPrivateKey).publicKey
        #expect(failure.dacPublicKey?.x963Representation == key.x963Representation)
        #expect(failure.dacVendorID == 0xFFF1 && failure.dacProductID == 0x8000)
    }

    @Test("a DAC whose key is not P-256 gives a failure with its fingerprint but no key")
    func nonP256KeyIsNil() async throws {
        let dac = try Self.certificate(
            subject: DistinguishedName([RelativeDistinguishedName(.init(type: .RDNAttributeType.commonName, utf8String: "P-384 DAC"))]),
            key: Certificate.PrivateKey(P384.Signing.PrivateKey()), algorithm: .ecdsaWithSHA384)
        let failure = try await Self.failure(dac: dac)
        #expect(failure.dacFingerprint == Data(SHA256.hash(data: dac)))
        #expect(failure.dacPublicKey == nil)
    }

    @Test("a DAC whose subject VID is malformed gives a failure with its key but no VID or PID")
    func malformedSubjectIDsAreNil() async throws {
        let key = P256.Signing.PrivateKey()
        let dac = try Self.certificate(
            subject: DistinguishedName([
                RelativeDistinguishedName(.init(type: .RDNAttributeType.commonName, utf8String: "Bad VID DAC")),
                RelativeDistinguishedName(.init(type: Self.vendorIDOID, utf8String: "ZZZZ")),
            ]),
            key: Certificate.PrivateKey(key), algorithm: .ecdsaWithSHA256)
        let failure = try await Self.failure(dac: dac)
        #expect(failure.dacFingerprint == Data(SHA256.hash(data: dac)))
        #expect(failure.dacPublicKey?.x963Representation == key.publicKey.x963Representation)
        #expect(failure.dacVendorID == nil && failure.dacProductID == nil)
    }

    @Test("two failures differing only in the carried key are not equal")
    func equalityIncludesKey() {
        let a = AttestationFailure(reason: .untrustedRoot, dacFingerprint: Data([1]), detail: "d",
                                   dacPublicKey: P256.Signing.PrivateKey().publicKey)
        let b = AttestationFailure(reason: .untrustedRoot, dacFingerprint: Data([1]), detail: "d",
                                   dacPublicKey: P256.Signing.PrivateKey().publicKey)
        #expect(a == a)
        #expect(a != b)
    }
}
