// DeviceAttestationVerifierTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
import X509
import MatterTypes
@testable import MatterCrypto
import MatterTestSupport

// MARK: - Vector table

/// What `verify` must return for a connectedhomeip commissioner DUT vector.
enum ExpectedAttestation: Sendable, Equatable, CustomStringConvertible {
    case verified
    case failed(AttestationFailureReason)

    var description: String {
        switch self {
        case .verified: "verified"
        case .failed(let reason): reason.rawValue
        }
    }
}

/// One row of the vector → outcome table.
struct ChainVector: Sendable, CustomTestStringConvertible {
    let name: String
    let expected: ExpectedAttestation

    var testDescription: String { "\(name) → \(expected)" }
}

/// Every commissioner DUT vector whose outcome concerns the DAC/PAI/PAA chain or the VID/PID
/// rules, with the reason `verify` must give. The `struct_cd_*` vectors are tabled in
/// CertificationDeclarationTests.swift.
///
/// Classification (mirrors connectedhomeip v1.4.0.0 `DefaultDACVerifier`):
/// - a certificate swift-certificates cannot parse (SHA-1, secp256k1), a VID/PID attribute that
///   `ExtractVIDPIDFromAttributeString` rejects, or a break of the Matter certificate profile
///   (`VerifyAttestationCertificateFormat`): upstream `k{Dac,Pai,Paa}FormatInvalid` → `.malformed`;
/// - a missing or disagreeing VID/PID: upstream `kDac{Vendor,Product}IdMismatch` → `.vidPidMismatch`;
/// - a certificate outside its validity window: upstream `kDacExpired` / chain time → `.certificateExpired`;
/// - a PAI no trusted PAA issued: upstream `kPaaNotFound` → `.untrustedRoot`.
///
/// `struct_{dac,pai}_subject_pid_mismatch` have a valid chain (DAC PID 0x8001, PAI without a
/// PID); upstream rejects them in `ValidateCertificateDeclarationPayload`
/// (DefaultDeviceAttestationVerifier.cpp, v1.4.0.0): the dac vector's CD lists 0x8000, so the
/// DAC PID is not in it (:552, `kCertificationDeclarationInvalidProductId`); the pai vector's
/// CD lists 0x8001, so the Basic Information PID 0x8000 is not in it (:517, same code). Both
/// give `.cdVidPidNotListed`.
let chainVectorTable: [ChainVector] = [
    .init(name: "invalid_paa", expected: .failed(.untrustedRoot)),

    // DAC
    .init(name: "struct_dac_cert_version_v2", expected: .failed(.malformed)),
    .init(name: "struct_dac_cert_version_v3", expected: .verified),
    .init(name: "struct_dac_ext_akid_missing", expected: .failed(.malformed)),
    .init(name: "struct_dac_ext_authority_info_access_present", expected: .verified),
    .init(name: "struct_dac_ext_basic_ca_missing", expected: .failed(.malformed)),
    .init(name: "struct_dac_ext_basic_ca_wrong", expected: .failed(.malformed)),
    .init(name: "struct_dac_ext_basic_critical_missing", expected: .failed(.malformed)),
    .init(name: "struct_dac_ext_basic_critical_wrong", expected: .failed(.malformed)),
    .init(name: "struct_dac_ext_basic_missing", expected: .failed(.malformed)),
    .init(name: "struct_dac_ext_basic_pathlen0", expected: .failed(.malformed)),
    .init(name: "struct_dac_ext_basic_pathlen1", expected: .failed(.malformed)),
    .init(name: "struct_dac_ext_basic_pathlen2", expected: .failed(.malformed)),
    .init(name: "struct_dac_ext_basic_pathlen_presence_wrong", expected: .failed(.malformed)),
    .init(name: "struct_dac_ext_extended_key_usage_present", expected: .verified),
    .init(name: "struct_dac_ext_key_usage_critical_missing", expected: .failed(.malformed)),
    .init(name: "struct_dac_ext_key_usage_critical_wrong", expected: .failed(.malformed)),
    .init(name: "struct_dac_ext_key_usage_crl_sign_wrong", expected: .failed(.malformed)),
    .init(name: "struct_dac_ext_key_usage_dig_sig_wrong", expected: .failed(.malformed)),
    .init(name: "struct_dac_ext_key_usage_key_cert_sign_wrong", expected: .failed(.malformed)),
    .init(name: "struct_dac_ext_key_usage_missing", expected: .failed(.malformed)),
    .init(name: "struct_dac_ext_skid_missing", expected: .failed(.malformed)),
    .init(name: "struct_dac_ext_subject_alt_name_present", expected: .verified),
    .init(name: "struct_dac_sig_algo_ecdsa_with_sha1", expected: .failed(.malformed)),
    .init(name: "struct_dac_sig_algo_ecdsa_with_sha256", expected: .verified),
    .init(name: "struct_dac_sig_curve_prime256v1", expected: .verified),
    .init(name: "struct_dac_sig_curve_secp256k1", expected: .failed(.malformed)),
    .init(name: "struct_dac_subject_pid_mismatch", expected: .failed(.cdVidPidNotListed)),
    .init(name: "struct_dac_subject_vid_mismatch", expected: .failed(.vidPidMismatch)),
    .init(name: "struct_dac_valid_in_future", expected: .failed(.certificateExpired)),
    .init(name: "struct_dac_valid_in_past", expected: .failed(.certificateExpired)),
    .init(name: "struct_dac_vidpid_fallback_encoding_01", expected: .verified),
    .init(name: "struct_dac_vidpid_fallback_encoding_02", expected: .verified),
    .init(name: "struct_dac_vidpid_fallback_encoding_03", expected: .verified),
    .init(name: "struct_dac_vidpid_fallback_encoding_04", expected: .verified),
    .init(name: "struct_dac_vidpid_fallback_encoding_05", expected: .verified),
    .init(name: "struct_dac_vidpid_fallback_encoding_06", expected: .failed(.malformed)),
    .init(name: "struct_dac_vidpid_fallback_encoding_07", expected: .failed(.malformed)),
    .init(name: "struct_dac_vidpid_fallback_encoding_08", expected: .failed(.malformed)),
    .init(name: "struct_dac_vidpid_fallback_encoding_09", expected: .failed(.malformed)),
    .init(name: "struct_dac_vidpid_fallback_encoding_10", expected: .failed(.malformed)),
    .init(name: "struct_dac_vidpid_fallback_encoding_11", expected: .verified),
    .init(name: "struct_dac_vidpid_fallback_encoding_12", expected: .failed(.malformed)),
    .init(name: "struct_dac_vidpid_fallback_encoding_13", expected: .failed(.vidPidMismatch)),
    .init(name: "struct_dac_vidpid_fallback_encoding_14", expected: .failed(.vidPidMismatch)),
    .init(name: "struct_dac_vidpid_fallback_encoding_15", expected: .verified),
    .init(name: "struct_dac_vidpid_fallback_encoding_16", expected: .failed(.vidPidMismatch)),
    .init(name: "struct_dac_vidpid_fallback_encoding_17", expected: .failed(.vidPidMismatch)),
    .init(name: "struct_dac_vidpid_fallback_encoding_18", expected: .verified),
    .init(name: "struct_dac_vidpid_fallback_encoding_19", expected: .failed(.malformed)),

    // PAI
    .init(name: "struct_pai_cert_version_v2", expected: .failed(.malformed)),
    .init(name: "struct_pai_cert_version_v3", expected: .verified),
    .init(name: "struct_pai_ext_akid_missing", expected: .failed(.malformed)),
    .init(name: "struct_pai_ext_authority_info_access_present", expected: .verified),
    .init(name: "struct_pai_ext_basic_ca_missing", expected: .failed(.malformed)),
    .init(name: "struct_pai_ext_basic_ca_wrong", expected: .failed(.malformed)),
    .init(name: "struct_pai_ext_basic_critical_missing", expected: .failed(.malformed)),
    .init(name: "struct_pai_ext_basic_critical_wrong", expected: .failed(.malformed)),
    .init(name: "struct_pai_ext_basic_missing", expected: .failed(.malformed)),
    .init(name: "struct_pai_ext_basic_pathlen0", expected: .verified),
    .init(name: "struct_pai_ext_basic_pathlen1", expected: .failed(.malformed)),
    .init(name: "struct_pai_ext_basic_pathlen2", expected: .failed(.malformed)),
    .init(name: "struct_pai_ext_basic_pathlen_presence_wrong", expected: .failed(.malformed)),
    .init(name: "struct_pai_ext_extended_key_usage_present", expected: .verified),
    .init(name: "struct_pai_ext_key_usage_critical_missing", expected: .failed(.malformed)),
    .init(name: "struct_pai_ext_key_usage_critical_wrong", expected: .failed(.malformed)),
    .init(name: "struct_pai_ext_key_usage_crl_sign_wrong", expected: .failed(.malformed)),
    .init(name: "struct_pai_ext_key_usage_dig_sig_wrong", expected: .verified),
    .init(name: "struct_pai_ext_key_usage_key_cert_sign_wrong", expected: .failed(.malformed)),
    .init(name: "struct_pai_ext_key_usage_missing", expected: .failed(.malformed)),
    .init(name: "struct_pai_ext_skid_missing", expected: .failed(.malformed)),
    .init(name: "struct_pai_ext_subject_alt_name_present", expected: .verified),
    .init(name: "struct_pai_sig_algo_ecdsa_with_sha1", expected: .failed(.malformed)),
    .init(name: "struct_pai_sig_algo_ecdsa_with_sha256", expected: .verified),
    .init(name: "struct_pai_sig_curve_prime256v1", expected: .verified),
    .init(name: "struct_pai_sig_curve_secp256k1", expected: .failed(.malformed)),
    .init(name: "struct_pai_subject_pid_mismatch", expected: .failed(.cdVidPidNotListed)),
    .init(name: "struct_pai_subject_vid_mismatch", expected: .failed(.vidPidMismatch)),
    .init(name: "struct_pai_valid_in_future", expected: .failed(.certificateExpired)),
    .init(name: "struct_pai_valid_in_past", expected: .failed(.certificateExpired)),
    .init(name: "struct_pai_vidpid_fallback_encoding_01", expected: .verified),
    .init(name: "struct_pai_vidpid_fallback_encoding_02", expected: .verified),
    .init(name: "struct_pai_vidpid_fallback_encoding_03", expected: .verified),
    .init(name: "struct_pai_vidpid_fallback_encoding_04", expected: .verified),
    .init(name: "struct_pai_vidpid_fallback_encoding_05", expected: .verified),
    .init(name: "struct_pai_vidpid_fallback_encoding_06", expected: .failed(.malformed)),
    .init(name: "struct_pai_vidpid_fallback_encoding_07", expected: .failed(.malformed)),
    .init(name: "struct_pai_vidpid_fallback_encoding_08", expected: .failed(.malformed)),
    .init(name: "struct_pai_vidpid_fallback_encoding_09", expected: .failed(.malformed)),
    .init(name: "struct_pai_vidpid_fallback_encoding_10", expected: .failed(.malformed)),
    .init(name: "struct_pai_vidpid_fallback_encoding_11", expected: .verified),
    .init(name: "struct_pai_vidpid_fallback_encoding_12", expected: .failed(.malformed)),
    .init(name: "struct_pai_vidpid_fallback_encoding_13", expected: .failed(.vidPidMismatch)),
    .init(name: "struct_pai_vidpid_fallback_encoding_14", expected: .failed(.vidPidMismatch)),
    .init(name: "struct_pai_vidpid_fallback_encoding_15", expected: .verified),
    .init(name: "struct_pai_vidpid_fallback_encoding_16", expected: .failed(.vidPidMismatch)),
    .init(name: "struct_pai_vidpid_fallback_encoding_17", expected: .failed(.vidPidMismatch)),
    .init(name: "struct_pai_vidpid_fallback_encoding_18", expected: .verified),
    .init(name: "struct_pai_vidpid_fallback_encoding_19", expected: .failed(.malformed)),
]

// MARK: - DeviceAttestationVerifierTests

@Suite("DeviceAttestationVerifier Tests", .timeLimit(.minutes(5)))
struct DeviceAttestationVerifierTests {

    // MARK: - Helpers

    private static let challenge = Data((0..<16).map { UInt8($0) })
    private static let nonce = Data((0..<32).map { UInt8(0xA0 &+ $0) })

    /// A fixed time at which every fixture certificate that is meant to be valid is valid:
    /// after the latest success-case DAC notBefore (2024-05-27) and before the
    /// `struct_pai_valid_in_*` DACs expire (2024-09-27), so those vectors fail on the PAI rule
    /// they test rather than on the DAC-at-now rule.
    private static let now = SyntheticAttestationChain.date(2024, month: 7, day: 1)

    /// The Basic Information the dev device (and the synthetic chain) reports.
    private static let devBasicInformation: (vendorID: UInt16, productID: UInt16) = (0xFFF1, 0x8000)

    private static func trustStore(paas: [Data]? = nil) throws -> AttestationTrustStore {
        try AttestationTrustStore(
            paas: paas ?? [AttestationFixtures.testPAA],
            cdSigningKeys: [CDSigningKey(certificateDER: AttestationFixtures.testCDSigningCert)],
            provenance: TrustStoreProvenance(source: "explicit")
        )
    }

    /// Attestation elements TLV: {1: CD, 2: nonce, 3: timestamp 0}.
    private static func elements(cd: Data, nonce: Data) -> Data {
        TLVEncoder.encode(.structure([
            .init(tag: .contextSpecific(1), value: .octetString(cd)),
            .init(tag: .contextSpecific(2), value: .octetString(nonce)),
            .init(tag: .contextSpecific(3), value: .unsignedInt(0)),
        ]))
    }

    private static func sign(_ elements: Data, with key: P256.Signing.PrivateKey) throws -> Data {
        try key.signature(for: elements + challenge).rawRepresentation
    }

    private static func devKey() throws -> P256.Signing.PrivateKey {
        try P256.Signing.PrivateKey(derRepresentation: AttestationFixtures.devDACPrivateKey)
    }

    /// Verifies the dev DAC/PAI with elements signed by the dev DAC key.
    private static func verifyDev(
        store: AttestationTrustStore? = nil,
        dac: Data? = nil,
        pai: Data? = nil,
        elementsNonce: Data = nonce,
        sentNonce: Data = nonce,
        tamper: (Data) -> Data = { $0 },
        now: Date = now
    ) async throws -> AttestationResult {
        let elements = elements(cd: try AttestationFixtures.testCD, nonce: elementsNonce)
        let signature = tamper(try sign(elements, with: devKey()))
        let verifier = DeviceAttestationVerifier(trustStore: try store ?? trustStore())
        return await verifier.verify(
            dac: try dac ?? AttestationFixtures.devDAC,
            pai: try pai ?? AttestationFixtures.devPAI,
            attestationElements: elements, attestationSignature: signature,
            attestationChallenge: challenge, sentNonce: sentNonce,
            basicInformation: devBasicInformation, now: now
        )
    }

    private static func failure(_ result: AttestationResult) -> AttestationFailure? {
        if case .failed(let failure) = result { return failure }
        return nil
    }

    // MARK: - Dev chain

    @Test("the dev DAC and PAI verify against the test PAA")
    func devChainVerifies() async throws {
        let result = try await Self.verifyDev()
        let paa = try Certificate(derEncoded: Array(AttestationFixtures.testPAA))
        let dacDER = try AttestationFixtures.devDAC
        let expected = VerifiedAttestation(
            vendorID: 0xFFF1, productID: 0x8000,
            paaSubject: paa.subject.description,
            dacFingerprint: Data(SHA256.hash(data: dacDER)),
            dacPublicKey: try Self.devKey().publicKey
        )
        #expect(result == .verified(expected))
    }

    @Test("a DER-encoded attestation signature gives attestationSignatureInvalid (raw r||s only)")
    func derSignatureRejected() async throws {
        let elements = Self.elements(cd: try AttestationFixtures.testCD, nonce: Self.nonce)
        let signature = try Self.devKey().signature(for: elements + Self.challenge).derRepresentation
        let result = await DeviceAttestationVerifier(trustStore: try Self.trustStore()).verify(
            dac: try AttestationFixtures.devDAC, pai: try AttestationFixtures.devPAI,
            attestationElements: elements, attestationSignature: signature,
            attestationChallenge: Self.challenge, sentNonce: Self.nonce,
            basicInformation: Self.devBasicInformation, now: Self.now
        )
        #expect(Self.failure(result)?.reason == .attestationSignatureInvalid)
    }

    // MARK: - Failures

    @Test("an empty trust store gives untrustedRoot")
    func emptyTrustStore() async throws {
        let result = try await Self.verifyDev(store: Self.trustStore(paas: []))
        let failure = try #require(Self.failure(result))
        #expect(failure.reason == .untrustedRoot)
        #expect(failure.dacFingerprint == Data(SHA256.hash(data: try AttestationFixtures.devDAC)))
    }

    @Test("a time after the DAC's notAfter gives certificateExpired")
    func expiredDAC() async throws {
        let dac = try Certificate(derEncoded: Array(AttestationFixtures.devDAC))
        let result = try await Self.verifyDev(now: dac.notValidAfter.addingTimeInterval(1))
        #expect(Self.failure(result)?.reason == .certificateExpired)
    }

    @Test("a time before the DAC's notBefore gives certificateExpired")
    func notYetValidDAC() async throws {
        let dac = try Certificate(derEncoded: Array(AttestationFixtures.devDAC))
        let result = try await Self.verifyDev(now: dac.notValidBefore.addingTimeInterval(-1))
        #expect(Self.failure(result)?.reason == .certificateExpired)
    }

    @Test("a nonce other than the one sent gives nonceMismatch")
    func wrongNonce() async throws {
        let result = try await Self.verifyDev(sentNonce: Data(repeating: 0x55, count: 32))
        #expect(Self.failure(result)?.reason == .nonceMismatch)
    }

    @Test("a flipped signature byte gives attestationSignatureInvalid")
    func flippedSignature() async throws {
        let result = try await Self.verifyDev(tamper: { signature in
            var copy = signature
            copy[copy.startIndex + 10] ^= 0x01
            return copy
        })
        #expect(Self.failure(result)?.reason == .attestationSignatureInvalid)
    }

    @Test("a signature of the wrong length gives attestationSignatureInvalid")
    func truncatedSignature() async throws {
        let result = try await Self.verifyDev(tamper: { $0.prefix(40) })
        #expect(Self.failure(result)?.reason == .attestationSignatureInvalid)
    }

    @Test("a garbage DAC gives malformed with no fingerprint")
    func garbageDAC() async throws {
        let result = try await Self.verifyDev(dac: Data([0x30, 0x03, 0x01, 0x02, 0x03]))
        let failure = try #require(Self.failure(result))
        #expect(failure.reason == .malformed)
        #expect(failure.dacFingerprint == nil)
    }

    @Test("a garbage PAI gives malformed with the DAC fingerprint")
    func garbagePAI() async throws {
        let result = try await Self.verifyDev(pai: Data([0xDE, 0xAD]))
        let failure = try #require(Self.failure(result))
        #expect(failure.reason == .malformed)
        #expect(failure.dacFingerprint == Data(SHA256.hash(data: try AttestationFixtures.devDAC)))
    }

    @Test("attestation elements that are not a TLV structure give malformed")
    func garbageElements() async throws {
        let elements = Data([0x15, 0x30])  // structure start, truncated
        let verifier = DeviceAttestationVerifier(trustStore: try Self.trustStore())
        let result = await verifier.verify(
            dac: try AttestationFixtures.devDAC, pai: try AttestationFixtures.devPAI,
            attestationElements: elements,
            attestationSignature: try Self.sign(elements, with: Self.devKey()),
            attestationChallenge: Self.challenge, sentNonce: Self.nonce,
            basicInformation: Self.devBasicInformation, now: Self.now
        )
        #expect(Self.failure(result)?.reason == .malformed)
    }

    @Test("a DAC the PAI did not sign gives chainInvalid, not untrustedRoot")
    func dacNotSignedByPAI() async throws {
        let foreign = try DeviceAttestationCredentials.testCredentials()
        let elements = Self.elements(cd: Data(), nonce: Self.nonce)
        let verifier = DeviceAttestationVerifier(trustStore: try Self.trustStore())
        let result = await verifier.verify(
            dac: foreign.dacCertificate, pai: try AttestationFixtures.devPAI,
            attestationElements: elements,
            attestationSignature: try Self.sign(elements, with: foreign.dacPrivateKey),
            attestationChallenge: Self.challenge, sentNonce: Self.nonce,
            basicInformation: Self.devBasicInformation, now: Self.now
        )
        #expect(Self.failure(result)?.reason == .chainInvalid)
    }

    @Test("failure details carry no private key material")
    func detailHasNoKeyMaterial() async throws {
        let result = try await Self.verifyDev(sentNonce: Data(repeating: 0x55, count: 32))
        let failure = try #require(Self.failure(result))
        let keyHex = try Self.devKey().rawRepresentation.map { String(format: "%02x", $0) }.joined()
        #expect(!failure.detail.lowercased().contains(keyHex))
    }

    // MARK: - Commissioner DUT vectors

    /// Runs `verify` on a vector, signing fresh elements with the vector's own DAC key.
    /// The Basic Information VendorID is assumed to be 0xFFF1 (the vectors give only a PID).
    static func verify(vector: NegativeCaseVector, store: AttestationTrustStore) async -> AttestationResult {
        let elements = elements(cd: vector.certificationDeclaration, nonce: nonce)
        let signature: Data
        if let key = try? P256.Signing.PrivateKey(rawRepresentation: vector.dacPrivateKey),
           let signed = try? sign(elements, with: key) {
            signature = signed
        } else {
            signature = Data(count: 64)
        }
        return await DeviceAttestationVerifier(trustStore: store).verify(
            dac: vector.dacCert, pai: vector.paiCert,
            attestationElements: elements, attestationSignature: signature,
            attestationChallenge: challenge, sentNonce: nonce,
            basicInformation: (vendorID: 0xFFF1, productID: vector.basicInfoPID),
            now: now
        )
    }

    @Test("commissioner DUT chain vectors give the tabled outcome", arguments: chainVectorTable)
    func chainVector(_ row: ChainVector) async throws {
        let vectors = try AttestationFixtures.negativeCases
        let vector = try #require(vectors.first(where: { $0.name == row.name })?.vector)
        let result = await Self.verify(vector: vector, store: try Self.trustStore())
        switch (row.expected, result) {
        case (.verified, .verified):
            break
        case (.failed(let reason), .failed(let failure)):
            #expect(failure.reason == reason, "\(row.name): \(failure.detail)")
            if row.name.hasPrefix("struct_pai_valid_in_") {
                // At the fixed `now` the DAC is valid; the PAI-at-issuance rule must be what fails.
                #expect(failure.detail.contains("PAI is valid"), "\(row.name): \(failure.detail)")
            }
        default:
            Issue.record("\(row.name): expected \(row.expected), got \(result)")
        }
        // The table's verdict agrees with upstream's.
        #expect(vector.isSuccessCase == (row.expected == .verified))
    }

    @Test("the table covers every chain vector, and only those")
    func tableCoversEveryChainVector() throws {
        let names = Set(try AttestationFixtures.negativeCases.map(\.name).filter { !$0.hasPrefix("struct_cd_") })
        let tabled = chainVectorTable.map(\.name)
        #expect(Set(tabled) == names)
        #expect(tabled.count == names.count)
    }

    // MARK: - Attestation elements

    private static func verifyElements(_ fields: [TLVElement.TLVField]) async throws -> AttestationResult {
        let elements = TLVEncoder.encode(.structure(fields))
        return await DeviceAttestationVerifier(trustStore: try trustStore()).verify(
            dac: try AttestationFixtures.devDAC, pai: try AttestationFixtures.devPAI,
            attestationElements: elements, attestationSignature: try sign(elements, with: devKey()),
            attestationChallenge: challenge, sentNonce: nonce,
            basicInformation: devBasicInformation, now: now
        )
    }

    @Test("attestation elements with a firmware field, a later context tag and a profile tag verify")
    func elementsWithOptionalFields() async throws {
        let result = try await Self.verifyElements([
            .init(tag: .contextSpecific(1), value: .octetString(try AttestationFixtures.testCD)),
            .init(tag: .contextSpecific(2), value: .octetString(Self.nonce)),
            .init(tag: .contextSpecific(3), value: .unsignedInt(0)),
            .init(tag: .contextSpecific(4), value: .octetString(Data([1, 2, 3]))),
            .init(tag: .contextSpecific(7), value: .unsignedInt(1)),
            .init(tag: .fullyQualified(vendorID: 0xFFF1, profileNumber: 1, tag: 1), value: .octetString(Data([9]))),
        ])
        guard case .verified = result else {
            Issue.record("expected verified, got \(result)")
            return
        }
    }

    @Test("attestation elements without the CD (tag 1) give malformed")
    func elementsMissingCD() async throws {
        let result = try await Self.verifyElements([
            .init(tag: .contextSpecific(2), value: .octetString(Self.nonce)),
            .init(tag: .contextSpecific(3), value: .unsignedInt(0)),
        ])
        #expect(Self.failure(result)?.reason == .malformed)
    }

    @Test("attestation elements without the timestamp (tag 3) give malformed")
    func elementsMissingTimestamp() async throws {
        let result = try await Self.verifyElements([
            .init(tag: .contextSpecific(1), value: .octetString(try AttestationFixtures.testCD)),
            .init(tag: .contextSpecific(2), value: .octetString(Self.nonce)),
        ])
        #expect(Self.failure(result)?.reason == .malformed)
    }

    @Test("attestation elements with out-of-order tags give malformed")
    func elementsOutOfOrder() async throws {
        let result = try await Self.verifyElements([
            .init(tag: .contextSpecific(1), value: .octetString(try AttestationFixtures.testCD)),
            .init(tag: .contextSpecific(3), value: .unsignedInt(0)),
            .init(tag: .contextSpecific(2), value: .octetString(Self.nonce)),
        ])
        #expect(Self.failure(result)?.reason == .malformed)
    }

    @Test("attestation elements with a timestamp above UInt32.max give malformed")
    func elementsTimestampTooLarge() async throws {
        let result = try await Self.verifyElements([
            .init(tag: .contextSpecific(1), value: .octetString(try AttestationFixtures.testCD)),
            .init(tag: .contextSpecific(2), value: .octetString(Self.nonce)),
            .init(tag: .contextSpecific(3), value: .unsignedInt(UInt64(UInt32.max) + 1)),
        ])
        #expect(Self.failure(result)?.reason == .malformed)
    }

    // MARK: - Synthetic chains (signatures, key identifiers and the validity model)

    private static func date(_ year: Int) -> Date { SyntheticAttestationChain.date(year) }

    /// `now` is fixed so the outcome never depends on the wall clock.
    private static let syntheticNow = date(2030)

    private static func verify(_ chain: SyntheticAttestationChain, now: Date = syntheticNow) async throws -> AttestationResult {
        let store = try AttestationTrustStore(
            paas: [chain.paa],
            cdSigningKeys: [CDSigningKey(certificateDER: AttestationFixtures.testCDSigningCert)],
            provenance: TrustStoreProvenance(source: "explicit"))
        // The synthetic DAC is FFF1/8000, which the test CD lists.
        let elements = Self.elements(cd: try AttestationFixtures.testCD, nonce: Self.nonce)
        return await DeviceAttestationVerifier(trustStore: store).verify(
            dac: chain.dac, pai: chain.pai,
            attestationElements: elements, attestationSignature: try Self.sign(elements, with: chain.dacKey),
            attestationChallenge: Self.challenge, sentNonce: Self.nonce,
            basicInformation: Self.devBasicInformation, now: now
        )
    }

    private static func standardChain(
        paiSigner: P256.Signing.PrivateKey? = nil, paiAKI: [UInt8]? = nil,
        dacSigner: P256.Signing.PrivateKey? = nil, dacAKI: [UInt8]? = nil,
        dacCriticalSubjectAlternativeName: Bool = false
    ) throws -> SyntheticAttestationChain {
        try SyntheticAttestationChain(
            paaValidity: date(2020)...date(2040),
            paiValidity: date(2021)...date(2039),
            dacValidity: date(2022)...date(2038),
            paiSigner: paiSigner, paiAKI: paiAKI, dacSigner: dacSigner, dacAKI: dacAKI,
            dacCriticalSubjectAlternativeName: dacCriticalSubjectAlternativeName
        )
    }

    @Test("a synthetic Matter-profile chain verifies")
    func syntheticChainVerifies() async throws {
        let result = try await Self.verify(Self.standardChain())
        guard case .verified = result else {
            Issue.record("expected verified, got \(result)")
            return
        }
    }

    @Test("a DAC with a critical subjectAlternativeName verifies")
    func criticalSubjectAlternativeName() async throws {
        let result = try await Self.verify(Self.standardChain(dacCriticalSubjectAlternativeName: true))
        guard case .verified = result else {
            Issue.record("expected verified, got \(result)")
            return
        }
    }

    @Test("a PAI whose signature does not verify under the PAA (same AKI) gives chainInvalid")
    func paiSignatureInvalid() async throws {
        let result = try await Self.verify(Self.standardChain(paiSigner: P256.Signing.PrivateKey()))
        #expect(Self.failure(result)?.reason == .chainInvalid, "\(result)")
    }

    @Test("a PAI signed by an unknown key with another AKI gives untrustedRoot")
    func paiFromUnknownAuthority() async throws {
        let result = try await Self.verify(Self.standardChain(
            paiSigner: P256.Signing.PrivateKey(), paiAKI: Array(repeating: 0x42, count: 20)))
        #expect(Self.failure(result)?.reason == .untrustedRoot, "\(result)")
    }

    @Test("a PAI signed by the PAA but whose AKI is not the PAA's SKI gives untrustedRoot")
    func paiAKIMismatch() async throws {
        let result = try await Self.verify(Self.standardChain(paiAKI: Array(repeating: 0x42, count: 20)))
        #expect(Self.failure(result)?.reason == .untrustedRoot, "\(result)")
    }

    @Test("a DAC signed by the PAI but whose AKI is not the PAI's SKI gives chainInvalid")
    func dacAKIMismatch() async throws {
        let result = try await Self.verify(Self.standardChain(dacAKI: Array(repeating: 0x24, count: 20)))
        #expect(Self.failure(result)?.reason == .chainInvalid, "\(result)")
    }

    @Test("a DAC naming the PAI (DN and AKI) but signed by another key gives chainInvalid")
    func dacSignedByAnotherKey() async throws {
        let result = try await Self.verify(Self.standardChain(dacSigner: P256.Signing.PrivateKey()))
        #expect(Self.failure(result)?.reason == .chainInvalid, "\(result)")
    }

    @Test("a PAI and PAA expired now but valid at the DAC's notBefore verify (upstream's reference time)")
    func issuersValidAtDACIssuance() async throws {
        let chain = try SyntheticAttestationChain(
            paaValidity: Self.date(2020)...Self.date(2029),
            paiValidity: Self.date(2021)...Self.date(2028),
            dacValidity: Self.date(2022)...Self.date(2038)
        )
        let result = try await Self.verify(chain)
        guard case .verified = result else {
            Issue.record("expected verified, got \(result)")
            return
        }
    }

    @Test("a PAI not yet valid at the DAC's notBefore gives certificateExpired")
    func paiNotValidAtDACIssuance() async throws {
        let chain = try SyntheticAttestationChain(
            paaValidity: Self.date(2020)...Self.date(2040),
            paiValidity: Self.date(2023)...Self.date(2039),
            dacValidity: Self.date(2022)...Self.date(2038)
        )
        #expect(Self.failure(try await Self.verify(chain))?.reason == .certificateExpired)
    }

    @Test("a PAA expired by the DAC's notBefore gives certificateExpired")
    func paaExpiredAtDACIssuance() async throws {
        let chain = try SyntheticAttestationChain(
            paaValidity: Self.date(2020)...Self.date(2021),
            paiValidity: Self.date(2020)...Self.date(2039),
            dacValidity: Self.date(2022)...Self.date(2038)
        )
        #expect(Self.failure(try await Self.verify(chain))?.reason == .certificateExpired)
    }

    @Test("a DAC expired now gives certificateExpired even though it was valid at issuance")
    func dacExpiredNow() async throws {
        let chain = try SyntheticAttestationChain(
            paaValidity: Self.date(2020)...Self.date(2040),
            paiValidity: Self.date(2021)...Self.date(2039),
            dacValidity: Self.date(2022)...Self.date(2029)
        )
        #expect(Self.failure(try await Self.verify(chain))?.reason == .certificateExpired)
    }

    // MARK: - NOCSR signature

    @Test("verifyNOCSRSignature accepts the DAC's raw signature and rejects another key, a DER signature and garbage")
    func nocsrSignature() throws {
        let key = try Self.devKey()
        let nocsr = TLVEncoder.encode(.structure([
            .init(tag: .contextSpecific(1), value: .octetString(Data(repeating: 0x11, count: 64))),
            .init(tag: .contextSpecific(2), value: .octetString(Self.nonce)),
        ]))
        let signature = try key.signature(for: nocsr + Self.challenge)

        #expect(DeviceAttestationVerifier.verifyNOCSRSignature(
            nocsrElements: nocsr, signature: signature.rawRepresentation,
            attestationChallenge: Self.challenge, dacPublicKey: key.publicKey))
        #expect(!DeviceAttestationVerifier.verifyNOCSRSignature(
            nocsrElements: nocsr, signature: signature.derRepresentation,
            attestationChallenge: Self.challenge, dacPublicKey: key.publicKey))
        #expect(!DeviceAttestationVerifier.verifyNOCSRSignature(
            nocsrElements: nocsr, signature: signature.rawRepresentation,
            attestationChallenge: Self.challenge, dacPublicKey: P256.Signing.PrivateKey().publicKey))
        #expect(!DeviceAttestationVerifier.verifyNOCSRSignature(
            nocsrElements: nocsr, signature: signature.rawRepresentation,
            attestationChallenge: Data(repeating: 0, count: 16), dacPublicKey: key.publicKey))
        #expect(!DeviceAttestationVerifier.verifyNOCSRSignature(
            nocsrElements: nocsr, signature: Data([1, 2, 3]),
            attestationChallenge: Self.challenge, dacPublicKey: key.publicKey))
    }
}
