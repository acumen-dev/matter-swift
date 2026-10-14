// DeviceAttestationVerifierTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
import SwiftASN1
import X509
import MatterTypes
@testable import MatterCrypto
import MatterTestSupport

// MARK: - Vector table

/// What `verify` must return for a connectedhomeip commissioner DUT vector.
enum ExpectedAttestation: Sendable, Equatable, CustomStringConvertible {
    case verified
    case failed(AttestationFailureReason)
    /// The chain and VID/PID rules pass; upstream rejects the vector later, at the
    /// Certification Declaration stage (Task 4). `verify` must not fail before that stage.
    case failsOnlyAtCD

    var description: String {
        switch self {
        case .verified: "verified"
        case .failed(let reason): reason.rawValue
        case .failsOnlyAtCD: "chain passes; CD stage fails"
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
/// rules, with the reason `verify` must give. The `struct_cd_*` vectors belong to the
/// Certification Declaration check and are excluded here.
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
/// PID); upstream rejects them in `ValidateCertificateDeclarationPayload`: the DAC PID is not
/// in the CD (dac), or the Basic Information PID 0x8000 is not in the CD (pai).
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
    .init(name: "struct_dac_subject_pid_mismatch", expected: .failsOnlyAtCD),
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
    .init(name: "struct_pai_subject_pid_mismatch", expected: .failsOnlyAtCD),
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

    /// A time at which every fixture certificate that is meant to be valid is valid.
    private static let now = Date()

    private static func trustStore(paas: [Data]? = nil) throws -> AttestationTrustStore {
        try AttestationTrustStore(
            paas: paas ?? [AttestationFixtures.testPAA],
            cdSigningKeys: [],
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
            now: now
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

    @Test("a DER-encoded attestation signature is accepted")
    func derSignatureAccepted() async throws {
        let elements = Self.elements(cd: try AttestationFixtures.testCD, nonce: Self.nonce)
        let signature = try Self.devKey().signature(for: elements + Self.challenge).derRepresentation
        let result = await DeviceAttestationVerifier(trustStore: try Self.trustStore()).verify(
            dac: try AttestationFixtures.devDAC, pai: try AttestationFixtures.devPAI,
            attestationElements: elements, attestationSignature: signature,
            attestationChallenge: Self.challenge, sentNonce: Self.nonce, now: Self.now
        )
        guard case .verified = result else {
            Issue.record("expected verified, got \(result)")
            return
        }
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
            attestationChallenge: Self.challenge, sentNonce: Self.nonce, now: Self.now
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
            attestationChallenge: Self.challenge, sentNonce: Self.nonce, now: Self.now
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
        case (.verified, .verified), (.failsOnlyAtCD, .verified):
            break
        case (.failed(let reason), .failed(let failure)):
            #expect(failure.reason == reason, "\(row.name): \(failure.detail)")
        case (.failsOnlyAtCD, .failed(let failure)):
            let cdReasons: Set<AttestationFailureReason> = [.cdSignatureInvalid, .cdUnknownSigningKey, .cdVidPidNotListed]
            #expect(cdReasons.contains(failure.reason), "\(row.name): \(failure.reason) \(failure.detail)")
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

    @Test("CD vectors run without crashing (their CD is Task 4's)")
    func cdVectorsRun() async throws {
        let store = try Self.trustStore()
        var outcomes: [String: [String]] = [:]
        for (name, vector) in try AttestationFixtures.negativeCases where name.hasPrefix("struct_cd_") {
            let result = await Self.verify(vector: vector, store: store)
            let key: String
            switch result {
            case .verified: key = "verified"
            case .failed(let failure): key = failure.reason.rawValue
            }
            outcomes[key, default: []].append(name)
        }
        #expect(outcomes.values.map(\.count).reduce(0, +) > 0)
        for (key, names) in outcomes.sorted(by: { $0.key < $1.key }) {
            print("CD-VECTOR-OUTCOME \(key) \(names.count): \(key == "verified" ? "" : names.joined(separator: " "))")
        }
    }

    // MARK: - Basic Information

    @Test("a matching Basic Information VID/PID verifies")
    func basicInformationMatching() async throws {
        let elements = Self.elements(cd: try AttestationFixtures.testCD, nonce: Self.nonce)
        let result = await DeviceAttestationVerifier(trustStore: try Self.trustStore()).verify(
            dac: try AttestationFixtures.devDAC, pai: try AttestationFixtures.devPAI,
            attestationElements: elements, attestationSignature: try Self.sign(elements, with: Self.devKey()),
            attestationChallenge: Self.challenge, sentNonce: Self.nonce,
            basicInformation: (vendorID: 0xFFF1, productID: 0x8000), now: Self.now
        )
        guard case .verified = result else {
            Issue.record("expected verified, got \(result)")
            return
        }
    }

    /// connectedhomeip compares Basic Information only with the CD, never with the DAC: a CD
    /// with dac_origin fields names a DAC vendor other than the product's
    /// (`struct_cd_origin_pid_vid_correct`: DAC VID 0xFFF2, Basic Information and CD VID 0xFFF1,
    /// an upstream success case). So a Basic Information VID/PID different from the DAC's does
    /// not fail the chain stage.
    @Test("a Basic Information VID/PID other than the DAC's is not a chain failure (dac_origin, struct_cd_origin_pid_vid_correct)")
    func basicInformationDifferentFromDAC() async throws {
        let elements = Self.elements(cd: try AttestationFixtures.testCD, nonce: Self.nonce)
        let result = await DeviceAttestationVerifier(trustStore: try Self.trustStore()).verify(
            dac: try AttestationFixtures.devDAC, pai: try AttestationFixtures.devPAI,
            attestationElements: elements, attestationSignature: try Self.sign(elements, with: Self.devKey()),
            attestationChallenge: Self.challenge, sentNonce: Self.nonce,
            basicInformation: (vendorID: 0xFFF2, productID: 0x8001), now: Self.now
        )
        let chainReasons: Set<AttestationFailureReason> = [.untrustedRoot, .chainInvalid, .certificateExpired, .vidPidMismatch, .malformed]
        if case .failed(let failure) = result {
            #expect(!chainReasons.contains(failure.reason), "\(failure.reason): \(failure.detail)")
        }
    }

    // MARK: - Synthetic chains (signatures and the validity model)

    /// A Matter-profile PAA → PAI → DAC chain built here, with chosen validity and signers.
    struct SyntheticChain {
        let paa: Data
        let pai: Data
        let dac: Data
        let dacKey: P256.Signing.PrivateKey

        static let vidOID: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 37244, 2, 1]
        static let pidOID: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 37244, 2, 2]

        static func name(_ commonName: String, vid: String, pid: String? = nil) -> DistinguishedName {
            var rdns = [
                RelativeDistinguishedName(.init(type: .RDNAttributeType.commonName, utf8String: commonName)),
                RelativeDistinguishedName(.init(type: vidOID, utf8String: vid)),
            ]
            if let pid { rdns.append(RelativeDistinguishedName(.init(type: pidOID, utf8String: pid))) }
            return DistinguishedName(rdns)
        }

        static func der(_ certificate: Certificate) throws -> Data {
            var serializer = DER.Serializer()
            try serializer.serialize(certificate)
            return Data(serializer.serializedBytes)
        }

        /// - Parameters:
        ///   - paiSigner: signs the PAI instead of the PAA key (the PAI still names the PAA).
        ///   - paiAKI: the PAI's AuthorityKeyIdentifier; defaults to the PAA's SKI.
        init(
            paaValidity: ClosedRange<Date>,
            paiValidity: ClosedRange<Date>,
            dacValidity: ClosedRange<Date>,
            paiSigner: P256.Signing.PrivateKey? = nil,
            paiAKI: [UInt8]? = nil
        ) throws {
            let paaKey = P256.Signing.PrivateKey()
            let paiKey = P256.Signing.PrivateKey()
            let dacKey = P256.Signing.PrivateKey()
            let paaSKI = SubjectKeyIdentifier(hash: Certificate.PublicKey(paaKey.publicKey))
            let paiSKI = SubjectKeyIdentifier(hash: Certificate.PublicKey(paiKey.publicKey))
            let paaName = Self.name("Synthetic PAA", vid: "FFF1")
            let paiName = Self.name("Synthetic PAI", vid: "FFF1")

            let paa = try Certificate(
                version: .v3, serialNumber: .init(), publicKey: .init(paaKey.publicKey),
                notValidBefore: paaValidity.lowerBound, notValidAfter: paaValidity.upperBound,
                issuer: paaName, subject: paaName, signatureAlgorithm: .ecdsaWithSHA256,
                extensions: try Certificate.Extensions {
                    Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 1))
                    Critical(X509.KeyUsage(keyCertSign: true, cRLSign: true))
                    paaSKI
                },
                issuerPrivateKey: .init(paaKey)
            )
            let pai = try Certificate(
                version: .v3, serialNumber: .init(), publicKey: .init(paiKey.publicKey),
                notValidBefore: paiValidity.lowerBound, notValidAfter: paiValidity.upperBound,
                issuer: paaName, subject: paiName, signatureAlgorithm: .ecdsaWithSHA256,
                extensions: try Certificate.Extensions {
                    Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0))
                    Critical(X509.KeyUsage(keyCertSign: true, cRLSign: true))
                    paiSKI
                    AuthorityKeyIdentifier(keyIdentifier: ArraySlice(paiAKI ?? Array(paaSKI.keyIdentifier)))
                },
                issuerPrivateKey: .init(paiSigner ?? paaKey)
            )
            let dac = try Certificate(
                version: .v3, serialNumber: .init(), publicKey: .init(dacKey.publicKey),
                notValidBefore: dacValidity.lowerBound, notValidAfter: dacValidity.upperBound,
                issuer: paiName, subject: Self.name("Synthetic DAC", vid: "FFF1", pid: "8000"),
                signatureAlgorithm: .ecdsaWithSHA256,
                extensions: try Certificate.Extensions {
                    Critical(BasicConstraints.notCertificateAuthority)
                    Critical(X509.KeyUsage(digitalSignature: true))
                    SubjectKeyIdentifier(hash: Certificate.PublicKey(dacKey.publicKey))
                    AuthorityKeyIdentifier(keyIdentifier: paiSKI.keyIdentifier)
                },
                issuerPrivateKey: .init(paiKey)
            )
            self.paa = try Self.der(paa)
            self.pai = try Self.der(pai)
            self.dac = try Self.der(dac)
            self.dacKey = dacKey
        }

        func verify(now: Date) async throws -> AttestationResult {
            let store = try AttestationTrustStore(
                paas: [paa], cdSigningKeys: [], provenance: TrustStoreProvenance(source: "explicit"))
            let elements = DeviceAttestationVerifierTests.elements(cd: Data(), nonce: DeviceAttestationVerifierTests.nonce)
            return await DeviceAttestationVerifier(trustStore: store).verify(
                dac: dac, pai: pai,
                attestationElements: elements,
                attestationSignature: try DeviceAttestationVerifierTests.sign(elements, with: dacKey),
                attestationChallenge: DeviceAttestationVerifierTests.challenge,
                sentNonce: DeviceAttestationVerifierTests.nonce, now: now
            )
        }
    }

    private static func date(_ year: Int) -> Date {
        var components = DateComponents()
        components.year = year
        components.month = 1
        components.day = 1
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        return calendar.date(from: components)!
    }

    /// `now` is fixed so the outcome never depends on the wall clock.
    private static let syntheticNow = date(2030)

    @Test("a synthetic Matter-profile chain verifies")
    func syntheticChainVerifies() async throws {
        let chain = try SyntheticChain(
            paaValidity: Self.date(2020)...Self.date(2040),
            paiValidity: Self.date(2021)...Self.date(2039),
            dacValidity: Self.date(2022)...Self.date(2038)
        )
        let result = try await chain.verify(now: Self.syntheticNow)
        guard case .verified = result else {
            Issue.record("expected verified, got \(result)")
            return
        }
    }

    @Test("a PAI whose signature does not verify under the PAA (same AKI) gives chainInvalid")
    func paiSignatureInvalid() async throws {
        let chain = try SyntheticChain(
            paaValidity: Self.date(2020)...Self.date(2040),
            paiValidity: Self.date(2021)...Self.date(2039),
            dacValidity: Self.date(2022)...Self.date(2038),
            paiSigner: P256.Signing.PrivateKey()
        )
        let result = try await chain.verify(now: Self.syntheticNow)
        #expect(Self.failure(result)?.reason == .chainInvalid, "\(result)")
    }

    @Test("a PAI signed by an unknown key with another AKI gives untrustedRoot")
    func paiFromUnknownAuthority() async throws {
        let chain = try SyntheticChain(
            paaValidity: Self.date(2020)...Self.date(2040),
            paiValidity: Self.date(2021)...Self.date(2039),
            dacValidity: Self.date(2022)...Self.date(2038),
            paiSigner: P256.Signing.PrivateKey(),
            paiAKI: Array(repeating: 0x42, count: 20)
        )
        let result = try await chain.verify(now: Self.syntheticNow)
        #expect(Self.failure(result)?.reason == .untrustedRoot, "\(result)")
    }

    @Test("a PAI and PAA expired now but valid at the DAC's notBefore verify (upstream's reference time)")
    func issuersValidAtDACIssuance() async throws {
        let chain = try SyntheticChain(
            paaValidity: Self.date(2020)...Self.date(2029),
            paiValidity: Self.date(2021)...Self.date(2028),
            dacValidity: Self.date(2022)...Self.date(2038)
        )
        let result = try await chain.verify(now: Self.syntheticNow)
        guard case .verified = result else {
            Issue.record("expected verified, got \(result)")
            return
        }
    }

    @Test("a PAI not yet valid at the DAC's notBefore gives certificateExpired")
    func paiNotValidAtDACIssuance() async throws {
        let chain = try SyntheticChain(
            paaValidity: Self.date(2020)...Self.date(2040),
            paiValidity: Self.date(2023)...Self.date(2039),
            dacValidity: Self.date(2022)...Self.date(2038)
        )
        let result = try await chain.verify(now: Self.syntheticNow)
        #expect(Self.failure(result)?.reason == .certificateExpired, "\(result)")
    }

    @Test("a PAA expired by the DAC's notBefore gives certificateExpired")
    func paaExpiredAtDACIssuance() async throws {
        let chain = try SyntheticChain(
            paaValidity: Self.date(2020)...Self.date(2021),
            paiValidity: Self.date(2020)...Self.date(2039),
            dacValidity: Self.date(2022)...Self.date(2038)
        )
        let result = try await chain.verify(now: Self.syntheticNow)
        #expect(Self.failure(result)?.reason == .certificateExpired, "\(result)")
    }

    @Test("a DAC expired now gives certificateExpired even though it was valid at issuance")
    func dacExpiredNow() async throws {
        let chain = try SyntheticChain(
            paaValidity: Self.date(2020)...Self.date(2040),
            paiValidity: Self.date(2021)...Self.date(2039),
            dacValidity: Self.date(2022)...Self.date(2029)
        )
        let result = try await chain.verify(now: Self.syntheticNow)
        #expect(Self.failure(result)?.reason == .certificateExpired, "\(result)")
    }

    // MARK: - NOCSR signature

    @Test("verifyNOCSRSignature accepts the DAC's signature and rejects another key")
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
        #expect(DeviceAttestationVerifier.verifyNOCSRSignature(
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
