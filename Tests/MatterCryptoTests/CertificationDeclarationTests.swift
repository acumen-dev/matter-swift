// CertificationDeclarationTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
import X509
import MatterTypes
@testable import MatterCrypto
import MatterTestSupport

// MARK: - CertificationDeclarationTests

@Suite("CertificationDeclaration Tests", .timeLimit(.minutes(5)))
struct CertificationDeclarationTests {

    private static func testKey() throws -> CDSigningKey {
        try CDSigningKey(certificateDER: AttestationFixtures.testCDSigningCert)
    }

    private static func productionKeys() throws -> [CDSigningKey] {
        try AttestationFixtures.productionCDSigningCerts.map { try CDSigningKey(certificateDER: $0) }
    }

    private static func vectorCD(_ name: String) throws -> Data {
        let vector = try #require(try AttestationFixtures.negativeCases.first { $0.name == name }?.vector)
        return vector.certificationDeclaration
    }

    // MARK: - Parsing

    /// Values read with `chip-cert print-cd` (connectedhomeip v1.4.0.0).
    @Test("the test CD parses to its known fields")
    func testCDParses() throws {
        let cd = try CertificationDeclaration(cmsDER: AttestationFixtures.testCD)
        #expect(cd.formatVersion == 1)
        #expect(cd.vendorID == 0xFFF1)
        #expect(cd.productIDs == [0x8000])
        #expect(cd.deviceTypeID == 0x1234)
        #expect(cd.certificateID == "ZIG20141ZB330001-24")
        #expect(cd.securityLevel == 0)
        #expect(cd.securityInformation == 0)
        #expect(cd.versionNumber == 0x9876)
        #expect(cd.certificationType == 0)
        #expect(cd.dacOriginVendorID == nil)
        #expect(cd.dacOriginProductID == nil)
        #expect(cd.authorizedPAAs == nil)
        #expect(cd.signerKeyIdentifier == CertificationDeclarationSigner.testCDKeyIdentifier)
        #expect(cd.signerKeyIdentifier == (try Self.testKey()).keyIdentifier)
    }

    @Test("the example apps' CD parses: VID 0xFFF1, PIDs 0x8000 to 0x8063, signed by CSA key 001")
    func exampleCDParses() throws {
        let der = try AttestationFixtures.exampleCD
        let cd = try CertificationDeclaration(cmsDER: der)
        #expect(cd.vendorID == 0xFFF1)
        #expect(cd.productIDs == Array(0x8000...0x8063))
        #expect(cd.formatVersion == 1)
        let key001 = try Self.productionKeys()[0]
        #expect(cd.signerKeyIdentifier == key001.keyIdentifier)
        #expect(cd.verifySignature(cmsDER: der, keys: try Self.productionKeys()) == .valid)
    }

    @Test("DAC origin fields parse when both are present")
    func dacOriginParses() throws {
        let cd = try CertificationDeclaration(cmsDER: Self.vectorCD("struct_cd_dac_origin_vid_pid_present_match"))
        #expect(cd.dacOriginVendorID == 0xFFF1)
        #expect(cd.dacOriginProductID == 0x8000)
    }

    @Test("authorized_paa_list: absent is nil, an empty array is present and empty")
    func authorizedPAAListPresence() throws {
        #expect(try CertificationDeclaration(cmsDER: Self.vectorCD("struct_cd_authorized_paa_list_missing")).authorizedPAAs == nil)
        #expect(try CertificationDeclaration(cmsDER: Self.vectorCD("struct_cd_authorized_paa_list_count0")).authorizedPAAs == [])
        let ten = try CertificationDeclaration(cmsDER: Self.vectorCD("struct_cd_authorized_paa_list_count10_valid"))
        let testPAA = try Certificate(derEncoded: Array(AttestationFixtures.testPAA))
        let testPAASKI = try #require(try testPAA.extensions.subjectKeyIdentifier?.keyIdentifier)
        #expect(ten.authorizedPAAs?.count == 10)
        #expect(ten.authorizedPAAs?.first == Data(testPAASKI))
    }

    @Test("an empty product_id_array parses (upstream rejects it only at the PID match)")
    func emptyProductArrayParses() throws {
        #expect(try CertificationDeclaration(cmsDER: Self.vectorCD("struct_cd_pid_array_count0")).productIDs == [])
    }

    @Test("the signer helper reproduces the test CD's payload byte for byte")
    func signerMatchesUpstreamEncoding() throws {
        let content = CertificationDeclarationSigner.content(vendorID: 0xFFF1, productIDs: [0x8000])
        #expect(try AttestationFixtures.testCD.range(of: content) != nil)
        let signed = try CertificationDeclarationSigner.signWithTestKey(content: content)
        let cd = try CertificationDeclaration(cmsDER: signed)
        #expect(cd == (try CertificationDeclaration(cmsDER: AttestationFixtures.testCD)))
        #expect(cd.verifySignature(cmsDER: signed, keys: [try Self.testKey()]) == .valid)
    }

    @Test("bytes that are not a Matter CMS envelope are malformed", arguments: [
        ("empty", Data()),
        ("garbage", Data([0x30, 0x03, 0x01, 0x02, 0x03])),
        ("bare TLV", CertificationDeclarationSigner.content(vendorID: 0xFFF1, productIDs: [0x8000])),
    ])
    func garbageIsMalformed(_ name: String, _ bytes: Data) {
        #expect(throws: CertificationDeclarationError.self, "\(name)") {
            try CertificationDeclaration(cmsDER: bytes)
        }
    }

    @Test("trailing bytes after the CMS envelope are malformed")
    func trailingBytesMalformed() throws {
        let der = try AttestationFixtures.testCD + Data([0x00])
        #expect(throws: CertificationDeclarationError.self) { try CertificationDeclaration(cmsDER: der) }
    }

    @Test("a payload with data after the structure is malformed")
    func trailingTLVMalformed() throws {
        let content = CertificationDeclarationSigner.content(vendorID: 0xFFF1, productIDs: [0x8000]) + Data([0x04, 0x01])
        let der = try CertificationDeclarationSigner.signWithTestKey(content: content)
        #expect(throws: CertificationDeclarationError.self) { try CertificationDeclaration(cmsDER: der) }
    }

    @Test("a payload above upstream's 790-byte bound is malformed")
    func oversizedPayloadMalformed() throws {
        let content = CertificationDeclarationSigner.content(vendorID: 0xFFF1, productIDs: Array(repeating: 0x8000, count: 300))
        #expect(content.count > 790)
        let der = try CertificationDeclarationSigner.signWithTestKey(content: content)
        #expect(throws: CertificationDeclarationError.self) { try CertificationDeclaration(cmsDER: der) }
    }

    // MARK: - Signature

    @Test("the test CD verifies with the test CD signing key")
    func testCDVerifies() throws {
        let der = try AttestationFixtures.testCD
        let cd = try CertificationDeclaration(cmsDER: der)
        #expect(cd.verifySignature(cmsDER: der, keys: [try Self.testKey()]) == .valid)
        #expect(cd.verifySignature(cmsDER: der, keys: try Self.productionKeys() + [try Self.testKey()]) == .valid)
    }

    @Test("with no matching key the result is unknownSigningKey")
    func unknownKey() throws {
        let der = try AttestationFixtures.testCD
        let cd = try CertificationDeclaration(cmsDER: der)
        #expect(cd.verifySignature(cmsDER: der, keys: []) == .unknownSigningKey)
        #expect(cd.verifySignature(cmsDER: der, keys: try Self.productionKeys()) == .unknownSigningKey)
    }

    @Test("a flipped signature byte gives invalidSignature")
    func flippedSignatureByte() throws {
        var der = try AttestationFixtures.testCD
        der[der.index(before: der.endIndex)] ^= 0x01  // last byte of the ECDSA s value
        let cd = try CertificationDeclaration(cmsDER: der)
        #expect(cd.verifySignature(cmsDER: der, keys: [try Self.testKey()]) == .invalidSignature)
    }

    @Test("a changed payload byte gives invalidSignature")
    func changedPayload() throws {
        var der = try AttestationFixtures.testCD
        let range = try #require(der.range(of: Data("ZIG2".utf8)))
        der[range.lowerBound] = UInt8(ascii: "X")
        let cd = try CertificationDeclaration(cmsDER: der)
        #expect(cd.certificateID == "XIG20141ZB330001-24")
        #expect(cd.verifySignature(cmsDER: der, keys: [try Self.testKey()]) == .invalidSignature)
    }

    @Test("a key with the signer's identifier but another public key gives invalidSignature")
    func wrongKeySameIdentifier() throws {
        let der = try AttestationFixtures.testCD
        let cd = try CertificationDeclaration(cmsDER: der)
        let impostor = try CertificationDeclarationSigner.sign(
            content: CertificationDeclarationSigner.content(vendorID: 0xFFF1, productIDs: [0x8000]),
            key: P256.Signing.PrivateKey(), keyIdentifier: CertificationDeclarationSigner.testCDKeyIdentifier)
        #expect(try CertificationDeclaration(cmsDER: impostor).verifySignature(cmsDER: impostor, keys: [try Self.testKey()]) == .invalidSignature)
        #expect(cd.verifySignature(cmsDER: der, keys: [try Self.testKey()]) == .valid)
    }
}

// MARK: - CD vector table

/// What `verify` must return for a `struct_cd_*` commissioner DUT vector.
enum ExpectedCDOutcome: Sendable, Equatable, CustomStringConvertible {
    /// An upstream success case.
    case verified
    case failed(AttestationFailureReason)
    /// An upstream failure case that connectedhomeip v1.4.0.0's `DefaultDACVerifier` also
    /// accepts: the field is checked against the DCL (out of scope), or, per the comment at
    /// DefaultDeviceAttestationVerifier.cpp:502-503, meant to be ignored by commissioners.
    case verifiedNeedsDCL

    var description: String {
        switch self {
        case .verified: "verified"
        case .failed(let reason): reason.rawValue
        case .verifiedNeedsDCL: "verified (upstream too; DCL check out of scope)"
        }
    }
}

struct CDVector: Sendable, CustomTestStringConvertible {
    let name: String
    let expected: ExpectedCDOutcome
    /// The connectedhomeip v1.4.0.0 result and line that decides the vector.
    let upstream: String

    var testDescription: String { "\(name) → \(expected)" }
}

/// Every `struct_cd_*` vector, with the reason `verify` gives and upstream's. Line numbers are in
/// src/credentials/attestation_verifier/DefaultDeviceAttestationVerifier.cpp (v1.4.0.0). CMS
/// shape failures are `kCertificationDeclarationNoKeyId` (:470) or `…InvalidSignature` (:483)
/// upstream and `.malformed` here; TLV failures are `…InvalidFormat` (:495) upstream.
let cdVectorTable: [CDVector] = [
    .init(name: "struct_cd_authorized_paa_list_count0", expected: .failed(.cdVidPidNotListed), upstream: "kCertificationDeclarationInvalidPAA :567 (no matching reason)"),
    .init(name: "struct_cd_authorized_paa_list_count10_invalid", expected: .failed(.cdVidPidNotListed), upstream: "kCertificationDeclarationInvalidPAA :567 (no matching reason)"),
    .init(name: "struct_cd_authorized_paa_list_count10_valid", expected: .verified, upstream: "success"),
    .init(name: "struct_cd_authorized_paa_list_count1_valid", expected: .verified, upstream: "success"),
    .init(name: "struct_cd_authorized_paa_list_count2_valid", expected: .verified, upstream: "success"),
    .init(name: "struct_cd_authorized_paa_list_count3_invalid", expected: .failed(.cdVidPidNotListed), upstream: "kCertificationDeclarationInvalidPAA :567 (no matching reason)"),
    .init(name: "struct_cd_authorized_paa_list_missing", expected: .verified, upstream: "success"),
    .init(name: "struct_cd_cert_id_len_wrong", expected: .failed(.malformed), upstream: "kCertificationDeclarationInvalidFormat :495"),
    .init(name: "struct_cd_cert_id_mismatch", expected: .verifiedNeedsDCL, upstream: "success (only the length is checked locally)"),
    .init(name: "struct_cd_cert_id_missing", expected: .failed(.malformed), upstream: "kCertificationDeclarationInvalidFormat :495"),
    .init(name: "struct_cd_cert_type_missing", expected: .failed(.malformed), upstream: "kCertificationDeclarationInvalidFormat :495"),
    .init(name: "struct_cd_cert_type_wrong", expected: .failed(.malformed), upstream: "kAttestationElementsMalformed :505"),
    .init(name: "struct_cd_cms_digest_algo_sha1", expected: .failed(.malformed), upstream: "kCertificationDeclarationInvalidSignature :483 (CMS_Verify rejects the shape)"),
    .init(name: "struct_cd_cms_digest_algo_sha256", expected: .verified, upstream: "success"),
    .init(name: "struct_cd_cms_econtent_type_msac", expected: .failed(.malformed), upstream: "kCertificationDeclarationInvalidSignature :483 (CMS_Verify rejects the shape)"),
    .init(name: "struct_cd_cms_econtent_type_pkcs7_data", expected: .verified, upstream: "success"),
    .init(name: "struct_cd_cms_sig_algo_ecdsa_with_sha1", expected: .failed(.malformed), upstream: "kCertificationDeclarationNoKeyId :470"),
    .init(name: "struct_cd_cms_sig_algo_ecdsa_with_sha256", expected: .verified, upstream: "success"),
    .init(name: "struct_cd_cms_signature", expected: .failed(.cdSignatureInvalid), upstream: "kCertificationDeclarationInvalidSignature :483"),
    .init(name: "struct_cd_cms_v2", expected: .failed(.malformed), upstream: "kCertificationDeclarationInvalidSignature :483 (CMS_Verify rejects the shape)"),
    .init(name: "struct_cd_cms_v3", expected: .verified, upstream: "success"),
    .init(name: "struct_cd_dac_origin_vid_missing_pid_present", expected: .failed(.malformed), upstream: "kCertificationDeclarationInvalidFormat :495"),
    .init(name: "struct_cd_dac_origin_vid_pid_missing", expected: .verified, upstream: "success"),
    .init(name: "struct_cd_dac_origin_vid_pid_present_match", expected: .verified, upstream: "success"),
    .init(name: "struct_cd_dac_origin_vid_pid_present_pid_mismatch", expected: .failed(.cdVidPidNotListed), upstream: "kCertificationDeclarationInvalidVendorId :524 (the vector's origin VID 0x8008 also differs)"),
    .init(name: "struct_cd_dac_origin_vid_pid_present_vid_mismatch", expected: .failed(.cdVidPidNotListed), upstream: "kCertificationDeclarationInvalidVendorId :524"),
    .init(name: "struct_cd_dac_origin_vid_present_pid_missing", expected: .failed(.malformed), upstream: "kCertificationDeclarationInvalidFormat :495"),
    .init(name: "struct_cd_device_type_id_mismatch", expected: .verifiedNeedsDCL, upstream: "success (device_type_id is checked against the DCL)"),
    .init(name: "struct_cd_device_type_id_missing", expected: .failed(.malformed), upstream: "kCertificationDeclarationInvalidFormat :495"),
    .init(name: "struct_cd_format_version_1", expected: .verified, upstream: "success"),
    .init(name: "struct_cd_format_version_2", expected: .failed(.malformed), upstream: "kAttestationElementsMalformed :505"),
    .init(name: "struct_cd_format_version_missing", expected: .failed(.malformed), upstream: "kCertificationDeclarationInvalidFormat :495"),
    .init(name: "struct_cd_origin_pid_vid_correct", expected: .verified, upstream: "success (needs Chip-Test-PAA-NoVID)"),
    .init(name: "struct_cd_pid_array_count0", expected: .failed(.cdVidPidNotListed), upstream: "kCertificationDeclarationInvalidProductId :517"),
    .init(name: "struct_cd_pid_array_count01_mismatch", expected: .failed(.cdVidPidNotListed), upstream: "kCertificationDeclarationInvalidProductId :517"),
    .init(name: "struct_cd_pid_array_count01_valid", expected: .verified, upstream: "success"),
    .init(name: "struct_cd_pid_array_count100_mismatch", expected: .failed(.cdVidPidNotListed), upstream: "kCertificationDeclarationInvalidProductId :517"),
    .init(name: "struct_cd_pid_array_count100_valid", expected: .verified, upstream: "success"),
    .init(name: "struct_cd_pid_array_count10_mismatch", expected: .failed(.cdVidPidNotListed), upstream: "kCertificationDeclarationInvalidProductId :517"),
    .init(name: "struct_cd_pid_array_count10_valid", expected: .verified, upstream: "success"),
    .init(name: "struct_cd_pid_array_missing", expected: .failed(.malformed), upstream: "kCertificationDeclarationInvalidFormat :495"),
    .init(name: "struct_cd_security_info_missing", expected: .failed(.malformed), upstream: "kCertificationDeclarationInvalidFormat :495"),
    .init(name: "struct_cd_security_info_wrong", expected: .verifiedNeedsDCL, upstream: "success (ignored, :502-503)"),
    .init(name: "struct_cd_security_level_missing", expected: .failed(.malformed), upstream: "kCertificationDeclarationInvalidFormat :495"),
    .init(name: "struct_cd_security_level_wrong", expected: .verifiedNeedsDCL, upstream: "success (ignored, :502-503)"),
    .init(name: "struct_cd_signer_info_digest_algo_sha1", expected: .failed(.malformed), upstream: "kCertificationDeclarationNoKeyId :470"),
    .init(name: "struct_cd_signer_info_skid_invalid", expected: .failed(.cdUnknownSigningKey), upstream: "kCertificationDeclarationNoCertificateFound :474"),
    .init(name: "struct_cd_signer_info_skid_valid", expected: .verified, upstream: "success"),
    .init(name: "struct_cd_signer_info_v2", expected: .failed(.malformed), upstream: "kCertificationDeclarationNoKeyId :470"),
    .init(name: "struct_cd_version_number_match", expected: .verified, upstream: "success"),
    .init(name: "struct_cd_version_number_missing", expected: .failed(.malformed), upstream: "kCertificationDeclarationInvalidFormat :495"),
    .init(name: "struct_cd_version_number_wrong", expected: .verifiedNeedsDCL, upstream: "success (version_number is checked against the DCL)"),
    .init(name: "struct_cd_vid_mismatch", expected: .failed(.cdVidPidNotListed), upstream: "kCertificationDeclarationInvalidVendorId :512"),
    .init(name: "struct_cd_vid_missing", expected: .failed(.malformed), upstream: "kCertificationDeclarationInvalidFormat :495"),
]

// MARK: - CertificationDeclarationVerifierStageTests

/// The verifier's Certification Declaration stage: signature, then upstream's
/// `ValidateCertificateDeclarationPayload` rules.
@Suite("CertificationDeclaration verifier stage Tests", .timeLimit(.minutes(5)))
struct CertificationDeclarationVerifierStageTests {

    private static let challenge = Data((0..<16).map { UInt8($0) })
    private static let nonce = Data((0..<32).map { UInt8(0xA0 &+ $0) })
    /// Fixed; see DeviceAttestationVerifierTests.now.
    private static let now = SyntheticAttestationChain.date(2024, month: 7, day: 1)

    private static func store(cdKeys: [CDSigningKey]? = nil) throws -> AttestationTrustStore {
        try AttestationTrustStore(
            paas: [AttestationFixtures.testPAA, AttestationFixtures.testPAANoVID],
            cdSigningKeys: cdKeys ?? [CDSigningKey(certificateDER: AttestationFixtures.testCDSigningCert)],
            provenance: TrustStoreProvenance(source: "explicit")
        )
    }

    private static func elements(cd: Data) -> Data {
        TLVEncoder.encode(.structure([
            .init(tag: .contextSpecific(1), value: .octetString(cd)),
            .init(tag: .contextSpecific(2), value: .octetString(nonce)),
            .init(tag: .contextSpecific(3), value: .unsignedInt(0)),
        ]))
    }

    /// The dev chain (DAC FFF1/8000, PAI FFF1 without a PID) presenting `cd`.
    private static func verifyDev(
        cd: Data, basicInformation: (vendorID: UInt16, productID: UInt16) = (0xFFF1, 0x8000),
        store: AttestationTrustStore? = nil
    ) async throws -> AttestationResult {
        let elements = elements(cd: cd)
        let key = try P256.Signing.PrivateKey(derRepresentation: AttestationFixtures.devDACPrivateKey)
        return await DeviceAttestationVerifier(trustStore: try store ?? Self.store()).verify(
            dac: try AttestationFixtures.devDAC, pai: try AttestationFixtures.devPAI,
            attestationElements: elements,
            attestationSignature: try key.signature(for: elements + challenge).rawRepresentation,
            attestationChallenge: challenge, sentNonce: nonce,
            basicInformation: basicInformation, now: now
        )
    }

    private static func signed(
        vendorID: UInt16, productIDs: [UInt16], certificationType: UInt8 = 0, formatVersion: UInt8 = 1,
        dacOrigin: (vendorID: UInt16, productID: UInt16)? = nil, authorizedPAAs: [Data]? = nil
    ) throws -> Data {
        try CertificationDeclarationSigner.signWithTestKey(content: CertificationDeclarationSigner.content(
            vendorID: vendorID, productIDs: productIDs, certificationType: certificationType,
            formatVersion: formatVersion, dacOrigin: dacOrigin, authorizedPAAs: authorizedPAAs))
    }

    private static func reason(_ result: AttestationResult) -> AttestationFailureReason? {
        if case .failed(let failure) = result { return failure.reason }
        return nil
    }

    private static func isVerified(_ result: AttestationResult) -> Bool {
        if case .verified = result { return true }
        return false
    }

    private static var testPAASKI: Data {
        get throws {
            let paa = try Certificate(derEncoded: Array(AttestationFixtures.testPAA))
            return Data(try #require(try paa.extensions.subjectKeyIdentifier?.keyIdentifier))
        }
    }

    // MARK: - Signature

    @Test("the dev chain with the test CD verifies when the store holds the test CD key")
    func devChainWithTestCD() async throws {
        #expect(Self.isVerified(try await Self.verifyDev(cd: AttestationFixtures.testCD)))
    }

    @Test("the dev chain with the example apps' CD verifies with CSA CD signing key 001")
    func devChainWithExampleCD() async throws {
        let keys = try AttestationFixtures.productionCDSigningCerts.map { try CDSigningKey(certificateDER: $0) }
        let result = try await Self.verifyDev(cd: AttestationFixtures.exampleCD, store: Self.store(cdKeys: keys))
        #expect(Self.isVerified(result), "\(result)")
    }

    @Test("without the test CD key the result is cdUnknownSigningKey")
    func noCDKey() async throws {
        let result = try await Self.verifyDev(cd: AttestationFixtures.testCD, store: Self.store(cdKeys: []))
        #expect(Self.reason(result) == .cdUnknownSigningKey)
    }

    @Test("a CD signed by another key under the test key's identifier gives cdSignatureInvalid")
    func forgedCD() async throws {
        let forged = try CertificationDeclarationSigner.sign(
            content: CertificationDeclarationSigner.content(vendorID: 0xFFF1, productIDs: [0x8000]),
            key: P256.Signing.PrivateKey(), keyIdentifier: CertificationDeclarationSigner.testCDKeyIdentifier)
        #expect(Self.reason(try await Self.verifyDev(cd: forged)) == .cdSignatureInvalid)
    }

    @Test("a CD that is not a Matter CMS envelope gives malformed")
    func garbageCD() async throws {
        #expect(Self.reason(try await Self.verifyDev(cd: Data([0x30, 0x00]))) == .malformed)
    }

    // MARK: - Payload rules

    @Test("a CD for another PID gives cdVidPidNotListed (:517)")
    func cdForAnotherPID() async throws {
        let other = try #require(try AttestationFixtures.negativeCases
            .first { $0.name == "struct_cd_pid_array_count01_mismatch" }?.vector.certificationDeclaration)
        #expect(try CertificationDeclaration(cmsDER: other).productIDs == [0x8001])
        #expect(Self.reason(try await Self.verifyDev(cd: other)) == .cdVidPidNotListed)
    }

    @Test("format_version other than 1 gives malformed (:505)")
    func formatVersion() async throws {
        let cd = try Self.signed(vendorID: 0xFFF1, productIDs: [0x8000], formatVersion: 2)
        #expect(Self.reason(try await Self.verifyDev(cd: cd)) == .malformed)
    }

    @Test("certification_type 0, 1 and 2 verify; 3 gives malformed (:505)")
    func certificationType() async throws {
        for type: UInt8 in [0, 1, 2] {
            let cd = try Self.signed(vendorID: 0xFFF1, productIDs: [0x8000], certificationType: type)
            #expect(Self.isVerified(try await Self.verifyDev(cd: cd)), "type \(type)")
        }
        let reserved = try Self.signed(vendorID: 0xFFF1, productIDs: [0x8000], certificationType: 3)
        #expect(Self.reason(try await Self.verifyDev(cd: reserved)) == .malformed)
    }

    @Test("Basic Information VID other than the CD vendor_id gives cdVidPidNotListed (:512)")
    func basicInformationVendor() async throws {
        let result = try await Self.verifyDev(cd: AttestationFixtures.testCD, basicInformation: (0xFFF2, 0x8000))
        #expect(Self.reason(result) == .cdVidPidNotListed)
    }

    @Test("Basic Information PID absent from product_id_array gives cdVidPidNotListed (:517)")
    func basicInformationProduct() async throws {
        let result = try await Self.verifyDev(cd: AttestationFixtures.testCD, basicInformation: (0xFFF1, 0x8001))
        #expect(Self.reason(result) == .cdVidPidNotListed)
    }

    @Test("no DAC origin: a DAC VID other than the CD vendor_id gives cdVidPidNotListed (:545)")
    func dacVendorNotCD() async throws {
        // Basic Information and the CD agree (0xFFF2); the dev DAC is 0xFFF1.
        let cd = try Self.signed(vendorID: 0xFFF2, productIDs: [0x8000])
        let result = try await Self.verifyDev(cd: cd, basicInformation: (0xFFF2, 0x8000))
        #expect(Self.reason(result) == .cdVidPidNotListed)
    }

    @Test("no DAC origin: a DAC PID absent from product_id_array gives cdVidPidNotListed (:552)")
    func dacProductNotListed() async throws {
        let cd = try Self.signed(vendorID: 0xFFF1, productIDs: [0x8001])
        let result = try await Self.verifyDev(cd: cd, basicInformation: (0xFFF1, 0x8001))
        #expect(Self.reason(result) == .cdVidPidNotListed)
    }

    @Test("DAC origin naming the DAC verifies a product of another vendor (white label, :520-538)")
    func dacOriginWhiteLabel() async throws {
        let cd = try Self.signed(vendorID: 0xFFF2, productIDs: [0x8001], dacOrigin: (0xFFF1, 0x8000))
        let result = try await Self.verifyDev(cd: cd, basicInformation: (0xFFF2, 0x8001))
        #expect(Self.isVerified(result), "\(result)")
    }

    @Test("DAC origin VID other than the DAC's gives cdVidPidNotListed (:524)")
    func dacOriginVendorMismatch() async throws {
        let cd = try Self.signed(vendorID: 0xFFF1, productIDs: [0x8000], dacOrigin: (0xFFF2, 0x8000))
        #expect(Self.reason(try await Self.verifyDev(cd: cd)) == .cdVidPidNotListed)
    }

    @Test("DAC origin PID other than the DAC's gives cdVidPidNotListed (:532)")
    func dacOriginProductMismatch() async throws {
        let cd = try Self.signed(vendorID: 0xFFF1, productIDs: [0x8000], dacOrigin: (0xFFF1, 0x8001))
        #expect(Self.reason(try await Self.verifyDev(cd: cd)) == .cdVidPidNotListed)
    }

    @Test("with DAC origin present the DAC need not be in product_id_array (:520 skips :552)")
    func dacOriginReplacesProductList() async throws {
        let cd = try Self.signed(vendorID: 0xFFF1, productIDs: [0x8001], dacOrigin: (0xFFF1, 0x8000))
        let result = try await Self.verifyDev(cd: cd, basicInformation: (0xFFF1, 0x8001))
        #expect(Self.isVerified(result), "\(result)")
    }

    @Test("authorized_paa_list: listing the PAA verifies; not listing it, or empty, gives cdVidPidNotListed (:567)")
    func authorizedPAAList() async throws {
        let listed = try Self.signed(vendorID: 0xFFF1, productIDs: [0x8000], authorizedPAAs: [Data(repeating: 0x11, count: 20), Self.testPAASKI])
        #expect(Self.isVerified(try await Self.verifyDev(cd: listed)))
        let unlisted = try Self.signed(vendorID: 0xFFF1, productIDs: [0x8000], authorizedPAAs: [Data(repeating: 0x11, count: 20)])
        let failure = try await Self.verifyDev(cd: unlisted)
        #expect(Self.reason(failure) == .cdVidPidNotListed)
        if case .failed(let detail) = failure { #expect(detail.detail.contains("authorized_paa_list")) }
        let empty = try Self.signed(vendorID: 0xFFF1, productIDs: [0x8000], authorizedPAAs: [])
        #expect(Self.reason(try await Self.verifyDev(cd: empty)) == .cdVidPidNotListed)
    }

    // MARK: - Commissioner DUT vectors

    @Test("struct_cd vectors give the tabled outcome", arguments: cdVectorTable)
    func cdVector(_ row: CDVector) async throws {
        let vector = try #require(try AttestationFixtures.negativeCases.first { $0.name == row.name }?.vector)
        let result = await DeviceAttestationVerifierTests.verify(vector: vector, store: try Self.store())
        switch (row.expected, result) {
        case (.verified, .verified), (.verifiedNeedsDCL, .verified):
            break
        case (.failed(let reason), .failed(let failure)):
            #expect(failure.reason == reason, "\(row.name): \(failure.detail)")
        default:
            Issue.record("\(row.name): expected \(row.expected), got \(result)")
        }
        #expect(vector.isSuccessCase == (row.expected == .verified), "\(row.name): upstream is_success_case")
    }

    @Test("the CD table covers every struct_cd vector")
    func tableCoversEveryCDVector() throws {
        let names = Set(try AttestationFixtures.negativeCases.map(\.name).filter { $0.hasPrefix("struct_cd_") })
        #expect(Set(cdVectorTable.map(\.name)) == names)
        #expect(cdVectorTable.count == names.count)
    }
}
