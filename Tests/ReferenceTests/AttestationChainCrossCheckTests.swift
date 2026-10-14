// AttestationChainCrossCheckTests.swift
// Copyright 2026 Monagle Pty Ltd
//
// Cross-checks DeviceAttestationVerifier's chain verdict against
// `chip-cert validate-att-cert` for every connectedhomeip commissioner DUT vector.

#if canImport(Network)
import Testing
import Foundation
import Crypto
import X509
import MatterCrypto
import MatterTypes
import MatterTestSupport

// MARK: - AttestationChainCrossCheckTests

@Suite("DeviceAttestationVerifier chip-cert cross-check", .timeLimit(.minutes(5)))
struct AttestationChainCrossCheckTests {

    private static let challenge = Data(repeating: 0x5A, count: 16)
    private static let nonce = Data(repeating: 0xA5, count: 32)

    /// Reasons that mean the chain and VID/PID rules passed and a later stage failed.
    private static let postChainReasons: Set<AttestationFailureReason> = [
        .nonceMismatch, .attestationSignatureInvalid,
        .cdSignatureInvalid, .cdUnknownSigningKey, .cdVidPidNotListed, .cdPAANotAuthorized,
    ]

    /// Whether `verify` accepted the DAC → PAI → PAA chain.
    ///
    /// Every case presents the test CD (FFF1/8000, signed by the test CD key, which `store`
    /// holds) instead of its own, so a CD the verifier rejects as malformed cannot be mistaken
    /// for a chain failure; a vector for another VID/PID then fails after the chain stage.
    private static func chainVerdict(dac: Data, pai: Data, key: Data, cd: Data, store: AttestationTrustStore) async -> (Bool, String) {
        let elements = TLVEncoder.encode(.structure([
            .init(tag: .contextSpecific(1), value: .octetString(cd)),
            .init(tag: .contextSpecific(2), value: .octetString(nonce)),
            .init(tag: .contextSpecific(3), value: .unsignedInt(0)),
        ]))
        let signature = (try? P256.Signing.PrivateKey(rawRepresentation: key))
            .flatMap { try? $0.signature(for: elements + challenge).rawRepresentation } ?? Data(count: 64)
        let result = await DeviceAttestationVerifier(trustStore: store).verify(
            dac: dac, pai: pai,
            attestationElements: elements, attestationSignature: signature,
            attestationChallenge: challenge, sentNonce: nonce,
            // The wall clock, deliberately: `chip-cert validate-att-cert` has no time option, so
            // it judges validity at the wall clock too and both sides move together. When the
            // fixtures expire both report invalid and the rows still agree; the pinned valid
            // count in `chipCertAgrees` is what turns that red.
            basicInformation: (vendorID: 0xFFF1, productID: 0x8000), now: Date()
        )
        switch result {
        case .verified:
            return (true, "verified")
        case .failed(let failure):
            return (postChainReasons.contains(failure.reason), failure.reason.rawValue)
        }
    }

    @Test("chip-cert and the verifier agree on every commissioner DUT chain, against the test PAA")
    func chipCertAgrees() async throws {
        guard let runner = ChipCertRunner.findBinary() else {
            print("[SKIP] chip-cert not found — run: make ref-setup-cert")
            return
        }
        let paa = try AttestationFixtures.testPAA
        let cdKey = try CDSigningKey(certificateDER: AttestationFixtures.testCDSigningCert)
        let testCD = try AttestationFixtures.testCD
        let store = try AttestationTrustStore(
            paas: [paa], cdSigningKeys: [cdKey], provenance: TrustStoreProvenance(source: "explicit")
        )

        var cases: [(name: String, dac: Data, pai: Data, key: Data)] = [(
            "dev", try AttestationFixtures.devDAC, try AttestationFixtures.devPAI,
            try P256.Signing.PrivateKey(derRepresentation: AttestationFixtures.devDACPrivateKey).rawRepresentation
        )]
        for (name, vector) in try AttestationFixtures.negativeCases {
            cases.append((name, vector.dacCert, vector.paiCert, vector.dacPrivateKey))
        }

        var agreed = 0
        var chipCertValid = 0
        for item in cases {
            let chipCert = try runner.validateAttestationChain(dac: item.dac, pai: item.pai, paa: paa)
            let (ours, outcome) = await Self.chainVerdict(dac: item.dac, pai: item.pai, key: item.key, cd: testCD, store: store)
            #expect(chipCert.succeeded == ours,
                    "\(item.name): chip-cert \(chipCert.succeeded ? "valid" : "invalid"), verifier \(outcome); \(chipCert.stderr)")
            if chipCert.succeeded == ours { agreed += 1 }
            if chipCert.succeeded { chipCertValid += 1 }
        }
        print("CROSS-CHECK agreed \(agreed)/\(cases.count); chip-cert valid \(chipCertValid), invalid \(cases.count - chipCertValid)")
        // Agreement alone passes vacuously once the fixtures expire (every row invalid on both
        // sides); 86 is the count while they are in date.
        #expect(chipCertValid == 86, "chip-cert found \(chipCertValid) valid chains, not 86: have the fixtures expired?")
    }

    @Test("chip-cert and the verifier agree on synthetic chains isolating signatures and key-identifier links")
    func chipCertAgreesOnSyntheticChains() async throws {
        guard let runner = ChipCertRunner.findBinary() else {
            print("[SKIP] chip-cert not found — run: make ref-setup-cert")
            return
        }
        let date = SyntheticAttestationChain.date
        func chain(
            paiSigner: P256.Signing.PrivateKey? = nil, paiAKI: [UInt8]? = nil,
            dacSigner: P256.Signing.PrivateKey? = nil, dacAKI: [UInt8]? = nil, san: Bool = false,
            paiExtra: [Certificate.Extension] = [], dacExtra: [Certificate.Extension] = []
        ) throws -> SyntheticAttestationChain {
            try SyntheticAttestationChain(
                paaValidity: date(2020, 1, 1)...date(2040, 1, 1),
                paiValidity: date(2021, 1, 1)...date(2039, 1, 1),
                dacValidity: date(2022, 1, 1)...date(2038, 1, 1),
                paiSigner: paiSigner, paiAKI: paiAKI, dacSigner: dacSigner, dacAKI: dacAKI,
                dacCriticalSubjectAlternativeName: san,
                paiExtraExtensions: paiExtra, dacExtraExtensions: dacExtra
            )
        }
        let cases: [(name: String, chain: SyntheticAttestationChain, valid: Bool)] = [
            ("valid", try chain(), true),
            ("critical SAN", try chain(san: true), true),
            ("DAC critical certificatePolicies", try chain(dacExtra: [SyntheticAttestationChain.criticalCertificatePolicies]), true),
            ("PAI critical certificatePolicies", try chain(paiExtra: [SyntheticAttestationChain.criticalCertificatePolicies]), true),
            ("DAC critical unknown extension", try chain(dacExtra: [SyntheticAttestationChain.criticalUnknownExtension]), false),
            ("PAI critical unknown extension", try chain(paiExtra: [SyntheticAttestationChain.criticalUnknownExtension]), false),
            ("PAI AKI is not the PAA SKI", try chain(paiAKI: Array(repeating: 0x42, count: 20)), false),
            ("DAC AKI is not the PAI SKI", try chain(dacAKI: Array(repeating: 0x24, count: 20)), false),
            ("PAI signed by another key", try chain(paiSigner: P256.Signing.PrivateKey()), false),
            ("DAC signed by another key", try chain(dacSigner: P256.Signing.PrivateKey()), false),
        ]
        let cdKey = try CDSigningKey(certificateDER: AttestationFixtures.testCDSigningCert)
        let testCD = try AttestationFixtures.testCD
        for item in cases {
            let store = try AttestationTrustStore(
                paas: [item.chain.paa], cdSigningKeys: [cdKey], provenance: TrustStoreProvenance(source: "explicit"))
            let chipCert = try runner.validateAttestationChain(dac: item.chain.dac, pai: item.chain.pai, paa: item.chain.paa)
            let (ours, outcome) = await Self.chainVerdict(
                dac: item.chain.dac, pai: item.chain.pai, key: item.chain.dacKey.rawRepresentation, cd: testCD, store: store)
            #expect(chipCert.succeeded == item.valid, "\(item.name): chip-cert exit \(chipCert.exitCode) \(chipCert.stderr)")
            #expect(ours == item.valid, "\(item.name): verifier \(outcome)")
            print("SYNTHETIC-CROSS-CHECK \(item.name): chip-cert exit \(chipCert.exitCode), verifier \(outcome)")
        }
    }
}
#endif
