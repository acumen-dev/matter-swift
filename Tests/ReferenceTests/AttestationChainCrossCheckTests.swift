// AttestationChainCrossCheckTests.swift
// Copyright 2026 Monagle Pty Ltd
//
// Cross-checks DeviceAttestationVerifier's chain verdict against
// `chip-cert validate-att-cert` for every connectedhomeip commissioner DUT vector.

#if canImport(Network)
import Testing
import Foundation
import Crypto
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
        .cdSignatureInvalid, .cdUnknownSigningKey, .cdVidPidNotListed,
    ]

    /// Whether `verify` accepted the DAC → PAI → PAA chain.
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
            attestationChallenge: challenge, sentNonce: nonce, now: Date()
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
        let store = try AttestationTrustStore(
            paas: [paa], cdSigningKeys: [], provenance: TrustStoreProvenance(source: "explicit")
        )

        var cases: [(name: String, dac: Data, pai: Data, key: Data, cd: Data)] = [(
            "dev", try AttestationFixtures.devDAC, try AttestationFixtures.devPAI,
            try P256.Signing.PrivateKey(derRepresentation: AttestationFixtures.devDACPrivateKey).rawRepresentation,
            try AttestationFixtures.testCD
        )]
        for (name, vector) in try AttestationFixtures.negativeCases {
            cases.append((name, vector.dacCert, vector.paiCert, vector.dacPrivateKey, vector.certificationDeclaration))
        }

        var agreed = 0
        var chipCertValid = 0
        for item in cases {
            let chipCert = try runner.validateAttestationChain(dac: item.dac, pai: item.pai, paa: paa)
            let (ours, outcome) = await Self.chainVerdict(dac: item.dac, pai: item.pai, key: item.key, cd: item.cd, store: store)
            #expect(chipCert.succeeded == ours,
                    "\(item.name): chip-cert \(chipCert.succeeded ? "valid" : "invalid"), verifier \(outcome); \(chipCert.stderr)")
            if chipCert.succeeded == ours { agreed += 1 }
            if chipCert.succeeded { chipCertValid += 1 }
        }
        print("CROSS-CHECK agreed \(agreed)/\(cases.count); chip-cert valid \(chipCertValid), invalid \(cases.count - chipCertValid)")
    }
}
#endif
