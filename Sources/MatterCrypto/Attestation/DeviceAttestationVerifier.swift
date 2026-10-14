// DeviceAttestationVerifier.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import MatterTypes
import X509

// MARK: - DeviceAttestationVerifier

/// Verifies a Matter device's attestation: the DAC → PAI → PAA chain against a trust store,
/// the VID/PID rules, the echoed nonce, and the DAC's signature over the attestation elements.
///
/// The chain is validated with swift-certificates' `Verifier`, which checks each issuer's
/// signature, under ``MatterAttestationPolicy`` alone (profile, VID/PID and connectedhomeip's
/// validity model: the DAC at `now`, the chain at the DAC's notBefore).
public struct DeviceAttestationVerifier: Sendable {

    public let trustStore: AttestationTrustStore

    public init(trustStore: AttestationTrustStore) {
        self.trustStore = trustStore
    }

    /// Verifies an attestation.
    ///
    /// The Certification Declaration inside the attestation elements is not yet checked.
    ///
    /// - Parameter basicInformation: the VendorID and ProductID the device reports in its Basic
    ///   Information cluster. connectedhomeip compares them only with the Certification
    ///   Declaration (CD vendor_id == VID, PID in product_id_array), never with the DAC: a CD
    ///   with dac_origin fields legitimately names a DAC vendor other than the product's. They
    ///   are therefore consumed by the CD check and not compared with the DAC here.
    public func verify(
        dac: Data, pai: Data,
        attestationElements: Data, attestationSignature: Data,
        attestationChallenge: Data, sentNonce: Data,
        basicInformation: (vendorID: UInt16, productID: UInt16)? = nil,
        now: Date
    ) async -> AttestationResult {
        // 1. Parse.
        guard let dacCertificate = try? Certificate(derEncoded: Array(dac)) else {
            return Self.failed(.malformed, nil, "the DAC is not a parseable P-256 X.509 certificate")
        }
        // 2. Fingerprint.
        let fingerprint = Data(SHA256.hash(data: dac))
        guard let paiCertificate = try? Certificate(derEncoded: Array(pai)) else {
            return Self.failed(.malformed, fingerprint, "the PAI is not a parseable P-256 X.509 certificate")
        }

        // 3. Chain.
        var verifier = Verifier(rootCertificates: CertificateStore(trustStore.paas)) {
            MatterAttestationPolicy(now: now)
        }
        let paa: Certificate
        switch await verifier.validate(leaf: dacCertificate, intermediates: CertificateStore([paiCertificate])) {
        case .validCertificate(let chain):
            guard let root = chain.last else {
                return Self.failed(.chainInvalid, fingerprint, "empty validated chain")
            }
            paa = root
        case .couldNotValidate(let failures):
            let (reason, detail) = classify(failures, dac: dacCertificate, pai: paiCertificate)
            return Self.failed(reason, fingerprint, detail)
        }

        guard let ids = try? MatterCertificateAttributes.identifiers(in: dacCertificate.subject),
              let vendorID = ids.vendorID, let productID = ids.productID,
              let dacPublicKey = P256.Signing.PublicKey(dacCertificate.publicKey)
        else {
            return Self.failed(.malformed, fingerprint, "the DAC's VID, PID or key could not be read")
        }

        // 4. Attestation elements: {1: CD, 2: nonce, 3: timestamp}.
        guard let (_, element) = try? TLVDecoder.decode(attestationElements),
              case .structure = element,
              element[contextTag: 1]?.dataValue != nil,
              let echoedNonce = element[contextTag: 2]?.dataValue,
              element[contextTag: 3]?.uintValue != nil
        else {
            return Self.failed(.malformed, fingerprint, "the attestation elements are not a structure with a CD, nonce and timestamp")
        }
        guard echoedNonce == sentNonce else {
            return Self.failed(.nonceMismatch, fingerprint, "the attestation elements do not echo the nonce that was sent")
        }

        // 5. Signature.
        guard Self.isValidSignature(attestationSignature, over: attestationElements + attestationChallenge, by: dacPublicKey) else {
            return Self.failed(.attestationSignatureInvalid, fingerprint, "the attestation signature does not verify with the DAC key")
        }

        // 6. The Certification Declaration (and with it `basicInformation`) is not checked yet.

        return .verified(VerifiedAttestation(
            vendorID: vendorID, productID: productID,
            paaSubject: paa.subject.description,
            dacFingerprint: fingerprint,
            dacPublicKey: dacPublicKey
        ))
    }

    /// CSRResponse: the device signs nocsrElements || attestationChallenge with its DAC key.
    public static func verifyNOCSRSignature(
        nocsrElements: Data, signature: Data, attestationChallenge: Data,
        dacPublicKey: P256.Signing.PublicKey
    ) -> Bool {
        isValidSignature(signature, over: nocsrElements + attestationChallenge, by: dacPublicKey)
    }

    // MARK: - Helpers

    /// ECDSA-SHA256, with the signature as raw r‖s (64 bytes) or DER.
    private static func isValidSignature(_ signature: Data, over message: Data, by key: P256.Signing.PublicKey) -> Bool {
        let parsed: P256.Signing.ECDSASignature?
        if signature.count == 64 {
            parsed = try? P256.Signing.ECDSASignature(rawRepresentation: signature)
        } else {
            parsed = try? P256.Signing.ECDSASignature(derRepresentation: signature)
        }
        guard let parsed else { return false }
        return key.isValidSignature(parsed, for: message)
    }

    private static func failed(_ reason: AttestationFailureReason, _ fingerprint: Data?, _ detail: String) -> AttestationResult {
        .failed(AttestationFailure(reason: reason, dacFingerprint: fingerprint, detail: detail))
    }

    /// Maps swift-certificates' failure list to a reason.
    ///
    /// - A failure from ``MatterAttestationPolicy`` maps by its category: VID/PID →
    ///   `.vidPidMismatch`, validity → `.certificateExpired`, profile → `.malformed`, chain
    ///   shape → `.chainInvalid`. A reason without a Matter prefix cannot occur (the Matter
    ///   policy is the only one); it is treated as `.chainInvalid`.
    /// - An empty list means no candidate chain reached a policy: no trusted PAA issued the PAI
    ///   → `.untrustedRoot`; a PAA with the PAI's authority key ID, or the PAI, did not sign its
    ///   child → `.chainInvalid`; otherwise a certificate has a critical extension the policy
    ///   does not handle → `.malformed`.
    private func classify(
        _ failures: [CertificateValidationResult.PolicyFailure],
        dac: Certificate, pai: Certificate
    ) -> (AttestationFailureReason, String) {
        if let first = failures.first {
            let text = first.policyFailureReason.description
            switch MatterAttestationPolicy.Category.of(text) {
            case .vidPidMismatch: return (.vidPidMismatch, text)
            case .validity: return (.certificateExpired, text)
            case .format: return (.malformed, text)
            case .chain, nil: return (.chainInvalid, text)
            }
        }

        let issuers = trustStore.paas.filter { $0.subject == pai.issuer }
        if !issuers.contains(where: { $0.publicKey.isValidSignature(pai.signature, for: pai) }) {
            let paiAKI = (try? pai.extensions.authorityKeyIdentifier)?.keyIdentifier
            let sameKeyID = paiAKI != nil && trustStore.paas.contains {
                (try? $0.extensions.subjectKeyIdentifier)?.keyIdentifier == paiAKI
            }
            if sameKeyID {
                return (.chainInvalid, "the trusted PAA with the PAI's authority key ID did not sign the PAI")
            }
            return (.untrustedRoot, "no trusted PAA issued the PAI (issuer \(pai.issuer))")
        }
        guard dac.issuer == pai.subject, pai.publicKey.isValidSignature(dac.signature, for: dac) else {
            return (.chainInvalid, "the PAI did not issue the DAC")
        }
        return (.malformed, "a chain certificate has an unsupported critical extension")
    }
}
