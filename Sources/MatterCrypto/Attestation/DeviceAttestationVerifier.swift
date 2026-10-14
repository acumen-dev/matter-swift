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
        guard let elements = AttestationElements(attestationElements) else {
            return Self.failed(.malformed, fingerprint, "the attestation elements are not a well-formed structure with a CD, nonce and timestamp")
        }
        guard elements.nonce == sentNonce else {
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

    /// ECDSA-SHA256 with the signature as raw r‖s, exactly 64 bytes: the wire format, and the
    /// only form upstream accepts (`P256PublicKey::ECDSA_validate_hash_signature` requires
    /// `kP256_ECDSA_Signature_Length_Raw`).
    private static func isValidSignature(_ signature: Data, over message: Data, by key: P256.Signing.PublicKey) -> Bool {
        guard signature.count == 64,
              let parsed = try? P256.Signing.ECDSASignature(rawRepresentation: signature)
        else { return false }
        return key.isValidSignature(parsed, for: message)
    }

    private static func failed(_ reason: AttestationFailureReason, _ fingerprint: Data?, _ detail: String) -> AttestationResult {
        .failed(AttestationFailure(reason: reason, dacFingerprint: fingerprint, detail: detail))
    }

    /// Maps swift-certificates' failure list to a reason.
    ///
    /// - A failure from ``MatterAttestationPolicy`` maps by its category: VID/PID →
    ///   `.vidPidMismatch`, validity → `.certificateExpired`, profile → `.malformed`, chain
    ///   shape or DAC → PAI key-ID link → `.chainInvalid`, PAI → PAA key-ID link →
    ///   `.untrustedRoot`. With several same-named PAAs, the failure of the chain ending at the
    ///   PAA whose SubjectKeyIdentifier the PAI names is preferred. A reason without a Matter prefix cannot occur (the Matter
    ///   policy is the only one); it is treated as `.chainInvalid`.
    /// - An empty list means no candidate chain reached a policy: no trusted PAA issued the PAI
    ///   → `.untrustedRoot`; a PAA with the PAI's authority key ID, or the PAI, did not sign its
    ///   child → `.chainInvalid`; otherwise a certificate has a critical extension the policy
    ///   does not handle → `.malformed`.
    private func classify(
        _ failures: [CertificateValidationResult.PolicyFailure],
        dac: Certificate, pai: Certificate
    ) -> (AttestationFailureReason, String) {
        let paiAKI = MatterAttestationPolicy.authorityKeyID(of: pai)
        let named = failures.first { failure in
            failure.chain.count == 3 && paiAKI != nil
                && MatterAttestationPolicy.subjectKeyID(of: failure.chain[2]) == paiAKI
        }
        if let chosen = named ?? failures.first {
            let text = chosen.policyFailureReason.description
            switch MatterAttestationPolicy.Category.of(text) {
            case .vidPidMismatch: return (.vidPidMismatch, text)
            case .validity: return (.certificateExpired, text)
            case .format: return (.malformed, text)
            case .paaNotFound: return (.untrustedRoot, text)
            case .chain, nil: return (.chainInvalid, text)
            }
        }

        let issuers = trustStore.paas.filter { $0.subject == pai.issuer }
        if !issuers.contains(where: { $0.publicKey.isValidSignature(pai.signature, for: pai) }) {
            let sameKeyID = paiAKI != nil && trustStore.paas.contains {
                MatterAttestationPolicy.subjectKeyID(of: $0) == paiAKI
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

// MARK: - AttestationElements

/// The attestation elements TLV, parsed as connectedhomeip v1.4.0.0
/// `DeconstructAttestationElements` (src/credentials/DeviceAttestationConstructor.cpp) does:
/// an anonymous structure whose leading context-tagged fields start with tag 1 and strictly
/// ascend; tag 1 (CD) and 2 (nonce) are byte strings, 3 (timestamp) an unsigned integer that
/// fits in 32 bits, 4 (firmware information) a byte string; other context tags are allowed in
/// order; the first non-context tag ends the context section. Tags 1, 2 and 3 are required.
struct AttestationElements: Equatable {
    let certificationDeclaration: Data
    let nonce: Data
    let timestamp: UInt32
    let firmwareInformation: Data?

    init?(_ data: Data) {
        guard let (tag, element) = try? TLVDecoder.decode(data),
              tag == .anonymous,
              case .structure(let fields) = element
        else { return nil }

        var certificationDeclaration: Data?
        var nonce: Data?
        var timestamp: UInt32?
        var firmwareInformation: Data?
        var lastTag: UInt8?
        for field in fields {
            guard case .contextSpecific(let number) = field.tag else { break }
            if let lastTag {
                guard number > lastTag else { return nil }
            } else {
                guard number == 1 else { return nil }
            }
            lastTag = number
            switch number {
            case 1:
                guard case .octetString(let value) = field.value else { return nil }
                certificationDeclaration = value
            case 2:
                guard case .octetString(let value) = field.value else { return nil }
                nonce = value
            case 3:
                guard case .unsignedInt(let value) = field.value, let narrowed = UInt32(exactly: value) else { return nil }
                timestamp = narrowed
            case 4:
                guard case .octetString(let value) = field.value else { return nil }
                firmwareInformation = value
            default:
                break
            }
        }
        guard let certificationDeclaration, let nonce, let timestamp else { return nil }
        self.certificationDeclaration = certificationDeclaration
        self.nonce = nonce
        self.timestamp = timestamp
        self.firmwareInformation = firmwareInformation
    }
}
