// DeviceAttestationVerifier.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import MatterTypes
import X509

// MARK: - DeviceAttestationVerifier

/// Verifies a Matter device's attestation: the DAC → PAI → PAA chain against a trust store,
/// the VID/PID rules, the echoed nonce, the DAC's signature over the attestation elements, and
/// the Certification Declaration.
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
    /// - Parameter basicInformation: the VendorID and ProductID the device reports in its Basic
    ///   Information cluster. As in connectedhomeip, they are compared only with the
    ///   Certification Declaration (CD vendor_id == VID, PID in product_id_array), never with
    ///   the DAC: a CD with dac_origin fields legitimately names a DAC vendor other than the
    ///   product's.
    public func verify(
        dac: Data, pai: Data,
        attestationElements: Data, attestationSignature: Data,
        attestationChallenge: Data, sentNonce: Data,
        basicInformation: (vendorID: UInt16, productID: UInt16),
        now: Date
    ) async -> AttestationResult {
        // 1. Parse.
        guard let dacCertificate = try? Certificate(derEncoded: Array(dac)) else {
            return Self.failed(.malformed, nil, "the DAC is not a parseable P-256 X.509 certificate")
        }
        // 2. Fingerprint, and the DAC's key and identifiers as they stand (unverified), carried
        //    by every failure from here on so a caller approving it has them from this parse.
        let fingerprint = Data(SHA256.hash(data: dac))
        let unverifiedKey = P256.Signing.PublicKey(dacCertificate.publicKey)
        let unverifiedIDs = try? MatterCertificateAttributes.identifiers(in: dacCertificate.subject)
        func failed(_ reason: AttestationFailureReason, _ detail: String) -> AttestationResult {
            .failed(AttestationFailure(
                reason: reason, dacFingerprint: fingerprint, detail: detail,
                dacPublicKey: unverifiedKey,
                dacVendorID: unverifiedIDs?.vendorID, dacProductID: unverifiedIDs?.productID))
        }
        guard let paiCertificate = try? Certificate(derEncoded: Array(pai)) else {
            return failed(.malformed, "the PAI is not a parseable P-256 X.509 certificate")
        }

        // 3. Chain.
        var verifier = Verifier(rootCertificates: CertificateStore(trustStore.paas)) {
            MatterAttestationPolicy(now: now)
        }
        let paa: Certificate
        switch await verifier.validate(leaf: dacCertificate, intermediates: CertificateStore([paiCertificate])) {
        case .validCertificate(let chain):
            guard let root = chain.last else {
                return failed(.chainInvalid, "empty validated chain")
            }
            paa = root
        case .couldNotValidate(let failures):
            let (reason, detail) = classify(failures, dac: dacCertificate, pai: paiCertificate)
            return failed(reason, detail)
        }

        guard let vendorID = unverifiedIDs?.vendorID, let productID = unverifiedIDs?.productID,
              let dacPublicKey = unverifiedKey
        else {
            return failed(.malformed, "the DAC's VID, PID or key could not be read")
        }

        // 4. Attestation elements: {1: CD, 2: nonce, 3: timestamp}.
        guard let elements = AttestationElements(attestationElements) else {
            return failed(.malformed, "the attestation elements are not a well-formed structure with a CD, nonce and timestamp")
        }
        guard elements.nonce == sentNonce else {
            return failed(.nonceMismatch, "the attestation elements do not echo the nonce that was sent")
        }

        // 5. Signature.
        guard Self.isValidSignature(attestationSignature, over: attestationElements + attestationChallenge, by: dacPublicKey) else {
            return failed(.attestationSignatureInvalid, "the attestation signature does not verify with the DAC key")
        }

        // 6. Certification Declaration.
        if let (reason, detail) = checkCertificationDeclaration(
            elements.certificationDeclaration, basicInformation: basicInformation,
            dacVendorID: vendorID, dacProductID: productID, pai: paiCertificate, paa: paa
        ) {
            return failed(reason, detail)
        }

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

    // MARK: - Certification Declaration

    /// The CD's signature, then connectedhomeip v1.4.0.0
    /// `DefaultDACVerifier::ValidateCertificateDeclarationPayload` rule for rule (line numbers
    /// in src/credentials/attestation_verifier/DefaultDeviceAttestationVerifier.cpp). Upstream's
    /// vendor-ID and product-ID failures give `.cdVidPidNotListed`, its authorized-PAA failure
    /// `.cdPAANotAuthorized`. `nil` when the CD passes.
    ///
    /// Upstream also refuses the test CD signing key unless test keys are enabled (:477-480);
    /// here the trust store alone decides which CD signing keys are trusted.
    private func checkCertificationDeclaration(
        _ cmsDER: Data, basicInformation: (vendorID: UInt16, productID: UInt16),
        dacVendorID: UInt16, dacProductID: UInt16, pai: Certificate, paa: Certificate
    ) -> (AttestationFailureReason, String)? {
        let cd: CertificationDeclaration
        do {
            cd = try CertificationDeclaration(cmsDER: cmsDER)
        } catch {
            return (.malformed, "the Certification Declaration is malformed: \(error)")
        }
        switch cd.verifySignature(keys: trustStore.cdSigningKeys) {
        case .valid:
            break
        case .unknownSigningKey:
            return (.cdUnknownSigningKey, "the trust store has no CD signing key with the CD signer's key identifier")
        case .invalidSignature:
            return (.cdSignatureInvalid, "the Certification Declaration signature does not verify")
        }

        // :505 (kAttestationElementsMalformed). security_level, security_information and
        // version_number are not interpreted by commissioners (:502-503).
        guard cd.formatVersion == 1, cd.certificationType < 3 else {
            return (.malformed, "the CD has format_version \(cd.formatVersion) or certification_type \(cd.certificationType)")
        }
        // :512 and :517: the Basic Information VID and PID.
        guard cd.vendorID == basicInformation.vendorID else {
            return (.cdVidPidNotListed, "the CD vendor_id is not the Basic Information VendorID")
        }
        guard cd.productIDs.contains(basicInformation.productID) else {
            return (.cdVidPidNotListed, "the CD product_id_array does not list the Basic Information ProductID")
        }

        // The PAI's ids; the chain stage has already required a valid PAI VID. A PAI PID of 0
        // counts as absent, as upstream's `paiProductId != 0`.
        guard let paiIDs = try? MatterCertificateAttributes.identifiers(in: pai.subject),
              let paiVendorID = paiIDs.vendorID
        else {
            return (.malformed, "the PAI's VID could not be read")
        }
        let paiProductID = paiIDs.productID ?? 0

        if let originVendorID = cd.dacOriginVendorID, let originProductID = cd.dacOriginProductID {
            // :524-539
            guard dacVendorID == originVendorID, paiVendorID == originVendorID else {
                return (.cdVidPidNotListed, "the DAC or PAI VID is not the CD dac_origin_vendor_id")
            }
            guard dacProductID == originProductID, paiProductID == 0 || paiProductID == originProductID else {
                return (.cdVidPidNotListed, "the DAC or PAI PID is not the CD dac_origin_product_id")
            }
        } else {
            // :545-560
            guard dacVendorID == cd.vendorID, paiVendorID == cd.vendorID else {
                return (.cdVidPidNotListed, "the DAC or PAI VID is not the CD vendor_id")
            }
            guard cd.productIDs.contains(dacProductID),
                  paiProductID == 0 || cd.productIDs.contains(paiProductID)
            else {
                return (.cdVidPidNotListed, "the CD product_id_array does not list the DAC or PAI PID")
            }
        }

        // :563-568 (kCertificationDeclarationInvalidPAA).
        if let authorizedPAAs = cd.authorizedPAAs {
            let paaSKI = MatterAttestationPolicy.subjectKeyID(of: paa).map { Data($0) }
            guard let paaSKI, authorizedPAAs.contains(paaSKI) else {
                return (.cdPAANotAuthorized, "the CD authorized_paa_list does not include the PAA's subject key identifier")
            }
        }
        return nil
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
    ///   does not handle → `.malformed`, with the profile's named violation for the DAC or PAI.
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
        // swift-certificates refuses an unhandled critical extension before the policy runs;
        // the profile names it.
        for (certificate, role) in [(pai, MatterAttestationPolicy.Role.pai), (dac, .dac)] {
            if let violation = MatterAttestationPolicy.profileViolation(certificate, role: role) {
                return (.malformed, MatterAttestationPolicy.Category.format.reason("\(role.rawValue) \(violation)"))
            }
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
