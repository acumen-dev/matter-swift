// AttestationResult.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto

// MARK: - AttestationFailureReason

/// Why device attestation failed.
///
/// The `rawValue` is a persistence format (a stored attestation override records it), so each
/// is spelled out and equals the case name. Renaming a case must not change its raw value.
///
/// Adding a case requires bumping `StoredControllerState.currentSchemaVersion` (MatterTypes):
/// an older library that loaded a stored override naming the new case would fail on it, and
/// the bump is what makes that library refuse the state up front with a clear error.
public enum AttestationFailureReason: String, Sendable, Codable, CaseIterable {
    /// No path from the PAI to any PAA in the trust store.
    case untrustedRoot = "untrustedRoot"
    /// A path exists but a signature, key-identifier link or chain shape is wrong.
    case chainInvalid = "chainInvalid"
    /// A chain certificate is outside its validity window at the verification time.
    case certificateExpired = "certificateExpired"
    /// The DAC, PAI and PAA vendor/product identifiers are missing or disagree.
    case vidPidMismatch = "vidPidMismatch"
    /// The Certification Declaration signature does not verify.
    case cdSignatureInvalid = "cdSignatureInvalid"
    /// The Certification Declaration is signed by a key the trust store does not hold.
    case cdUnknownSigningKey = "cdUnknownSigningKey"
    /// The Certification Declaration does not list the device's VID/PID.
    case cdVidPidNotListed = "cdVidPidNotListed"
    /// The Certification Declaration has an authorized PAA list that omits the PAA the chain
    /// ends at (connectedhomeip `kCertificationDeclarationInvalidPAA`).
    case cdPAANotAuthorized = "cdPAANotAuthorized"
    /// The attestation elements are not signed by the DAC key.
    case attestationSignatureInvalid = "attestationSignatureInvalid"
    /// The attestation elements do not echo the nonce the commissioner sent.
    case nonceMismatch = "nonceMismatch"
    /// A certificate, the attestation elements or the Certification Declaration could not be
    /// parsed, a certificate breaks the Matter attestation certificate profile, or the CD has an
    /// unsupported format version or certification type.
    case malformed = "malformed"
}

// MARK: - AttestationFailure

/// A failed device attestation.
public struct AttestationFailure: Error, Sendable, Equatable {

    public let reason: AttestationFailureReason

    /// SHA-256 of the DAC DER; `nil` only if the DAC could not be parsed.
    public let dacFingerprint: Data?

    /// Human-readable; never contains key material.
    public let detail: String

    /// The public key in the DAC whose fingerprint is `dacFingerprint`, from the same parse;
    /// **unverified**. `nil` if the DAC could not be parsed or its key is not P-256. A
    /// commissioner that approves the failure binds the device to this key (the CSRResponse
    /// must be signed with it).
    public let dacPublicKey: P256.Signing.PublicKey?

    /// The vendor ID in the DAC's subject; **unverified** (the chain may not have validated).
    /// `nil` if the subject yields none. For showing a person deciding on an approval.
    public let dacVendorID: UInt16?

    /// The product ID in the DAC's subject; **unverified**, as ``dacVendorID``.
    public let dacProductID: UInt16?

    /// Only the verifier produces failures; a commissioner applies the one `verify` returned.
    package init(
        reason: AttestationFailureReason, dacFingerprint: Data?, detail: String,
        dacPublicKey: P256.Signing.PublicKey? = nil, dacVendorID: UInt16? = nil, dacProductID: UInt16? = nil
    ) {
        self.reason = reason
        self.dacFingerprint = dacFingerprint
        self.detail = detail
        self.dacPublicKey = dacPublicKey
        self.dacVendorID = dacVendorID
        self.dacProductID = dacProductID
    }

    public static func == (lhs: AttestationFailure, rhs: AttestationFailure) -> Bool {
        lhs.reason == rhs.reason
            && lhs.dacFingerprint == rhs.dacFingerprint
            && lhs.detail == rhs.detail
            && lhs.dacPublicKey?.x963Representation == rhs.dacPublicKey?.x963Representation
            && lhs.dacVendorID == rhs.dacVendorID
            && lhs.dacProductID == rhs.dacProductID
    }
}

// MARK: - VerifiedAttestation

/// A device whose attestation verified.
public struct VerifiedAttestation: Sendable, Equatable {

    /// The vendor ID in the DAC's subject. For a white-label product this is the DAC issuer's
    /// (the OEM's), which may differ from the product's Basic Information VendorID.
    public let vendorID: UInt16

    /// The product ID in the DAC's subject; as ``vendorID``.
    public let productID: UInt16

    /// The Certification Declaration's `certification_type`: 0 development and test,
    /// 1 provisional, 2 official. A consumer that admits only certified products checks for 2;
    /// swift-matter applies no such policy.
    public let certificationType: UInt8

    /// The subject of the trusted PAA the chain ended at.
    public let paaSubject: String

    /// SHA-256 of the DAC DER.
    public let dacFingerprint: Data

    public let dacPublicKey: P256.Signing.PublicKey

    /// Only the verifier produces a verified attestation.
    package init(
        vendorID: UInt16, productID: UInt16, certificationType: UInt8, paaSubject: String,
        dacFingerprint: Data, dacPublicKey: P256.Signing.PublicKey
    ) {
        self.vendorID = vendorID
        self.productID = productID
        self.certificationType = certificationType
        self.paaSubject = paaSubject
        self.dacFingerprint = dacFingerprint
        self.dacPublicKey = dacPublicKey
    }

    public static func == (lhs: VerifiedAttestation, rhs: VerifiedAttestation) -> Bool {
        lhs.vendorID == rhs.vendorID
            && lhs.productID == rhs.productID
            && lhs.certificationType == rhs.certificationType
            && lhs.paaSubject == rhs.paaSubject
            && lhs.dacFingerprint == rhs.dacFingerprint
            && lhs.dacPublicKey.x963Representation == rhs.dacPublicKey.x963Representation
    }
}

// MARK: - AttestationResult

/// The outcome of ``DeviceAttestationVerifier/verify(dac:pai:attestationElements:attestationSignature:attestationChallenge:sentNonce:basicInformation:now:)``.
public enum AttestationResult: Sendable, Equatable {
    case verified(VerifiedAttestation)
    case failed(AttestationFailure)
}
