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

    public init(reason: AttestationFailureReason, dacFingerprint: Data?, detail: String) {
        self.reason = reason
        self.dacFingerprint = dacFingerprint
        self.detail = detail
    }
}

// MARK: - VerifiedAttestation

/// A device whose attestation verified.
public struct VerifiedAttestation: Sendable, Equatable {

    public let vendorID: UInt16
    public let productID: UInt16

    /// The subject of the trusted PAA the chain ended at.
    public let paaSubject: String

    /// SHA-256 of the DAC DER.
    public let dacFingerprint: Data

    public let dacPublicKey: P256.Signing.PublicKey

    public init(
        vendorID: UInt16, productID: UInt16, paaSubject: String,
        dacFingerprint: Data, dacPublicKey: P256.Signing.PublicKey
    ) {
        self.vendorID = vendorID
        self.productID = productID
        self.paaSubject = paaSubject
        self.dacFingerprint = dacFingerprint
        self.dacPublicKey = dacPublicKey
    }

    public static func == (lhs: VerifiedAttestation, rhs: VerifiedAttestation) -> Bool {
        lhs.vendorID == rhs.vendorID
            && lhs.productID == rhs.productID
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
