// PAAAssessment.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import X509

// MARK: - PAAAssessment

/// The verdict on one candidate PAA: whether it satisfies the rules the runtime applies.
public struct PAAAssessment: Sendable, Equatable {

    /// The certificate's subject, if it parsed.
    public let subject: String?

    /// The VID named in the subject, if it parsed and names one.
    public let vendorID: UInt16?

    /// Why the certificate is not acceptable as a PAA at the assessed time; `nil` if it is.
    public let rejection: String?

    public var isAcceptable: Bool { rejection == nil }
}

// MARK: - Assessment

extension AttestationTrustStore {

    /// Applies, to one DER-encoded certificate, the same rules a store enforces on its roots:
    /// - it parses;
    /// - it is a self-signed P-256 CA with a SubjectKeyIdentifier (the store's admission rules);
    /// - it conforms to the Matter PAA profile that attestation verification applies;
    /// - it is valid at `now`;
    /// - its subject carries a well-formed Matter VID/PID.
    ///
    /// Returns a verdict rather than throwing, so a caller can list what it rejected and why.
    public static func assessPAA(_ der: Data, now: Date) -> PAAAssessment {
        do {
            _ = try AttestationTrustStore(
                paas: [der], cdSigningKeys: [], provenance: TrustStoreProvenance(source: "assessment"))
        } catch let error as AttestationTrustStoreError {
            return PAAAssessment(subject: nil, vendorID: nil, rejection: admissionReason(error))
        } catch {
            return PAAAssessment(subject: nil, vendorID: nil, rejection: "\(error)")
        }
        // Admission has parsed it once, so this cannot fail; keep a reason anyway.
        guard let certificate = try? Certificate(derEncoded: Array(der)) else {
            return PAAAssessment(subject: nil, vendorID: nil, rejection: "does not parse as a certificate")
        }
        let subject = String(describing: certificate.subject)
        func rejected(_ reason: String, vendorID: UInt16? = nil) -> PAAAssessment {
            PAAAssessment(subject: subject, vendorID: vendorID, rejection: reason)
        }
        if let violation = MatterAttestationPolicy.profileViolation(certificate, role: .paa) {
            return rejected(violation)
        }
        guard let identifiers = try? MatterCertificateAttributes.identifiers(in: certificate.subject) else {
            return rejected("has an invalid Matter VID/PID in its subject")
        }
        if now < certificate.notValidBefore { return rejected("is not yet valid", vendorID: identifiers.vendorID) }
        if now > certificate.notValidAfter { return rejected("has expired", vendorID: identifiers.vendorID) }
        return PAAAssessment(subject: subject, vendorID: identifiers.vendorID, rejection: nil)
    }

    /// A short human reason for a store admission failure, without the index or label it carries.
    static func admissionReason(_ error: AttestationTrustStoreError) -> String {
        switch error {
        case .notACertificate: "does not parse as a certificate"
        case .notASelfSignedCA: "is not a self-signed CA"
        case .unsupportedKey: "does not have a P-256 key"
        case .missingSubjectKeyIdentifier: "has no SubjectKeyIdentifier"
        default: "\(error)"
        }
    }
}
