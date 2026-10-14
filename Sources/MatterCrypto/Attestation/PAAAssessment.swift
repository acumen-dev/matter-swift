// PAAAssessment.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import X509

// MARK: - PAAAssessment

/// The verdict on one candidate PAA: whether it satisfies the rules the runtime applies to a PAA.
public struct PAAAssessment: Sendable, Equatable {

    /// The certificate's subject, when it parsed and passed admission; `nil` when it was
    /// rejected (the `reason` then names the problem).
    public let subject: String?

    /// The VID named in the subject, if it parsed and names one.
    public let vendorID: UInt16?

    /// Why the certificate is not acceptable as a PAA; `nil` if it is.
    public let rejection: String?

    public var isAcceptable: Bool { rejection == nil }
}

// MARK: - Assessment

extension AttestationTrustStore {

    /// Applies, to one DER-encoded certificate, the rules the runtime applies to a PAA:
    /// - it parses;
    /// - it is a self-signed P-256 CA with a SubjectKeyIdentifier that conforms to the Matter PAA
    ///   profile attestation verification applies (the store's admission rules);
    /// - its subject carries a well-formed Matter VID and no PID.
    ///
    /// Validity dates are deliberately not judged: the runtime accepts a PAA that was valid when
    /// the DAC's validity began, and a diff exposes `notValidAfter` for callers who care.
    ///
    /// Returns a verdict rather than throwing, so a caller can list what it rejected and why.
    public static func assessPAA(_ der: Data) -> PAAAssessment {
        let store: AttestationTrustStore
        do {
            store = try AttestationTrustStore(
                paas: [der], cdSigningKeys: [], provenance: TrustStoreProvenance(source: "assessment"))
        } catch let error as AttestationTrustStoreError {
            return PAAAssessment(subject: nil, vendorID: nil, rejection: admissionReason(error))
        } catch {
            return PAAAssessment(subject: nil, vendorID: nil, rejection: "\(error)")
        }
        guard let certificate = store.paas.first else {
            return PAAAssessment(subject: nil, vendorID: nil, rejection: "does not parse as a certificate")
        }
        let subject = String(describing: certificate.subject)
        func rejected(_ reason: String, vendorID: UInt16? = nil) -> PAAAssessment {
            PAAAssessment(subject: subject, vendorID: vendorID, rejection: reason)
        }
        guard let identifiers = try? MatterCertificateAttributes.identifiers(in: certificate.subject) else {
            return rejected("has an invalid Matter VID/PID in its subject")
        }
        guard identifiers.productID == nil else {
            return rejected("carries a PID", vendorID: identifiers.vendorID)
        }
        return PAAAssessment(subject: subject, vendorID: identifiers.vendorID, rejection: nil)
    }

    /// A short human reason for a store admission failure, without the index or label it carries.
    static func admissionReason(_ error: AttestationTrustStoreError) -> String {
        switch error {
        case .notACertificate: "does not parse as a certificate"
        case .notASelfSignedCA: "is not a self-signed CA"
        case .unsupportedKey: "does not have a P-256 key"
        case .missingSubjectKeyIdentifier: "has no SubjectKeyIdentifier"
        case .notAMatterPAA(_, let reason): reason
        default: "\(error)"
        }
    }
}
