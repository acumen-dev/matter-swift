// MatterAttestationPolicy.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import SwiftASN1
import X509

// MARK: - MatterAttestationPolicy

/// The Matter device attestation rules for a DAC → PAI → PAA chain, as a swift-certificates
/// ``VerifierPolicy``.
///
/// Mirrors connectedhomeip v1.4.0.0 (`DefaultDACVerifier::VerifyAttestationInformation`,
/// `VerifyAttestationCertificateFormat` in src/crypto/CHIPCryptoPALOpenSSL.cpp, and
/// `chip-cert validate-att-cert`):
///
/// - the chain is exactly [DAC, PAI, PAA];
/// - every certificate passes the Matter certificate profile for its position: X.509 v3,
///   ecdsa-with-SHA256, a P-256 key, a critical basicConstraints (DAC: not a CA and no path
///   length; PAI: a CA with path length 0; PAA: a CA with no path length or 1), a critical
///   keyUsage (DAC: exactly digitalSignature; PAI/PAA: keyCertSign and cRLSign, optionally
///   digitalSignature, nothing else), a non-critical 20-byte SubjectKeyIdentifier, and, for the
///   DAC and PAI, a non-critical 20-byte AuthorityKeyIdentifier; no extension repeats;
/// - the Matter VID/PID subject attributes parse (``MatterCertificateAttributes``), and the PAA
///   carries no PID;
/// - the DAC has a VID and a PID, the PAI has a VID equal to the DAC's, a PAI PID (if any)
///   equals the DAC's, and a PAA VID (if any) equals the DAC's;
/// - every certificate is within its validity window at `validationTime`.
///
/// Upstream validates the PAI and PAA at the DAC's notBefore and only the DAC at the current
/// time; this policy checks all three at `validationTime`, which is stricter.
///
/// Each failure reason starts with one of the ``Category`` prefixes so the verifier can map it
/// to an ``AttestationFailureReason``.
struct MatterAttestationPolicy: VerifierPolicy, Sendable {

    /// The prefix of a failure reason, naming what kind of rule failed.
    enum Category: String, CaseIterable {
        /// A missing or disagreeing VID/PID. Maps to ``AttestationFailureReason/vidPidMismatch``.
        case vidPidMismatch = "matter-vid-pid"
        /// A certificate outside its validity window. Maps to ``AttestationFailureReason/certificateExpired``.
        case validity = "matter-validity"
        /// A break of the Matter certificate profile. Maps to ``AttestationFailureReason/malformed``.
        case format = "matter-format"
        /// A chain of the wrong shape. Maps to ``AttestationFailureReason/chainInvalid``.
        case chain = "matter-chain"

        func reason(_ detail: String) -> String { "\(rawValue): \(detail)" }

        /// The category a failure reason produced by this policy starts with, if any.
        static func of(_ reason: String) -> Category? {
            allCases.first { reason.hasPrefix("\($0.rawValue): ") }
        }
    }

    /// The time each certificate's validity window is checked against.
    let validationTime: Date

    /// Matter requires critical basicConstraints and keyUsage; connectedhomeip also accepts a
    /// critical extendedKeyUsage (vector `struct_*_ext_extended_key_usage_present`).
    let verifyingCriticalExtensions: [ASN1ObjectIdentifier] = [
        .X509ExtensionID.basicConstraints,
        .X509ExtensionID.keyUsage,
        .X509ExtensionID.extendedKeyUsage,
    ]

    init(validationTime: Date) {
        self.validationTime = validationTime
    }

    func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) -> PolicyEvaluationResult {
        guard chain.count == 3 else {
            return .failsToMeetPolicy(reason: Category.chain.reason("chain length \(chain.count), expected DAC, PAI, PAA"))
        }
        let dac = chain[0], pai = chain[1], paa = chain[2]

        // Profile, in connectedhomeip's order: PAI, then DAC (then the PAA, which chip-cert checks).
        for (certificate, role) in [(pai, Role.pai), (dac, .dac), (paa, .paa)] {
            if let violation = Self.profileViolation(certificate, role: role) {
                return .failsToMeetPolicy(reason: Category.format.reason("\(role.rawValue) \(violation)"))
            }
        }

        // VID/PID.
        let dacIDs: (vendorID: UInt16?, productID: UInt16?)
        let paiIDs: (vendorID: UInt16?, productID: UInt16?)
        let paaIDs: (vendorID: UInt16?, productID: UInt16?)
        do {
            dacIDs = try MatterCertificateAttributes.identifiers(in: dac.subject)
        } catch {
            return .failsToMeetPolicy(reason: Category.format.reason("DAC VID/PID attributes are invalid (\(error))"))
        }
        do {
            paiIDs = try MatterCertificateAttributes.identifiers(in: pai.subject)
        } catch {
            return .failsToMeetPolicy(reason: Category.format.reason("PAI VID/PID attributes are invalid (\(error))"))
        }
        do {
            paaIDs = try MatterCertificateAttributes.identifiers(in: paa.subject)
        } catch {
            return .failsToMeetPolicy(reason: Category.format.reason("PAA VID/PID attributes are invalid (\(error))"))
        }
        if let violation = Self.identifierViolation(dac: dacIDs, pai: paiIDs, paa: paaIDs) {
            return .failsToMeetPolicy(reason: violation)
        }

        // Validity.
        for (certificate, role) in [(dac, Role.dac), (pai, .pai), (paa, .paa)] {
            guard certificate.notValidBefore <= validationTime, validationTime <= certificate.notValidAfter else {
                return .failsToMeetPolicy(reason: Category.validity.reason(
                    "\(role.rawValue) is valid \(certificate.notValidBefore) to \(certificate.notValidAfter), not at \(validationTime)"
                ))
            }
        }
        return .meetsPolicy
    }

    // MARK: - VID/PID

    private static func identifierViolation(
        dac: (vendorID: UInt16?, productID: UInt16?),
        pai: (vendorID: UInt16?, productID: UInt16?),
        paa: (vendorID: UInt16?, productID: UInt16?)
    ) -> String? {
        guard let dacVID = dac.vendorID else {
            return Category.vidPidMismatch.reason("DAC has no VID")
        }
        guard let dacPID = dac.productID else {
            return Category.vidPidMismatch.reason("DAC has no PID")
        }
        guard let paiVID = pai.vendorID else {
            return Category.vidPidMismatch.reason("PAI has no VID")
        }
        guard paiVID == dacVID else {
            return Category.vidPidMismatch.reason("PAI VID \(hex(paiVID)) differs from DAC VID \(hex(dacVID))")
        }
        if let paiPID = pai.productID, paiPID != dacPID {
            return Category.vidPidMismatch.reason("PAI PID \(hex(paiPID)) differs from DAC PID \(hex(dacPID))")
        }
        if let paaVID = paa.vendorID, paaVID != dacVID {
            return Category.vidPidMismatch.reason("PAA VID \(hex(paaVID)) differs from DAC VID \(hex(dacVID))")
        }
        guard paa.productID == nil else {
            return Category.format.reason("PAA carries a PID")
        }
        return nil
    }

    private static func hex(_ value: UInt16) -> String {
        "0x" + String(value, radix: 16, uppercase: true)
    }

    // MARK: - Certificate profile

    enum Role: String {
        case dac = "DAC"
        case pai = "PAI"
        case paa = "PAA"
    }

    /// `VerifyAttestationCertificateFormat`: why `certificate` breaks the Matter profile for
    /// `role`, or `nil` if it conforms.
    static func profileViolation(_ certificate: Certificate, role: Role) -> String? {
        guard certificate.version == .v3 else { return "is not X.509 v3" }
        guard certificate.signatureAlgorithm == .ecdsaWithSHA256 else { return "is not signed with ecdsa-with-SHA256" }
        guard P256.Signing.PublicKey(certificate.publicKey) != nil else { return "does not have a P-256 key" }

        var basicConstraintsSeen = false
        var keyUsageSeen = false
        var subjectKeyIDSeen = false
        var authorityKeyIDSeen = false

        for ext in certificate.extensions {
            switch ext.oid {
            case .X509ExtensionID.basicConstraints:
                guard ext.critical, !basicConstraintsSeen else { return "basicConstraints is not critical or repeats" }
                basicConstraintsSeen = true
                guard let constraints = try? BasicConstraints(ext) else { return "basicConstraints is invalid" }
                switch (role, constraints) {
                case (.dac, .notCertificateAuthority):
                    break
                case (.pai, .isCertificateAuthority(maxPathLength: 0)):
                    break
                case (.paa, .isCertificateAuthority(maxPathLength: nil)), (.paa, .isCertificateAuthority(maxPathLength: 1)):
                    break
                default:
                    return "basicConstraints \(constraints) is wrong for a \(role.rawValue)"
                }

            case .X509ExtensionID.keyUsage:
                guard ext.critical, !keyUsageSeen else { return "keyUsage is not critical or repeats" }
                keyUsageSeen = true
                guard let usage = try? X509.KeyUsage(ext) else { return "keyUsage is invalid" }
                let others = usage.nonRepudiation || usage.keyEncipherment || usage.dataEncipherment
                    || usage.keyAgreement || usage.encipherOnly || usage.decipherOnly
                switch role {
                case .dac:
                    guard usage.digitalSignature, !usage.keyCertSign, !usage.cRLSign, !others else {
                        return "keyUsage \(usage) is not exactly digitalSignature"
                    }
                case .pai, .paa:
                    guard usage.keyCertSign, usage.cRLSign, !others else {
                        return "keyUsage \(usage) is not keyCertSign and cRLSign"
                    }
                }

            case .X509ExtensionID.subjectKeyIdentifier:
                guard !ext.critical, !subjectKeyIDSeen else { return "subjectKeyIdentifier is critical or repeats" }
                subjectKeyIDSeen = true
                guard let ski = try? SubjectKeyIdentifier(ext), ski.keyIdentifier.count == 20 else {
                    return "subjectKeyIdentifier is not 20 bytes"
                }

            case .X509ExtensionID.authorityKeyIdentifier:
                guard !ext.critical, !authorityKeyIDSeen else { return "authorityKeyIdentifier is critical or repeats" }
                authorityKeyIDSeen = true
                guard let aki = try? AuthorityKeyIdentifier(ext), aki.keyIdentifier?.count == 20 else {
                    return "authorityKeyIdentifier key identifier is not 20 bytes"
                }

            default:
                break
            }
        }

        guard basicConstraintsSeen else { return "has no basicConstraints" }
        guard keyUsageSeen else { return "has no keyUsage" }
        guard subjectKeyIDSeen else { return "has no subjectKeyIdentifier" }
        if role != .paa, !authorityKeyIDSeen { return "has no authorityKeyIdentifier" }
        return nil
    }
}
