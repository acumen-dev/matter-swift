// TestAttestation.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterCrypto

// MARK: - TestAttestationError

public enum TestAttestationError: Error, Sendable, Equatable, CustomStringConvertible {
    /// The credentials carry no CD signing certificate, so there is no CD key to trust.
    case noCDSigningCertificate

    public var description: String {
        "the credentials have no cdSigningCertificate, so a trust store for them has no CD signing key"
    }
}

// MARK: - TestAttestation

/// Trust stores for tests, so a harness states which attestation roots it trusts rather than
/// relying on a global switch.
public enum TestAttestation {

    /// The store that trusts exactly the chain and CD signer of `creds`: its PAA, and its
    /// dedicated CD signing key.
    ///
    /// - Throws: ``TestAttestationError/noCDSigningCertificate`` if `creds` has no
    ///   `cdSigningCertificate`.
    public static func trustStore(for creds: DeviceAttestationCredentials) throws -> AttestationTrustStore {
        guard let cdSigningCertificate = creds.cdSigningCertificate else {
            throw TestAttestationError.noCDSigningCertificate
        }
        return try AttestationTrustStore(
            paas: [creds.paaCertificate],
            cdSigningKeys: [try CDSigningKey(certificateDER: cdSigningCertificate)],
            provenance: TrustStoreProvenance(source: "test:credentials"))
    }

    /// The store that trusts what connectedhomeip's example apps present: the Chip test PAA for
    /// VID 0xFFF1, the Chip test CD signing key, and CSA production CD signing key 001 (which
    /// signs the CD the example apps compile in).
    public static func chipDevelopmentTrustStore() throws -> AttestationTrustStore {
        try AttestationTrustStore(
            paas: [try AttestationFixtures.testPAA],
            cdSigningKeys: [
                try CDSigningKey(certificateDER: try AttestationFixtures.testCDSigningCert),
                try CDSigningKey(certificateDER: try AttestationFixtures.productionCDSigningCerts[0]),
            ],
            provenance: TrustStoreProvenance(source: "test:chip-development"))
    }
}
