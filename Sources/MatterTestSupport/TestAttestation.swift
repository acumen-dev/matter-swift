// TestAttestation.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterCrypto

// MARK: - TestAttestation

/// Trust stores for tests, so a harness states which attestation roots it trusts rather than
/// relying on a global switch.
public enum TestAttestation {

    /// The store that trusts exactly the chain and CD signer of `creds`: its PAA, and its
    /// dedicated CD signing key.
    public static func trustStore(for creds: DeviceAttestationCredentials) throws -> AttestationTrustStore {
        try AttestationTrustStore(
            paas: [creds.paaCertificate],
            cdSigningKeys: [try CDSigningKey(certificateDER: creds.cdSigningCertificate)],
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
