// StoredAttestationRecord.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

/// How a commissioned device passed device attestation, serialized for persistence.
///
/// Mirrors `DeviceAttestationRecord` in MatterController using plain values, so
/// MatterTypes does not depend on MatterCrypto. The `reason` of an override is the
/// `rawValue` of `AttestationFailureReason`, which is a persistence format: raw
/// values are explicit and pinned by a test.
public enum StoredAttestationRecord: Codable, Sendable, Equatable {

    /// The attestation chain verified against a trusted PAA.
    case verified(paaSubject: String, vendorID: UInt16, productID: UInt16)

    /// Attestation failed and a caller approved commissioning anyway.
    ///
    /// - `dacFingerprint`: SHA-256 of the DAC DER the approval applies to.
    /// - `reason`: `AttestationFailureReason.rawValue` of the failure that was overridden.
    /// - `approvedAt`: when the override was approved.
    case overridden(dacFingerprint: Data, reason: String, approvedAt: Date)
}
