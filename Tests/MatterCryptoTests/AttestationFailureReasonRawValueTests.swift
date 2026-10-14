// AttestationFailureReasonRawValueTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
@testable import MatterCrypto

@Suite("AttestationFailureReason raw values")
struct AttestationFailureReasonRawValueTests {

    /// A raw value is a persistence format (a stored attestation override records it).
    /// Changing any of these strings strands stored state.
    static let pinned: [(AttestationFailureReason, String)] = [
        (.untrustedRoot, "untrustedRoot"),
        (.chainInvalid, "chainInvalid"),
        (.certificateExpired, "certificateExpired"),
        (.vidPidMismatch, "vidPidMismatch"),
        (.cdSignatureInvalid, "cdSignatureInvalid"),
        (.cdUnknownSigningKey, "cdUnknownSigningKey"),
        (.cdVidPidNotListed, "cdVidPidNotListed"),
        (.cdPAANotAuthorized, "cdPAANotAuthorized"),
        (.attestationSignatureInvalid, "attestationSignatureInvalid"),
        (.nonceMismatch, "nonceMismatch"),
        (.malformed, "malformed"),
    ]

    @Test("every case's raw value is pinned")
    func pinnedRawValues() {
        for (reason, raw) in Self.pinned {
            #expect(reason.rawValue == raw)
            #expect(AttestationFailureReason(rawValue: raw) == reason)
        }
        // A new case must be added to `pinned`, AND adding a case requires bumping
        // StoredControllerState.currentSchemaVersion so older libraries refuse the new state.
        #expect(Self.pinned.count == AttestationFailureReason.allCases.count)
        #expect(Set(Self.pinned.map(\.0)) == Set(AttestationFailureReason.allCases))
    }
}
