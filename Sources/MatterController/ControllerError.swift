// ControllerError.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterCrypto

/// Errors specific to the Matter controller module.
public enum ControllerError: Error, Sendable, Equatable {

    // MARK: - Fabric Management

    /// Failed to generate a root CA certificate.
    case rcacGenerationFailed

    /// Failed to generate a Node Operational Certificate.
    case nocGenerationFailed

    /// Certificate chain validation failed.
    case chainValidationFailed

    // MARK: - Persistence

    /// Stored controller state is present but cannot be trusted (for example an unknown
    /// attestation override reason). The state is not loaded.
    case corruptStoredState(String)

    // MARK: - Commissioning

    /// PASE handshake failed.
    case paseHandshakeFailed(String)

    /// Commissioning step received an unexpected response.
    case unexpectedResponse(String)

    /// The device returned a commissioning error.
    case commissioningFailed(String)

    /// CSR response could not be parsed.
    case invalidCSRResponse

    /// A device attestation exchange could not be completed (for example a
    /// CertificateChainResponse without a certificate).
    case attestationValidationFailed(String)

    /// The device failed attestation. Nothing was committed on the device: its fail-safe was
    /// disarmed and no node ID was consumed. A retry passing the failure's `dacFingerprint` as
    /// `approvingUnverifiedDevice` commissions that device anyway, unless the reason is
    /// `.malformed`.
    case attestationFailed(AttestationFailure)

    /// The attestation trust store could not be loaded when the controller was created.
    case attestationTrustStoreUnavailable(String)

    // MARK: - Operational

    /// CASE session establishment failed.
    case caseSessionFailed(String)

    /// Device not found in the registry.
    case deviceNotFound

    /// No operational address for the device.
    case noOperationalAddress

    /// The device did not acknowledge a request after every MRP
    /// retransmission, or its session closed mid-request. The cached session
    /// has been invalidated; the request was **not** re-sent. The next call
    /// establishes a fresh session.
    case peerUnreachable(NodeID)

    /// The device answered with an Interaction Model StatusResponse instead
    /// of the expected reply; carries the IM status code (e.g. 0x7E
    /// UnsupportedAccess, 0x9C Busy, 0xC6 NeedsTimedInteraction).
    case imStatus(UInt8)

    /// Secure message encoding/decoding failed.
    case secureMessageFailed(String)

    /// Interaction Model error in response.
    case interactionModelError(String)

    // MARK: - Transport & Discovery

    /// UDP transport failure.
    case transportError(String)

    /// mDNS discovery failure.
    case discoveryFailed(String)

    /// The onboarding payload could not be used.
    case invalidSetupCode(String)

    /// No commissionable device matching the setup code was found in time.
    /// The message names the discriminator sought — never an address or passcode.
    case commissionableNotFound(String)

    /// Cached session has expired.
    case sessionExpired

    /// No response received within the deadline.
    case timeout(String)
}
