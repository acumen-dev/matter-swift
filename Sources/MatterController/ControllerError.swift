// ControllerError.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

/// Errors specific to the Matter controller module.
public enum ControllerError: Error, Sendable, Equatable {

    // MARK: - Fabric Management

    /// Failed to generate a root CA certificate.
    case rcacGenerationFailed

    /// Failed to generate a Node Operational Certificate.
    case nocGenerationFailed

    /// Certificate chain validation failed.
    case chainValidationFailed

    // MARK: - Commissioning

    /// PASE handshake failed.
    case paseHandshakeFailed(String)

    /// Commissioning step received an unexpected response.
    case unexpectedResponse(String)

    /// The device returned a commissioning error.
    case commissioningFailed(String)

    /// CSR response could not be parsed.
    case invalidCSRResponse

    /// Device attestation validation failed (nonce mismatch, invalid signature, etc.).
    case attestationValidationFailed(String)

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
