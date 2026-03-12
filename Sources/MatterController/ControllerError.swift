// ControllerError.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

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

    // MARK: - Operational

    /// CASE session establishment failed.
    case caseSessionFailed(String)

    /// Device not found in the registry.
    case deviceNotFound

    /// No operational address for the device.
    case noOperationalAddress

    /// Secure message encoding/decoding failed.
    case secureMessageFailed(String)

    /// Interaction Model error in response.
    case interactionModelError(String)

    // MARK: - Transport & Discovery

    /// UDP transport failure.
    case transportError(String)

    /// mDNS discovery failure.
    case discoveryFailed(String)

    /// Cached session has expired.
    case sessionExpired

    /// No response received within the deadline.
    case timeout(String)
}
