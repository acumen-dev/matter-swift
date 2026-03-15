// MatterApple.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(Network)
/// Apple platform transport implementations.
///
/// Provides platform-specific networking using Apple frameworks:
/// - `AppleUDPTransport`: `NWConnection` / `NWListener` for UDP communication
/// - `AppleDiscovery`: `NWBrowser` for mDNS/DNS-SD service browsing and `NWListener` for advertising
/// - CryptoKit integration for SPAKE2+, CASE, AES-CCM via `MatterCrypto`
///
/// This module is only available on Apple platforms (macOS, iOS, tvOS, watchOS, visionOS).

@_exported import MatterTransport
#endif
