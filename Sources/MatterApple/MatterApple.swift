// MatterApple.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(Network)
/// Apple platform transport implementations.
///
/// Provides platform-specific networking using Apple frameworks:
/// - `AppleUDPTransport`: `NWConnection` / `NWListener` for UDP communication
/// - `AppleDiscovery`: `NWBrowser` for mDNS/DNS-SD service browsing and
///   `DNSServiceRegister` for advertising (re-exported from `MDNSApple` as `AppleServiceDiscovery`)
/// - CryptoKit integration for SPAKE2+, CASE, AES-CCM via `MatterCrypto`
///
/// This module is only available on Apple platforms (macOS, iOS, tvOS, watchOS, visionOS).

@_exported import MatterTransport
@_exported import MDNSApple

/// Apple mDNS/DNS-SD discovery — alias for `AppleServiceDiscovery` from MDNSApple.
public typealias AppleDiscovery = AppleServiceDiscovery

/// Discovery error — alias for `ServiceDiscoveryError` from MDNSCore.
public typealias DiscoveryError = ServiceDiscoveryError
#endif
