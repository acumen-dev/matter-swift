// MatterLinux.swift
// Copyright 2026 Monagle Pty Ltd

/// Linux platform transport implementations using SwiftNIO.
///
/// Provides platform-specific networking for Linux deployments:
/// - `LinuxUDPTransport`: SwiftNIO `DatagramBootstrap` for UDP communication
/// - `LinuxDiscovery`: Pure-Swift mDNS responder (RFC 6762) for DNS-SD service discovery
///
/// Usage:
/// ```swift
/// let transport = LinuxUDPTransport()
/// let discovery = LinuxDiscovery()
/// try await transport.bind(port: 5540)
/// try await discovery.advertise(service: record)
/// ```

@_exported import MatterTransport
