// MatterController.swift
// Copyright 2026 Monagle Pty Ltd

/// Matter controller role implementation.
///
/// This module provides:
/// - Device commissioning (discover, PASE, provision, NOC issuance)
/// - Operational communication (CASE sessions to commissioned devices)
/// - Read/write/subscribe/invoke as a client
/// - Device management (track commissioned devices, session resumption)
///
/// High-level API:
/// ```swift
/// let controller = MatterController(config: .init(
///     fabricId: myFabricId,
///     rootCA: myRootCert
/// ))
///
/// let device = try await controller.commission(
///     discoveredDevice,
///     setupCode: "34970112332"
/// )
///
/// let isOn = try await device.read(\.onOff.onOff)
/// try await device.write(\.onOff.onOff, value: true)
/// try await device.subscribe(\.levelControl.currentLevel) { newLevel in
///     print("Level changed to \(newLevel)")
/// }
/// ```

// Placeholder — will be implemented in Phase 5
