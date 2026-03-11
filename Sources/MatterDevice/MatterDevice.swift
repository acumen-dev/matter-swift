// MatterDevice.swift
// Copyright 2026 Monagle Pty Ltd

/// Matter device/bridge role implementation.
///
/// This module provides:
/// - Dynamic endpoint management (add/remove bridged devices at runtime)
/// - Attribute storage with change tracking for subscription reports
/// - Command handling (route incoming commands to registered handlers)
/// - Subscription management (per-fabric, min/max intervals)
/// - Bridge device type (Aggregator with PartsList management)
/// - Commissioning responder (handle PASE sessions)
///
/// High-level API:
/// ```swift
/// let bridge = MatterBridge(config: .init(
///     vendorId: 0xFFF1, productId: 0x8000,
///     discriminator: 3840, passcode: 20202021
/// ))
///
/// let light = bridge.addEndpoint(.dimmableLight, name: "Kitchen Pendant")
/// light.onOff.onWrite { newValue in /* handle toggle from Apple Home */ }
/// light.levelControl.currentLevel = 200
///
/// try await bridge.start()
/// ```

// Placeholder — will be implemented in Phase 4
