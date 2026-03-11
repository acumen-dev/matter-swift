// SwiftMatter.swift
// Copyright 2026 Monagle Pty Ltd

/// Convenience re-export of all SwiftMatter modules.
///
/// Import `SwiftMatter` for access to the full library.
/// For finer-grained control, import individual modules:
/// - `MatterTypes` — core types, TLV, identifiers
/// - `MatterModel` — cluster definitions, device types
/// - `MatterCrypto` — cryptographic operations
/// - `MatterProtocol` — wire protocol, sessions, Interaction Model
/// - `MatterDevice` — device/bridge role
/// - `MatterController` — controller role
/// - `MatterTransport` — platform-agnostic transport abstractions
/// - `MatterApple` — Apple platform transport
@_exported import MatterTypes
@_exported import MatterModel
@_exported import MatterCrypto
@_exported import MatterProtocol
@_exported import MatterDevice
@_exported import MatterController
@_exported import MatterTransport
@_exported import MatterApple
