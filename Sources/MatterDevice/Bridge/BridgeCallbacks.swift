// BridgeCallbacks.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes

// MARK: - Bridge Callback Types

/// Callback invoked when a Matter controller writes to an attribute.
///
/// The bridge implementation should apply the value to its backing device and
/// return `true` if the write is accepted, or `false` to reject.
///
/// - Parameters:
///   - AttributeID: The attribute being written.
///   - TLVElement: The new value.
/// - Returns: `true` if the write is accepted, `false` to reject.
public typealias AttributeWriteCallback = @Sendable (AttributeID, TLVElement) async -> Bool

/// Callback invoked when a Matter controller sends a command to the cluster.
///
/// The bridge implementation should execute the command on its backing device
/// and return an optional response payload. Throw to indicate a command error.
///
/// - Parameters:
///   - CommandID: The command being invoked.
///   - TLVElement: The command fields (may be an empty structure).
/// - Returns: Optional response TLV payload, or `nil` for status-only response.
public typealias CommandInvokeCallback = @Sendable (CommandID, TLVElement) async throws -> TLVElement?
