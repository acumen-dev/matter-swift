// ClusterHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

/// Protocol for cluster-specific logic.
///
/// Each cluster implementation provides attribute defaults, command handling,
/// and attribute write validation. The device/bridge runtime calls these methods
/// when processing Interaction Model requests.
public protocol ClusterHandler: Sendable {

    /// The cluster this handler manages.
    var clusterID: ClusterID { get }

    /// Initial attribute values for this cluster.
    ///
    /// Called once when the endpoint is registered. The returned values are
    /// written into the `AttributeStore` as the starting state.
    func initialAttributes() -> [(AttributeID, TLVElement)]

    /// Handle an incoming command. Returns optional response payload.
    ///
    /// The handler may mutate the `AttributeStore` as a side effect (e.g., On/Off toggle).
    /// Return `nil` for commands that produce no response payload (status-only).
    func handleCommand(
        commandID: CommandID,
        fields: TLVElement?,
        store: AttributeStore,
        endpointID: EndpointID
    ) throws -> TLVElement?

    /// Validate a write to an attribute. Returns `.allowed` on success, `.rejected` on failure.
    ///
    /// Called before the value is written to the `AttributeStore`. If the handler returns
    /// `.rejected`, the write is refused and the status is reported to the client.
    func validateWrite(attributeID: AttributeID, value: TLVElement) -> WriteValidation
}

// MARK: - Default Implementations

extension ClusterHandler {

    /// Default: no commands handled.
    public func handleCommand(
        commandID: CommandID,
        fields: TLVElement?,
        store: AttributeStore,
        endpointID: EndpointID
    ) throws -> TLVElement? {
        nil
    }

    /// Default: all writes rejected (read-only cluster).
    public func validateWrite(attributeID: AttributeID, value: TLVElement) -> WriteValidation {
        .unsupportedWrite
    }
}

// MARK: - Write Validation

/// Result of write validation.
public enum WriteValidation: Sendable, Equatable {
    case allowed
    case rejected(status: UInt8)

    /// The attribute does not support writes.
    public static let unsupportedWrite = WriteValidation.rejected(status: 0x88)

    /// The value violates a constraint (range, length, etc.).
    public static let constraintError = WriteValidation.rejected(status: 0x87)
}
