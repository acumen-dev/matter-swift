// ClusterHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterProtocol

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

    /// Returns `true` if the given attribute is fabric-scoped.
    ///
    /// Fabric-scoped attributes (e.g. ACLs, NOCs, fabrics list) are filtered in read/subscribe
    /// responses to only include entries belonging to the requesting fabric when
    /// `isFabricFiltered` is `true`.
    func isFabricScoped(attributeID: AttributeID) -> Bool

    /// Filter a fabric-scoped attribute value to only include entries for the specified fabric.
    ///
    /// Called during read/subscribe when `isFabricFiltered` is `true` and `isFabricScoped`
    /// returns `true` for the attribute. The default implementation returns `value` unchanged.
    func filterFabricScopedAttribute(attributeID: AttributeID, value: TLVElement, fabricIndex: FabricIndex) -> TLVElement

    /// Returns `true` if the given command requires a timed interaction.
    ///
    /// Security-sensitive commands (e.g., DoorLock lock/unlock, AdminCommissioning open window)
    /// must be preceded by a `TimedRequest` message that establishes a timeout window.
    /// If a client sends such a command without a preceding `TimedRequest`, the server
    /// returns `needsTimedInteraction` (0xC6).
    func requiresTimedInteraction(commandID: CommandID) -> Bool

    /// Return events generated as a side-effect of a command.
    ///
    /// Called after `handleCommand` returns. The returned events are recorded in the
    /// node's `EventStore` and used to notify active subscriptions.
    ///
    /// - Parameters:
    ///   - commandID: The command that was executed.
    ///   - endpointID: The endpoint on which the command was executed.
    ///   - store: The attribute store after the command has been applied.
    /// - Returns: Zero or more events to be recorded. Default: `[]`.
    func generatedEvents(commandID: CommandID, endpointID: EndpointID, store: AttributeStore) -> [ClusterEvent]
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

    /// Default: attribute is not fabric-scoped.
    public func isFabricScoped(attributeID: AttributeID) -> Bool {
        false
    }

    /// Default: return value unchanged (no filtering needed).
    public func filterFabricScopedAttribute(attributeID: AttributeID, value: TLVElement, fabricIndex: FabricIndex) -> TLVElement {
        value
    }

    /// Default: command does not require a timed interaction.
    public func requiresTimedInteraction(commandID: CommandID) -> Bool {
        false
    }

    /// Default: no events generated.
    public func generatedEvents(commandID: CommandID, endpointID: EndpointID, store: AttributeStore) -> [ClusterEvent] {
        []
    }
}

// MARK: - Cluster Event

/// An event produced by a cluster handler as a side-effect of a command.
public struct ClusterEvent: Sendable {
    public let eventID: EventID
    public let priority: EventPriority
    public let data: TLVElement?
    public let isUrgent: Bool

    public init(
        eventID: EventID,
        priority: EventPriority,
        data: TLVElement? = nil,
        isUrgent: Bool = false
    ) {
        self.eventID = eventID
        self.priority = priority
        self.data = data
        self.isUrgent = isUrgent
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
