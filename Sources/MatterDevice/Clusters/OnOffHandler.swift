// OnOffHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Cluster handler for the On/Off cluster (0x0006).
///
/// Handles On, Off, and Toggle commands by updating the `onOff` attribute
/// in the `AttributeStore`. An optional `onChange` callback notifies the
/// application when the on/off state changes.
public struct OnOffHandler: ClusterHandler {

    public let clusterID = ClusterID.onOff

    /// Called when the on/off state changes due to a command.
    public var onChange: (@Sendable (Bool) -> Void)?

    public init(onChange: (@Sendable (Bool) -> Void)? = nil) {
        self.onChange = onChange
    }

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        [
            (OnOffCluster.Attribute.onOff, .bool(false)),
        ]
    }

    public func acceptedCommands() -> [CommandID] {
        [OnOffCluster.Command.off, OnOffCluster.Command.on, OnOffCluster.Command.toggle]
    }

    public func handleCommand(
        commandID: CommandID,
        fields: TLVElement?,
        store: AttributeStore,
        endpointID: EndpointID
    ) throws -> TLVElement? {
        switch commandID {
        case OnOffCluster.Command.off:
            store.set(endpoint: endpointID, cluster: clusterID, attribute: OnOffCluster.Attribute.onOff, value: .bool(false))
            // Always mark dirty so subscription reports confirm the command,
            // even when the value was already false (no-op write).
            store.markDirty(endpoint: endpointID, cluster: clusterID, attribute: OnOffCluster.Attribute.onOff)
            onChange?(false)

        case OnOffCluster.Command.on:
            store.set(endpoint: endpointID, cluster: clusterID, attribute: OnOffCluster.Attribute.onOff, value: .bool(true))
            store.markDirty(endpoint: endpointID, cluster: clusterID, attribute: OnOffCluster.Attribute.onOff)
            onChange?(true)

        case OnOffCluster.Command.toggle:
            let current = store.get(endpoint: endpointID, cluster: clusterID, attribute: OnOffCluster.Attribute.onOff)
            let isOn = current?.boolValue ?? false
            store.set(endpoint: endpointID, cluster: clusterID, attribute: OnOffCluster.Attribute.onOff, value: .bool(!isOn))
            store.markDirty(endpoint: endpointID, cluster: clusterID, attribute: OnOffCluster.Attribute.onOff)
            onChange?(!isOn)

        default:
            break
        }
        return nil
    }

    public func validateWrite(attributeID: AttributeID, value: TLVElement) -> WriteValidation {
        if attributeID == OnOffCluster.Attribute.onOff, value.boolValue != nil {
            return .allowed
        }
        return .unsupportedWrite
    }

    // MARK: - Event Generation

    /// Generate a StateChange event for on/off/toggle commands.
    ///
    /// The event payload is a structure containing the new on/off state (tag 0).
    public func generatedEvents(commandID: CommandID, endpointID: EndpointID, store: AttributeStore) -> [ClusterEvent] {
        switch commandID {
        case OnOffCluster.Command.off, OnOffCluster.Command.on, OnOffCluster.Command.toggle:
            let isOn = store.get(endpoint: endpointID, cluster: clusterID, attribute: OnOffCluster.Attribute.onOff)?.boolValue ?? false
            let data = TLVElement.structure([
                TLVElement.TLVField(tag: .contextSpecific(0), value: .bool(isOn))
            ])
            return [ClusterEvent(
                eventID: OnOffCluster.Event.stateChange,
                priority: .info,
                data: data,
                isUrgent: false
            )]
        default:
            return []
        }
    }
}
