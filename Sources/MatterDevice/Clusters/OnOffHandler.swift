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

    public func handleCommand(
        commandID: CommandID,
        fields: TLVElement?,
        store: AttributeStore,
        endpointID: EndpointID
    ) throws -> TLVElement? {
        switch commandID {
        case OnOffCluster.Command.off:
            store.set(endpoint: endpointID, cluster: clusterID, attribute: OnOffCluster.Attribute.onOff, value: .bool(false))
            onChange?(false)

        case OnOffCluster.Command.on:
            store.set(endpoint: endpointID, cluster: clusterID, attribute: OnOffCluster.Attribute.onOff, value: .bool(true))
            onChange?(true)

        case OnOffCluster.Command.toggle:
            let current = store.get(endpoint: endpointID, cluster: clusterID, attribute: OnOffCluster.Attribute.onOff)
            let isOn = current?.boolValue ?? false
            store.set(endpoint: endpointID, cluster: clusterID, attribute: OnOffCluster.Attribute.onOff, value: .bool(!isOn))
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
}
