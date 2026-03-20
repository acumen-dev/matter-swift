// IdentifyHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Cluster handler for the Identify cluster (0x0003).
///
/// Manages device identification state. The `identifyTime` attribute counts
/// down while the device is identifying. `identifyType` indicates the
/// identification method (e.g., VisibleIndicator = 2).
public struct IdentifyHandler: ClusterHandler {

    public let clusterID = ClusterID.identify

    public init() {}

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        [
            (IdentifyCluster.Attribute.identifyTime, .unsignedInt(0)),
            (IdentifyCluster.Attribute.identifyType, .unsignedInt(2)), // VisibleIndicator
        ]
    }

    public func acceptedCommands() -> [CommandID] {
        [IdentifyCluster.Command.identify, IdentifyCluster.Command.triggerEffect]
    }

    public func generatedCommands() -> [CommandID] {
        []
    }

    public func handleCommand(
        commandID: CommandID,
        fields: TLVElement?,
        store: AttributeStore,
        endpointID: EndpointID
    ) throws -> TLVElement? {
        switch commandID {

        // MARK: Identify (0x00) — set identifyTime from field tag 0
        case IdentifyCluster.Command.identify:
            let time: UInt64
            if let fields,
               case .structure(let structFields) = fields,
               let timeValue = structFields.first(where: { $0.tag == .contextSpecific(0) })?.value.uintValue {
                time = timeValue
            } else {
                time = 0
            }
            store.set(
                endpoint: endpointID,
                cluster: clusterID,
                attribute: IdentifyCluster.Attribute.identifyTime,
                value: .unsignedInt(time)
            )
            return nil

        // MARK: TriggerEffect (0x40)
        case IdentifyCluster.Command.triggerEffect:
            // Accept but no-op for now
            return nil

        default:
            return nil
        }
    }

    public func validateWrite(attributeID: AttributeID, value: TLVElement) -> WriteValidation {
        switch attributeID {
        case IdentifyCluster.Attribute.identifyTime:
            guard value.uintValue != nil else { return .constraintError }
            return .allowed
        default:
            return .unsupportedWrite
        }
    }
}
