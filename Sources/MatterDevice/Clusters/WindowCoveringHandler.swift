// WindowCoveringHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Describes a window covering command action.
public enum WindowCoveringCommand: Sendable {
    case upOrOpen
    case downOrClose
    case stop
    case goToLiftPercentage(UInt16)
}

/// Cluster handler for the Window Covering cluster (0x0102).
///
/// Handles UpOrOpen, DownOrClose, StopMotion, and GoToLiftPercentage commands.
/// Position values are in 0.01% units (0 = fully open, 10000 = fully closed).
public struct WindowCoveringHandler: ClusterHandler {

    public let clusterID = ClusterID.windowCovering

    /// Called when a window covering command is executed.
    public var onChange: (@Sendable (WindowCoveringCommand) -> Void)?

    public init(onChange: (@Sendable (WindowCoveringCommand) -> Void)? = nil) {
        self.onChange = onChange
    }

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        [
            (WindowCoveringCluster.Attribute.type, .unsignedInt(0)),                              // Rollershade
            (WindowCoveringCluster.Attribute.currentPositionLiftPercent100ths, .unsignedInt(0)),   // Fully open
            (WindowCoveringCluster.Attribute.targetPositionLiftPercent100ths, .unsignedInt(0)),    // Fully open
            (WindowCoveringCluster.Attribute.operationalStatus, .unsignedInt(0)),                  // Stopped
        ]
    }

    public func acceptedCommands() -> [CommandID] {
        [
            WindowCoveringCluster.Command.upOrOpen,
            WindowCoveringCluster.Command.downOrClose,
            WindowCoveringCluster.Command.stopMotion,
            WindowCoveringCluster.Command.goToLiftPercentage,
        ]
    }

    public func handleCommand(
        commandID: CommandID,
        fields: TLVElement?,
        store: AttributeStore,
        endpointID: EndpointID
    ) throws -> TLVElement? {
        switch commandID {
        case WindowCoveringCluster.Command.upOrOpen:
            store.set(endpoint: endpointID, cluster: clusterID, attribute: WindowCoveringCluster.Attribute.targetPositionLiftPercent100ths, value: .unsignedInt(0))
            store.set(endpoint: endpointID, cluster: clusterID, attribute: WindowCoveringCluster.Attribute.currentPositionLiftPercent100ths, value: .unsignedInt(0))
            onChange?(.upOrOpen)

        case WindowCoveringCluster.Command.downOrClose:
            store.set(endpoint: endpointID, cluster: clusterID, attribute: WindowCoveringCluster.Attribute.targetPositionLiftPercent100ths, value: .unsignedInt(10000))
            store.set(endpoint: endpointID, cluster: clusterID, attribute: WindowCoveringCluster.Attribute.currentPositionLiftPercent100ths, value: .unsignedInt(10000))
            onChange?(.downOrClose)

        case WindowCoveringCluster.Command.stopMotion:
            onChange?(.stop)

        case WindowCoveringCluster.Command.goToLiftPercentage:
            guard let percent = fields?[contextTag: 0]?.uintValue else { return nil }
            let clamped = UInt16(min(max(percent, 0), 10000))
            store.set(endpoint: endpointID, cluster: clusterID, attribute: WindowCoveringCluster.Attribute.targetPositionLiftPercent100ths, value: .unsignedInt(UInt64(clamped)))
            store.set(endpoint: endpointID, cluster: clusterID, attribute: WindowCoveringCluster.Attribute.currentPositionLiftPercent100ths, value: .unsignedInt(UInt64(clamped)))
            onChange?(.goToLiftPercentage(clamped))

        default:
            break
        }
        return nil
    }
}
