// ColorControlHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Describes a color change from a Color Control command.
public enum ColorControlChange: Sendable {
    case hue(UInt8)
    case saturation(UInt8)
    case color(x: UInt16, y: UInt16)
    case colorTemperature(UInt16)
}

/// Cluster handler for the Color Control cluster (0x0300).
///
/// Handles MoveToHue, MoveToSaturation, MoveToColor, and MoveToColorTemperature
/// commands. Updates the corresponding attributes and color mode in the
/// `AttributeStore`. Color temperature is clamped to the physical min/max range.
public struct ColorControlHandler: ClusterHandler {

    public let clusterID = ClusterID.colorControl

    /// Physical minimum color temperature in mireds.
    public let physicalMinMireds: UInt16

    /// Physical maximum color temperature in mireds.
    public let physicalMaxMireds: UInt16

    /// Called when the color changes due to a command.
    public var onChange: (@Sendable (ColorControlChange) -> Void)?

    public init(
        physicalMinMireds: UInt16 = 147,
        physicalMaxMireds: UInt16 = 500,
        onChange: (@Sendable (ColorControlChange) -> Void)? = nil
    ) {
        self.physicalMinMireds = physicalMinMireds
        self.physicalMaxMireds = physicalMaxMireds
        self.onChange = onChange
    }

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        [
            (ColorControlCluster.Attribute.currentHue, .unsignedInt(0)),
            (ColorControlCluster.Attribute.currentSaturation, .unsignedInt(0)),
            (ColorControlCluster.Attribute.currentX, .unsignedInt(0)),
            (ColorControlCluster.Attribute.currentY, .unsignedInt(0)),
            (ColorControlCluster.Attribute.colorTemperatureMireds, .unsignedInt(UInt64(physicalMinMireds))),
            (ColorControlCluster.Attribute.colorMode, .unsignedInt(0)),
            (ColorControlCluster.Attribute.enhancedColorMode, .unsignedInt(0)),
            (ColorControlCluster.Attribute.colorTempPhysicalMinMireds, .unsignedInt(UInt64(physicalMinMireds))),
            (ColorControlCluster.Attribute.colorTempPhysicalMaxMireds, .unsignedInt(UInt64(physicalMaxMireds))),
        ]
    }

    public func acceptedCommands() -> [CommandID] {
        [
            ColorControlCluster.Command.moveToHue,
            ColorControlCluster.Command.moveToSaturation,
            ColorControlCluster.Command.moveToColor,
            ColorControlCluster.Command.moveToColorTemperature,
        ]
    }

    public func handleCommand(
        commandID: CommandID,
        fields: TLVElement?,
        store: AttributeStore,
        endpointID: EndpointID
    ) throws -> TLVElement? {
        switch commandID {
        case ColorControlCluster.Command.moveToHue:
            guard let hue = fields?[contextTag: 0]?.uintValue else { return nil }
            let hue8 = UInt8(min(hue, 254))
            store.set(endpoint: endpointID, cluster: clusterID, attribute: ColorControlCluster.Attribute.currentHue, value: .unsignedInt(UInt64(hue8)))
            store.set(endpoint: endpointID, cluster: clusterID, attribute: ColorControlCluster.Attribute.colorMode, value: .unsignedInt(0))
            onChange?(.hue(hue8))

        case ColorControlCluster.Command.moveToSaturation:
            guard let sat = fields?[contextTag: 0]?.uintValue else { return nil }
            let sat8 = UInt8(min(sat, 254))
            store.set(endpoint: endpointID, cluster: clusterID, attribute: ColorControlCluster.Attribute.currentSaturation, value: .unsignedInt(UInt64(sat8)))
            store.set(endpoint: endpointID, cluster: clusterID, attribute: ColorControlCluster.Attribute.colorMode, value: .unsignedInt(0))
            onChange?(.saturation(sat8))

        case ColorControlCluster.Command.moveToColor:
            guard let x = fields?[contextTag: 0]?.uintValue,
                  let y = fields?[contextTag: 1]?.uintValue else { return nil }
            let x16 = UInt16(min(x, UInt64(UInt16.max)))
            let y16 = UInt16(min(y, UInt64(UInt16.max)))
            store.set(endpoint: endpointID, cluster: clusterID, attribute: ColorControlCluster.Attribute.currentX, value: .unsignedInt(UInt64(x16)))
            store.set(endpoint: endpointID, cluster: clusterID, attribute: ColorControlCluster.Attribute.currentY, value: .unsignedInt(UInt64(y16)))
            store.set(endpoint: endpointID, cluster: clusterID, attribute: ColorControlCluster.Attribute.colorMode, value: .unsignedInt(1))
            onChange?(.color(x: x16, y: y16))

        case ColorControlCluster.Command.moveToColorTemperature:
            guard let mireds = fields?[contextTag: 0]?.uintValue else { return nil }
            let clamped = UInt16(min(max(UInt16(min(mireds, UInt64(UInt16.max))), physicalMinMireds), physicalMaxMireds))
            store.set(endpoint: endpointID, cluster: clusterID, attribute: ColorControlCluster.Attribute.colorTemperatureMireds, value: .unsignedInt(UInt64(clamped)))
            store.set(endpoint: endpointID, cluster: clusterID, attribute: ColorControlCluster.Attribute.colorMode, value: .unsignedInt(2))
            onChange?(.colorTemperature(clamped))

        default:
            break
        }
        return nil
    }
}
