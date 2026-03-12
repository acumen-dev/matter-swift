// LevelControlHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Cluster handler for the Level Control cluster (0x0008).
///
/// Handles MoveToLevel and MoveToLevelWithOnOff commands by updating
/// the `currentLevel` attribute in the `AttributeStore`. The level is
/// clamped to the configured min/max range.
public struct LevelControlHandler: ClusterHandler {

    public let clusterID = ClusterID.levelControl

    /// Minimum supported level (default 1).
    public let minLevel: UInt8

    /// Maximum supported level (default 254).
    public let maxLevel: UInt8

    /// Called when the level changes due to a command.
    public var onChange: (@Sendable (UInt8) -> Void)?

    public init(minLevel: UInt8 = 1, maxLevel: UInt8 = 254, onChange: (@Sendable (UInt8) -> Void)? = nil) {
        self.minLevel = minLevel
        self.maxLevel = maxLevel
        self.onChange = onChange
    }

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        [
            (LevelControlCluster.Attribute.currentLevel, .unsignedInt(UInt64(minLevel))),
            (LevelControlCluster.Attribute.minLevel, .unsignedInt(UInt64(minLevel))),
            (LevelControlCluster.Attribute.maxLevel, .unsignedInt(UInt64(maxLevel))),
        ]
    }

    public func handleCommand(
        commandID: CommandID,
        fields: TLVElement?,
        store: AttributeStore,
        endpointID: EndpointID
    ) throws -> TLVElement? {
        // MoveToLevel and MoveToLevelWithOnOff: tag 0 = level (uint8)
        if commandID == LevelControlCluster.Command.moveToLevel
            || commandID == LevelControlCluster.Command.moveToLevelWithOnOff
        {
            guard let fields = fields,
                  let levelValue = fields[contextTag: 0]?.uintValue else {
                return nil
            }
            let clamped = min(max(UInt8(levelValue), minLevel), maxLevel)
            store.set(
                endpoint: endpointID,
                cluster: clusterID,
                attribute: LevelControlCluster.Attribute.currentLevel,
                value: .unsignedInt(UInt64(clamped))
            )
            onChange?(clamped)
        }
        return nil
    }

    public func validateWrite(attributeID: AttributeID, value: TLVElement) -> WriteValidation {
        if attributeID == LevelControlCluster.Attribute.currentLevel, value.uintValue != nil {
            return .allowed
        }
        return .unsupportedWrite
    }
}
