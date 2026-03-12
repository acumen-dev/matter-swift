// FanControlHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Describes a fan control change from an attribute write.
public enum FanControlChange: Sendable {
    case fanMode(UInt8)
    case percentSetting(UInt8)
    case speedSetting(UInt8)
}

/// Cluster handler for the Fan Control cluster (0x0202).
///
/// Fan control has no commands — all control is via writable attributes
/// (fanMode, percentSetting, speedSetting). Read-only attributes
/// (percentCurrent, speedCurrent, speedMax) reject writes.
public struct FanControlHandler: ClusterHandler {

    public let clusterID = ClusterID.fanControl

    /// Maximum speed level.
    public let speedMax: UInt8

    /// Called when a writable fan attribute changes.
    public var onChange: (@Sendable (FanControlChange) -> Void)?

    public init(speedMax: UInt8 = 10, onChange: (@Sendable (FanControlChange) -> Void)? = nil) {
        self.speedMax = speedMax
        self.onChange = onChange
    }

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        [
            (FanControlCluster.Attribute.fanMode, .unsignedInt(0)),              // Off
            (FanControlCluster.Attribute.percentSetting, .unsignedInt(0)),
            (FanControlCluster.Attribute.percentCurrent, .unsignedInt(0)),
            (FanControlCluster.Attribute.speedMax, .unsignedInt(UInt64(speedMax))),
            (FanControlCluster.Attribute.speedSetting, .unsignedInt(0)),
            (FanControlCluster.Attribute.speedCurrent, .unsignedInt(0)),
        ]
    }

    public func validateWrite(attributeID: AttributeID, value: TLVElement) -> WriteValidation {
        switch attributeID {
        case FanControlCluster.Attribute.fanMode:
            guard let v = value.uintValue, v <= 5 else { return .constraintError }
            return .allowed

        case FanControlCluster.Attribute.percentSetting:
            guard let v = value.uintValue, v <= 100 else { return .constraintError }
            return .allowed

        case FanControlCluster.Attribute.speedSetting:
            guard let v = value.uintValue, v <= UInt64(speedMax) else { return .constraintError }
            return .allowed

        case FanControlCluster.Attribute.percentCurrent,
             FanControlCluster.Attribute.speedCurrent,
             FanControlCluster.Attribute.speedMax:
            return .unsupportedWrite

        default:
            return .unsupportedWrite
        }
    }
}
