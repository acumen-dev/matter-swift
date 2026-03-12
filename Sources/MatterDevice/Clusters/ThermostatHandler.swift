// ThermostatHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Describes a thermostat change from a command or write.
public enum ThermostatChange: Sendable {
    case heatingSetpoint(Int16)
    case coolingSetpoint(Int16)
    case systemMode(UInt8)
}

/// Cluster handler for the Thermostat cluster (0x0201).
///
/// Handles the SetpointRaiseLower command and writable attributes for
/// system mode and setpoints. Temperatures are in 0.01°C units.
public struct ThermostatHandler: ClusterHandler {

    public let clusterID = ClusterID.thermostat

    /// Called when a thermostat setting changes.
    public var onChange: (@Sendable (ThermostatChange) -> Void)?

    public init(onChange: (@Sendable (ThermostatChange) -> Void)? = nil) {
        self.onChange = onChange
    }

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        [
            (ThermostatCluster.Attribute.localTemperature, .signedInt(2000)),         // 20.00°C
            (ThermostatCluster.Attribute.occupiedHeatingSetpoint, .signedInt(2000)),   // 20.00°C
            (ThermostatCluster.Attribute.occupiedCoolingSetpoint, .signedInt(2600)),   // 26.00°C
            (ThermostatCluster.Attribute.systemMode, .unsignedInt(1)),                 // Auto
            (ThermostatCluster.Attribute.controlSequenceOfOperation, .unsignedInt(4)), // Heating + Cooling
        ]
    }

    public func handleCommand(
        commandID: CommandID,
        fields: TLVElement?,
        store: AttributeStore,
        endpointID: EndpointID
    ) throws -> TLVElement? {
        if commandID == ThermostatCluster.Command.setpointRaiseLower {
            guard let fields = fields,
                  let mode = fields[contextTag: 0]?.uintValue,
                  let amount = fields[contextTag: 1]?.intValue else {
                return nil
            }

            let delta = Int64(amount) * 10 // amount is in 0.1°C steps

            // Mode: 0=Heat, 1=Cool, 2=Both
            if mode == 0 || mode == 2 {
                let current = store.get(endpoint: endpointID, cluster: clusterID, attribute: ThermostatCluster.Attribute.occupiedHeatingSetpoint)?.intValue ?? 2000
                let newValue = Int16(clamping: current + delta)
                store.set(endpoint: endpointID, cluster: clusterID, attribute: ThermostatCluster.Attribute.occupiedHeatingSetpoint, value: .signedInt(Int64(newValue)))
                onChange?(.heatingSetpoint(newValue))
            }
            if mode == 1 || mode == 2 {
                let current = store.get(endpoint: endpointID, cluster: clusterID, attribute: ThermostatCluster.Attribute.occupiedCoolingSetpoint)?.intValue ?? 2600
                let newValue = Int16(clamping: current + delta)
                store.set(endpoint: endpointID, cluster: clusterID, attribute: ThermostatCluster.Attribute.occupiedCoolingSetpoint, value: .signedInt(Int64(newValue)))
                onChange?(.coolingSetpoint(newValue))
            }
        }
        return nil
    }

    public func validateWrite(attributeID: AttributeID, value: TLVElement) -> WriteValidation {
        switch attributeID {
        case ThermostatCluster.Attribute.systemMode:
            if value.uintValue != nil { return .allowed }
            return .constraintError
        case ThermostatCluster.Attribute.occupiedHeatingSetpoint,
             ThermostatCluster.Attribute.occupiedCoolingSetpoint:
            if value.intValue != nil { return .allowed }
            return .constraintError
        default:
            return .unsupportedWrite
        }
    }
}
