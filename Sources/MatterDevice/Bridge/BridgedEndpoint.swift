// BridgedEndpoint.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel
import MatterProtocol

/// A handle to a bridged endpoint within a `MatterBridge`.
///
/// Provides bridge-side setters for common attributes (on/off, level, reachable).
/// Writes via this handle update the `AttributeStore` and notify the
/// `SubscriptionManager` of dirty paths so active subscriptions get reports.
///
/// ```swift
/// let light = bridge.addDimmableLight(name: "Kitchen Pendant")
/// light.setOnOff(true)
/// light.setLevel(200)
/// light.setReachable(false)
/// ```
public final class BridgedEndpoint: @unchecked Sendable {

    /// The endpoint ID of this bridged device.
    public let endpointID: EndpointID

    /// The display name of this bridged device.
    public let name: String

    private let store: AttributeStore
    private let subscriptions: SubscriptionManager

    init(
        endpointID: EndpointID,
        name: String,
        store: AttributeStore,
        subscriptions: SubscriptionManager
    ) {
        self.endpointID = endpointID
        self.name = name
        self.store = store
        self.subscriptions = subscriptions
    }

    // MARK: - OnOff

    /// Set the on/off state from the bridge side.
    public func setOnOff(_ value: Bool) async {
        let changed = store.set(
            endpoint: endpointID,
            cluster: .onOff,
            attribute: OnOffCluster.Attribute.onOff,
            value: .bool(value)
        )
        if changed {
            await notifyChange(cluster: .onOff, attribute: OnOffCluster.Attribute.onOff)
        }
    }

    // MARK: - Level Control

    /// Set the current level from the bridge side.
    public func setLevel(_ value: UInt8) async {
        let changed = store.set(
            endpoint: endpointID,
            cluster: .levelControl,
            attribute: LevelControlCluster.Attribute.currentLevel,
            value: .unsignedInt(UInt64(value))
        )
        if changed {
            await notifyChange(cluster: .levelControl, attribute: LevelControlCluster.Attribute.currentLevel)
        }
    }

    // MARK: - Bridged Device Basic Information

    /// Set the reachable state from the bridge side.
    public func setReachable(_ value: Bool) async {
        let changed = store.set(
            endpoint: endpointID,
            cluster: .bridgedDeviceBasicInformation,
            attribute: BridgedDeviceBasicInfoCluster.Attribute.reachable,
            value: .bool(value)
        )
        if changed {
            await notifyChange(cluster: .bridgedDeviceBasicInformation, attribute: BridgedDeviceBasicInfoCluster.Attribute.reachable)
        }
    }

    // MARK: - Color Control

    /// Set the color temperature in mireds from the bridge side.
    public func setColorTemperature(_ mireds: UInt16) async {
        let changed = store.set(
            endpoint: endpointID,
            cluster: .colorControl,
            attribute: ColorControlCluster.Attribute.colorTemperatureMireds,
            value: .unsignedInt(UInt64(mireds))
        )
        if changed {
            store.set(
                endpoint: endpointID,
                cluster: .colorControl,
                attribute: ColorControlCluster.Attribute.colorMode,
                value: .unsignedInt(2)
            )
            await notifyChange(cluster: .colorControl, attribute: ColorControlCluster.Attribute.colorTemperatureMireds)
        }
    }

    /// Set the hue from the bridge side.
    public func setHue(_ hue: UInt8) async {
        let changed = store.set(
            endpoint: endpointID,
            cluster: .colorControl,
            attribute: ColorControlCluster.Attribute.currentHue,
            value: .unsignedInt(UInt64(hue))
        )
        if changed {
            store.set(
                endpoint: endpointID,
                cluster: .colorControl,
                attribute: ColorControlCluster.Attribute.colorMode,
                value: .unsignedInt(0)
            )
            await notifyChange(cluster: .colorControl, attribute: ColorControlCluster.Attribute.currentHue)
        }
    }

    /// Set the saturation from the bridge side.
    public func setSaturation(_ saturation: UInt8) async {
        let changed = store.set(
            endpoint: endpointID,
            cluster: .colorControl,
            attribute: ColorControlCluster.Attribute.currentSaturation,
            value: .unsignedInt(UInt64(saturation))
        )
        if changed {
            store.set(
                endpoint: endpointID,
                cluster: .colorControl,
                attribute: ColorControlCluster.Attribute.colorMode,
                value: .unsignedInt(0)
            )
            await notifyChange(cluster: .colorControl, attribute: ColorControlCluster.Attribute.currentSaturation)
        }
    }

    /// Set the CIE x,y color from the bridge side.
    public func setCurrentXY(x: UInt16, y: UInt16) async {
        let changedX = store.set(
            endpoint: endpointID,
            cluster: .colorControl,
            attribute: ColorControlCluster.Attribute.currentX,
            value: .unsignedInt(UInt64(x))
        )
        let changedY = store.set(
            endpoint: endpointID,
            cluster: .colorControl,
            attribute: ColorControlCluster.Attribute.currentY,
            value: .unsignedInt(UInt64(y))
        )
        if changedX || changedY {
            store.set(
                endpoint: endpointID,
                cluster: .colorControl,
                attribute: ColorControlCluster.Attribute.colorMode,
                value: .unsignedInt(1)
            )
            await notifyChange(cluster: .colorControl, attribute: ColorControlCluster.Attribute.currentX)
        }
    }

    // MARK: - Thermostat

    /// Set the local (measured) temperature from the bridge side (0.01°C units).
    public func setLocalTemperature(_ value: Int16) async {
        let changed = store.set(
            endpoint: endpointID,
            cluster: .thermostat,
            attribute: ThermostatCluster.Attribute.localTemperature,
            value: .signedInt(Int64(value))
        )
        if changed {
            await notifyChange(cluster: .thermostat, attribute: ThermostatCluster.Attribute.localTemperature)
        }
    }

    /// Set the heating setpoint from the bridge side (0.01°C units).
    public func setHeatingSetpoint(_ value: Int16) async {
        let changed = store.set(
            endpoint: endpointID,
            cluster: .thermostat,
            attribute: ThermostatCluster.Attribute.occupiedHeatingSetpoint,
            value: .signedInt(Int64(value))
        )
        if changed {
            await notifyChange(cluster: .thermostat, attribute: ThermostatCluster.Attribute.occupiedHeatingSetpoint)
        }
    }

    /// Set the cooling setpoint from the bridge side (0.01°C units).
    public func setCoolingSetpoint(_ value: Int16) async {
        let changed = store.set(
            endpoint: endpointID,
            cluster: .thermostat,
            attribute: ThermostatCluster.Attribute.occupiedCoolingSetpoint,
            value: .signedInt(Int64(value))
        )
        if changed {
            await notifyChange(cluster: .thermostat, attribute: ThermostatCluster.Attribute.occupiedCoolingSetpoint)
        }
    }

    /// Set the system mode from the bridge side.
    public func setSystemMode(_ mode: UInt8) async {
        let changed = store.set(
            endpoint: endpointID,
            cluster: .thermostat,
            attribute: ThermostatCluster.Attribute.systemMode,
            value: .unsignedInt(UInt64(mode))
        )
        if changed {
            await notifyChange(cluster: .thermostat, attribute: ThermostatCluster.Attribute.systemMode)
        }
    }

    // MARK: - Door Lock

    /// Set the lock state from the bridge side (1=locked, 2=unlocked).
    public func setLockState(_ state: UInt8) async {
        let changed = store.set(
            endpoint: endpointID,
            cluster: .doorLock,
            attribute: DoorLockCluster.Attribute.lockState,
            value: .unsignedInt(UInt64(state))
        )
        if changed {
            await notifyChange(cluster: .doorLock, attribute: DoorLockCluster.Attribute.lockState)
        }
    }

    // MARK: - Window Covering

    /// Set the lift position from the bridge side (0-10000 in 0.01%).
    public func setLiftPosition(_ percent100ths: UInt16) async {
        let changed = store.set(
            endpoint: endpointID,
            cluster: .windowCovering,
            attribute: WindowCoveringCluster.Attribute.currentPositionLiftPercent100ths,
            value: .unsignedInt(UInt64(percent100ths))
        )
        if changed {
            await notifyChange(cluster: .windowCovering, attribute: WindowCoveringCluster.Attribute.currentPositionLiftPercent100ths)
        }
    }

    /// Set the lift target from the bridge side (0-10000 in 0.01%).
    public func setLiftTarget(_ percent100ths: UInt16) async {
        let changed = store.set(
            endpoint: endpointID,
            cluster: .windowCovering,
            attribute: WindowCoveringCluster.Attribute.targetPositionLiftPercent100ths,
            value: .unsignedInt(UInt64(percent100ths))
        )
        if changed {
            await notifyChange(cluster: .windowCovering, attribute: WindowCoveringCluster.Attribute.targetPositionLiftPercent100ths)
        }
    }

    // MARK: - Fan Control

    /// Set the fan mode from the bridge side (0=off, 1-5).
    public func setFanMode(_ mode: UInt8) async {
        let changed = store.set(
            endpoint: endpointID,
            cluster: .fanControl,
            attribute: FanControlCluster.Attribute.fanMode,
            value: .unsignedInt(UInt64(mode))
        )
        if changed {
            await notifyChange(cluster: .fanControl, attribute: FanControlCluster.Attribute.fanMode)
        }
    }

    /// Set the fan percent setting from the bridge side (0-100).
    public func setFanPercent(_ percent: UInt8) async {
        let changed = store.set(
            endpoint: endpointID,
            cluster: .fanControl,
            attribute: FanControlCluster.Attribute.percentSetting,
            value: .unsignedInt(UInt64(percent))
        )
        if changed {
            store.set(
                endpoint: endpointID,
                cluster: .fanControl,
                attribute: FanControlCluster.Attribute.percentCurrent,
                value: .unsignedInt(UInt64(percent))
            )
            await notifyChange(cluster: .fanControl, attribute: FanControlCluster.Attribute.percentSetting)
        }
    }

    /// Set the fan speed from the bridge side (0-speedMax).
    public func setFanSpeed(_ speed: UInt8) async {
        let changed = store.set(
            endpoint: endpointID,
            cluster: .fanControl,
            attribute: FanControlCluster.Attribute.speedSetting,
            value: .unsignedInt(UInt64(speed))
        )
        if changed {
            store.set(
                endpoint: endpointID,
                cluster: .fanControl,
                attribute: FanControlCluster.Attribute.speedCurrent,
                value: .unsignedInt(UInt64(speed))
            )
            await notifyChange(cluster: .fanControl, attribute: FanControlCluster.Attribute.speedSetting)
        }
    }

    // MARK: - Sensors

    /// Set the temperature value from the bridge side (0.01°C units).
    public func setTemperature(_ value: Int16) async {
        let changed = store.set(
            endpoint: endpointID,
            cluster: .temperatureMeasurement,
            attribute: TemperatureMeasurementCluster.Attribute.measuredValue,
            value: .signedInt(Int64(value))
        )
        if changed {
            await notifyChange(cluster: .temperatureMeasurement, attribute: TemperatureMeasurementCluster.Attribute.measuredValue)
        }
    }

    /// Set the relative humidity from the bridge side (0.01% units, 0-10000).
    public func setHumidity(_ value: UInt16) async {
        let changed = store.set(
            endpoint: endpointID,
            cluster: .relativeHumidityMeasurement,
            attribute: RelativeHumidityMeasurementCluster.Attribute.measuredValue,
            value: .unsignedInt(UInt64(value))
        )
        if changed {
            await notifyChange(cluster: .relativeHumidityMeasurement, attribute: RelativeHumidityMeasurementCluster.Attribute.measuredValue)
        }
    }

    /// Set the illuminance from the bridge side.
    public func setIlluminance(_ value: UInt16) async {
        let changed = store.set(
            endpoint: endpointID,
            cluster: .illuminanceMeasurement,
            attribute: IlluminanceMeasurementCluster.Attribute.measuredValue,
            value: .unsignedInt(UInt64(value))
        )
        if changed {
            await notifyChange(cluster: .illuminanceMeasurement, attribute: IlluminanceMeasurementCluster.Attribute.measuredValue)
        }
    }

    /// Set the occupancy bitmap from the bridge side (0=unoccupied, 1=occupied).
    public func setOccupancy(_ value: UInt8) async {
        let changed = store.set(
            endpoint: endpointID,
            cluster: .occupancySensing,
            attribute: OccupancySensingCluster.Attribute.occupancy,
            value: .unsignedInt(UInt64(value))
        )
        if changed {
            await notifyChange(cluster: .occupancySensing, attribute: OccupancySensingCluster.Attribute.occupancy)
        }
    }

    /// Set the boolean state value from the bridge side (e.g., contact sensor).
    public func setStateValue(_ value: Bool) async {
        let changed = store.set(
            endpoint: endpointID,
            cluster: .booleanState,
            attribute: BooleanStateCluster.Attribute.stateValue,
            value: .bool(value)
        )
        if changed {
            await notifyChange(cluster: .booleanState, attribute: BooleanStateCluster.Attribute.stateValue)
        }
    }

    // MARK: - Generic

    /// Set an arbitrary attribute value from the bridge side.
    public func set(cluster: ClusterID, attribute: AttributeID, value: TLVElement) async {
        let changed = store.set(
            endpoint: endpointID,
            cluster: cluster,
            attribute: attribute,
            value: value
        )
        if changed {
            await notifyChange(cluster: cluster, attribute: attribute)
        }
    }

    // MARK: - Internal

    private func notifyChange(cluster: ClusterID, attribute: AttributeID) async {
        await subscriptions.attributesChanged([
            AttributePath(endpointID: endpointID, clusterID: cluster, attributeID: attribute)
        ])
    }
}
