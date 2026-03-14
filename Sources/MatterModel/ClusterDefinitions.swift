// ClusterDefinitions.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes

// MARK: - Standard Cluster IDs

/// Well-known Matter cluster identifiers.
///
/// These will be expanded via code generation from the Matter XML cluster definitions.
/// For now, define the most commonly used clusters for bridge/controller development.
extension ClusterID {
    // Utility clusters (endpoint 0)
    public static let descriptor                    = ClusterID(rawValue: 0x001D)
    public static let accessControl                 = ClusterID(rawValue: 0x001F)
    public static let basicInformation              = ClusterID(rawValue: 0x0028)
    public static let generalCommissioning          = ClusterID(rawValue: 0x0030)
    public static let networkCommissioning          = ClusterID(rawValue: 0x0031)
    public static let generalDiagnostics            = ClusterID(rawValue: 0x0033)
    public static let adminCommissioning            = ClusterID(rawValue: 0x003C)
    public static let operationalCredentials        = ClusterID(rawValue: 0x003E)
    public static let groupKeyManagement            = ClusterID(rawValue: 0x003F)
    public static let timeSynchronization           = ClusterID(rawValue: 0x0038)

    // Bridge cluster
    public static let bridgedDeviceBasicInformation = ClusterID(rawValue: 0x0039)
    public static let fixedLabel                    = ClusterID(rawValue: 0x0040)
    public static let binding                       = ClusterID(rawValue: 0x001E)

    // Application clusters
    public static let identify                      = ClusterID(rawValue: 0x0003)
    public static let groups                        = ClusterID(rawValue: 0x0004)
    public static let onOff                         = ClusterID(rawValue: 0x0006)
    public static let levelControl                  = ClusterID(rawValue: 0x0008)
    public static let colorControl                  = ClusterID(rawValue: 0x0300)
    public static let booleanState                  = ClusterID(rawValue: 0x0045)
    public static let doorLock                      = ClusterID(rawValue: 0x0101)
    public static let windowCovering                = ClusterID(rawValue: 0x0102)
    public static let thermostat                    = ClusterID(rawValue: 0x0201)
    public static let fanControl                    = ClusterID(rawValue: 0x0202)
    public static let temperatureMeasurement        = ClusterID(rawValue: 0x0402)
    public static let illuminanceMeasurement        = ClusterID(rawValue: 0x0400)
    public static let relativeHumidityMeasurement   = ClusterID(rawValue: 0x0405)
    public static let occupancySensing              = ClusterID(rawValue: 0x0406)
    public static let smokeCoAlarm                  = ClusterID(rawValue: 0x005C)
}

// MARK: - Standard Device Type IDs

extension DeviceTypeID {
    // Utility
    public static let rootNode             = DeviceTypeID(rawValue: 0x0016)
    public static let bridgedNode          = DeviceTypeID(rawValue: 0x0013)
    public static let aggregator           = DeviceTypeID(rawValue: 0x000E)

    // Lighting
    public static let onOffLight           = DeviceTypeID(rawValue: 0x0100)
    public static let dimmableLight        = DeviceTypeID(rawValue: 0x0101)
    public static let colorTemperatureLight = DeviceTypeID(rawValue: 0x0102)
    public static let extendedColorLight   = DeviceTypeID(rawValue: 0x010D)

    // Plugs / switches
    public static let onOffPlugInUnit      = DeviceTypeID(rawValue: 0x010A)

    // Sensors
    public static let contactSensor        = DeviceTypeID(rawValue: 0x0015)
    public static let occupancySensor      = DeviceTypeID(rawValue: 0x0107)
    public static let temperatureSensor    = DeviceTypeID(rawValue: 0x0302)
    public static let humiditySensor       = DeviceTypeID(rawValue: 0x0307)
    public static let lightSensor          = DeviceTypeID(rawValue: 0x0106)

    // HVAC
    public static let thermostat           = DeviceTypeID(rawValue: 0x0301)
    public static let fan                  = DeviceTypeID(rawValue: 0x002B)

    // Closure
    public static let doorLock             = DeviceTypeID(rawValue: 0x000A)
    public static let windowCovering       = DeviceTypeID(rawValue: 0x0202)

    // Safety
    public static let smokeCoAlarm         = DeviceTypeID(rawValue: 0x0076)
    public static let waterLeakDetector    = DeviceTypeID(rawValue: 0x0044)
}
