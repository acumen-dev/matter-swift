// DeviceTypeRegistryTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import MatterTypes
@testable import MatterModel

@Suite("DeviceTypeRegistry")
struct DeviceTypeRegistryTests {

    // MARK: - Well-Known Device Types

    @Test("On/Off Light (0x0100) is registered with correct required clusters")
    func onOffLight() {
        let spec = DeviceTypeRegistry.spec(for: .onOffLight)
        #expect(spec != nil)
        #expect(spec?.name == "On/Off Light")
        #expect(spec?.requiredServerClusters.contains(.identify) == true)
        #expect(spec?.requiredServerClusters.contains(.groups) == true)
        #expect(spec?.requiredServerClusters.contains(.onOff) == true)
    }

    @Test("Dimmable Light (0x0101) is registered with correct required clusters")
    func dimmableLight() {
        let spec = DeviceTypeRegistry.spec(for: .dimmableLight)
        #expect(spec != nil)
        #expect(spec?.name == "Dimmable Light")
        #expect(spec?.requiredServerClusters.contains(.identify) == true)
        #expect(spec?.requiredServerClusters.contains(.groups) == true)
        #expect(spec?.requiredServerClusters.contains(.onOff) == true)
    }

    @Test("Contact Sensor (0x0015) is registered with correct clusters")
    func contactSensor() {
        let spec = DeviceTypeRegistry.spec(for: .contactSensor)
        #expect(spec != nil)
        #expect(spec?.name == "Contact Sensor")
        #expect(spec?.requiredServerClusters.contains(.identify) == true)
        #expect(spec?.requiredServerClusters.contains(.booleanState) == true)
        // Boolean State Configuration is optional
        #expect(spec?.optionalServerClusters.contains(.booleanStateConfiguration) == true)
    }

    @Test("Thermostat (0x0301) is registered with correct clusters")
    func thermostat() {
        let spec = DeviceTypeRegistry.spec(for: .thermostat)
        #expect(spec != nil)
        #expect(spec?.name == "Thermostat")
        #expect(spec?.requiredServerClusters.contains(.identify) == true)
        #expect(spec?.requiredServerClusters.contains(.thermostat) == true)
        // Thermostat User Interface Configuration is optional
        #expect(spec?.optionalServerClusters.contains(.thermostatUserInterfaceConfiguration) == true)
    }

    @Test("Door Lock (0x000A) is registered with correct clusters")
    func doorLock() {
        let spec = DeviceTypeRegistry.spec(for: .doorLock)
        #expect(spec != nil)
        #expect(spec?.name == "Door Lock")
        #expect(spec?.requiredServerClusters.contains(.identify) == true)
        #expect(spec?.requiredServerClusters.contains(.doorLock) == true)
        // Groups is disallowed for Door Lock, should not appear
        #expect(spec?.requiredServerClusters.contains(.groups) == false)
        #expect(spec?.optionalServerClusters.contains(.groups) == false)
    }

    // MARK: - Registry Coverage

    @Test("Registry contains more than 50 device types")
    func totalCount() {
        #expect(DeviceTypeRegistry.count > 50)
    }

    @Test("Unknown device type ID returns nil")
    func unknownDeviceType() {
        let spec = DeviceTypeRegistry.spec(for: DeviceTypeID(rawValue: 0xFFFF))
        #expect(spec == nil)
    }

    // MARK: - Revision

    @Test("Device type specs have non-zero revision")
    func revisionsPopulated() {
        // Check a sampling of device types
        let ids: [DeviceTypeID] = [.onOffLight, .contactSensor, .thermostat, .doorLock, .fan]
        for id in ids {
            let spec = DeviceTypeRegistry.spec(for: id)
            #expect(spec != nil)
            #expect(spec!.revision >= 1, "Device type 0x\(String(format: "%04X", id.rawValue)) should have revision >= 1")
        }
    }

    // MARK: - Optional Clusters

    @Test("Optional clusters are populated for device types that have them")
    func optionalClustersPopulated() {
        // Fan has optional OnOff
        let fan = DeviceTypeRegistry.spec(for: .fan)
        #expect(fan != nil)
        #expect(fan?.optionalServerClusters.contains(.onOff) == true)

        // Window Covering has optional Groups
        let wc = DeviceTypeRegistry.spec(for: .windowCovering)
        #expect(wc != nil)
        #expect(wc?.optionalServerClusters.contains(.groups) == true)
    }

    // MARK: - Custom Registration

    @Test("Custom device type can be registered")
    func customRegistration() {
        let customID = DeviceTypeID(rawValue: 0xBEEF)
        #expect(DeviceTypeRegistry.spec(for: customID) == nil)

        DeviceTypeRegistry.register(DeviceTypeSpec(
            id: customID,
            name: "Custom Widget",
            revision: 1,
            requiredServerClusters: [.onOff],
            optionalServerClusters: [.levelControl]
        ))

        let spec = DeviceTypeRegistry.spec(for: customID)
        #expect(spec != nil)
        #expect(spec?.name == "Custom Widget")
        #expect(spec?.requiredServerClusters == [.onOff])
        #expect(spec?.optionalServerClusters == [.levelControl])
    }
}
