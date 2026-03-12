// ClusterHandlerTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import MatterTypes
@testable import MatterDevice
@testable import MatterModel

// MARK: - Helpers

/// Populate the store with a handler's initial attributes for the given endpoint.
private func populateStore(_ store: AttributeStore, handler: some ClusterHandler, endpoint: EndpointID) {
    for (attr, value) in handler.initialAttributes() {
        store.set(endpoint: endpoint, cluster: handler.clusterID, attribute: attr, value: value)
    }
}

// MARK: - OnOff Tests

@Suite("OnOffHandler")
struct OnOffHandlerTests {

    let endpoint = EndpointID(rawValue: 1)

    @Test("On command sets onOff attribute to true")
    func onCommand() throws {
        let handler = OnOffHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        _ = try handler.handleCommand(
            commandID: OnOffCluster.Command.on,
            fields: nil,
            store: store,
            endpointID: endpoint
        )

        let value = store.get(endpoint: endpoint, cluster: ClusterID.onOff, attribute: OnOffCluster.Attribute.onOff)
        #expect(value == .bool(true))
    }

    @Test("Off command sets onOff attribute to false")
    func offCommand() throws {
        let handler = OnOffHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        // First turn on
        _ = try handler.handleCommand(
            commandID: OnOffCluster.Command.on,
            fields: nil,
            store: store,
            endpointID: endpoint
        )
        // Then turn off
        _ = try handler.handleCommand(
            commandID: OnOffCluster.Command.off,
            fields: nil,
            store: store,
            endpointID: endpoint
        )

        let value = store.get(endpoint: endpoint, cluster: ClusterID.onOff, attribute: OnOffCluster.Attribute.onOff)
        #expect(value == .bool(false))
    }

    @Test("Toggle flips state from on to off")
    func toggleFromOn() throws {
        let handler = OnOffHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        // Turn on first
        _ = try handler.handleCommand(
            commandID: OnOffCluster.Command.on,
            fields: nil,
            store: store,
            endpointID: endpoint
        )
        // Toggle should turn off
        _ = try handler.handleCommand(
            commandID: OnOffCluster.Command.toggle,
            fields: nil,
            store: store,
            endpointID: endpoint
        )

        let value = store.get(endpoint: endpoint, cluster: ClusterID.onOff, attribute: OnOffCluster.Attribute.onOff)
        #expect(value == .bool(false))
    }

    @Test("Toggle from default (false) goes to true")
    func toggleFromDefault() throws {
        let handler = OnOffHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        _ = try handler.handleCommand(
            commandID: OnOffCluster.Command.toggle,
            fields: nil,
            store: store,
            endpointID: endpoint
        )

        let value = store.get(endpoint: endpoint, cluster: ClusterID.onOff, attribute: OnOffCluster.Attribute.onOff)
        #expect(value == .bool(true))
    }

    @Test("validateWrite allows bool for onOff attribute")
    func validateWriteAllowsBool() {
        let handler = OnOffHandler()
        let result = handler.validateWrite(attributeID: OnOffCluster.Attribute.onOff, value: .bool(true))
        #expect(result == .allowed)
    }

    @Test("validateWrite rejects non-bool for onOff attribute")
    func validateWriteRejectsNonBool() {
        let handler = OnOffHandler()
        let result = handler.validateWrite(attributeID: OnOffCluster.Attribute.onOff, value: .unsignedInt(1))
        #expect(result == .unsupportedWrite)
    }
}

// MARK: - LevelControl Tests

@Suite("LevelControlHandler")
struct LevelControlHandlerTests {

    let endpoint = EndpointID(rawValue: 1)

    @Test("MoveToLevel sets currentLevel")
    func moveToLevel() throws {
        let handler = LevelControlHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        let fields = TLVElement.structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(128))
        ])

        _ = try handler.handleCommand(
            commandID: LevelControlCluster.Command.moveToLevel,
            fields: fields,
            store: store,
            endpointID: endpoint
        )

        let value = store.get(endpoint: endpoint, cluster: ClusterID.levelControl, attribute: LevelControlCluster.Attribute.currentLevel)
        #expect(value == .unsignedInt(128))
    }

    @Test("MoveToLevel clamps to min level")
    func moveToLevelClampsMin() throws {
        let handler = LevelControlHandler(minLevel: 10, maxLevel: 254)
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        let fields = TLVElement.structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(2))
        ])

        _ = try handler.handleCommand(
            commandID: LevelControlCluster.Command.moveToLevel,
            fields: fields,
            store: store,
            endpointID: endpoint
        )

        let value = store.get(endpoint: endpoint, cluster: ClusterID.levelControl, attribute: LevelControlCluster.Attribute.currentLevel)
        #expect(value == .unsignedInt(10))
    }

    @Test("MoveToLevel clamps to max level")
    func moveToLevelClampsMax() throws {
        let handler = LevelControlHandler(minLevel: 1, maxLevel: 200)
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        let fields = TLVElement.structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(250))
        ])

        _ = try handler.handleCommand(
            commandID: LevelControlCluster.Command.moveToLevel,
            fields: fields,
            store: store,
            endpointID: endpoint
        )

        let value = store.get(endpoint: endpoint, cluster: ClusterID.levelControl, attribute: LevelControlCluster.Attribute.currentLevel)
        #expect(value == .unsignedInt(200))
    }

    @Test("initialAttributes has correct min and max")
    func initialAttributesMinMax() {
        let handler = LevelControlHandler(minLevel: 5, maxLevel: 200)
        let attrs = Dictionary(uniqueKeysWithValues: handler.initialAttributes())

        #expect(attrs[LevelControlCluster.Attribute.minLevel] == .unsignedInt(5))
        #expect(attrs[LevelControlCluster.Attribute.maxLevel] == .unsignedInt(200))
        #expect(attrs[LevelControlCluster.Attribute.currentLevel] == .unsignedInt(5))
    }
}

// MARK: - Descriptor Tests

@Suite("DescriptorHandler")
struct DescriptorHandlerTests {

    let endpoint = EndpointID(rawValue: 0)

    @Test("initialAttributes has correct device types")
    func initialAttributesDeviceTypes() {
        let handler = DescriptorHandler(
            deviceTypes: [(.dimmableLight, 2), (.onOffLight, 1)],
            serverClusters: [.onOff]
        )
        let attrs = Dictionary(uniqueKeysWithValues: handler.initialAttributes())

        guard let deviceTypeList = attrs[DescriptorCluster.Attribute.deviceTypeList],
              case .array(let elements) = deviceTypeList else {
            Issue.record("deviceTypeList missing or wrong type")
            return
        }
        #expect(elements.count == 2)

        // Verify first device type struct
        let first = try? DescriptorCluster.DeviceTypeStruct.fromTLVElement(elements[0])
        #expect(first?.deviceType == .dimmableLight)
        #expect(first?.revision == 2)
    }

    @Test("initialAttributes has correct server list")
    func initialAttributesServerList() {
        let handler = DescriptorHandler(
            deviceTypes: [(.rootNode, 1)],
            serverClusters: [.onOff, .levelControl, .descriptor]
        )
        let attrs = Dictionary(uniqueKeysWithValues: handler.initialAttributes())

        guard let serverList = attrs[DescriptorCluster.Attribute.serverList],
              case .array(let elements) = serverList else {
            Issue.record("serverList missing or wrong type")
            return
        }
        #expect(elements.count == 3)
        #expect(elements[0].uintValue == UInt64(ClusterID.onOff.rawValue))
        #expect(elements[1].uintValue == UInt64(ClusterID.levelControl.rawValue))
        #expect(elements[2].uintValue == UInt64(ClusterID.descriptor.rawValue))
    }

    @Test("validateWrite rejects all writes")
    func validateWriteRejectsAll() {
        let handler = DescriptorHandler(
            deviceTypes: [(.rootNode, 1)],
            serverClusters: []
        )
        // Descriptor is entirely read-only
        let result = handler.validateWrite(
            attributeID: DescriptorCluster.Attribute.deviceTypeList,
            value: .array([])
        )
        #expect(result == .unsupportedWrite)
    }
}

// MARK: - BridgedDeviceBasicInfo Tests

@Suite("BridgedDeviceBasicInfoHandler")
struct BridgedDeviceBasicInfoHandlerTests {

    @Test("initialAttributes has nodeLabel and reachable")
    func initialAttributesBasic() {
        let handler = BridgedDeviceBasicInfoHandler(nodeLabel: "Kitchen Light")
        let attrs = Dictionary(uniqueKeysWithValues: handler.initialAttributes())

        #expect(attrs[BridgedDeviceBasicInfoCluster.Attribute.nodeLabel] == .utf8String("Kitchen Light"))
        #expect(attrs[BridgedDeviceBasicInfoCluster.Attribute.reachable] == .bool(true))
    }

    @Test("nodeLabel is writable")
    func nodeLabelWritable() {
        let handler = BridgedDeviceBasicInfoHandler(nodeLabel: "Test")
        let result = handler.validateWrite(
            attributeID: BridgedDeviceBasicInfoCluster.Attribute.nodeLabel,
            value: .utf8String("New Label")
        )
        #expect(result == .allowed)
    }

    @Test("vendorName is not writable")
    func vendorNameNotWritable() {
        let handler = BridgedDeviceBasicInfoHandler(
            vendorName: "Acme",
            nodeLabel: "Test"
        )
        let result = handler.validateWrite(
            attributeID: BridgedDeviceBasicInfoCluster.Attribute.vendorName,
            value: .utf8String("Evil Corp")
        )
        #expect(result == .unsupportedWrite)
    }
}

// MARK: - ColorControl Tests

@Suite("ColorControlHandler")
struct ColorControlHandlerTests {

    let endpoint = EndpointID(rawValue: 1)

    @Test("initialAttributes has correct defaults")
    func initialAttributes() {
        let handler = ColorControlHandler(physicalMinMireds: 153, physicalMaxMireds: 500)
        let attrs = Dictionary(uniqueKeysWithValues: handler.initialAttributes())

        #expect(attrs[ColorControlCluster.Attribute.currentHue] == .unsignedInt(0))
        #expect(attrs[ColorControlCluster.Attribute.colorTemperatureMireds] == .unsignedInt(153))
        #expect(attrs[ColorControlCluster.Attribute.colorTempPhysicalMinMireds] == .unsignedInt(153))
        #expect(attrs[ColorControlCluster.Attribute.colorTempPhysicalMaxMireds] == .unsignedInt(500))
    }

    @Test("moveToHue sets hue and colorMode to 0")
    func moveToHue() throws {
        let handler = ColorControlHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        let fields = TLVElement.structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(180))
        ])

        _ = try handler.handleCommand(
            commandID: ColorControlCluster.Command.moveToHue,
            fields: fields,
            store: store,
            endpointID: endpoint
        )

        #expect(store.get(endpoint: endpoint, cluster: .colorControl, attribute: ColorControlCluster.Attribute.currentHue) == .unsignedInt(180))
        #expect(store.get(endpoint: endpoint, cluster: .colorControl, attribute: ColorControlCluster.Attribute.colorMode) == .unsignedInt(0))
    }

    @Test("moveToColor sets x, y and colorMode to 1")
    func moveToColor() throws {
        let handler = ColorControlHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        let fields = TLVElement.structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(24000)),
            .init(tag: .contextSpecific(1), value: .unsignedInt(25000))
        ])

        _ = try handler.handleCommand(
            commandID: ColorControlCluster.Command.moveToColor,
            fields: fields,
            store: store,
            endpointID: endpoint
        )

        #expect(store.get(endpoint: endpoint, cluster: .colorControl, attribute: ColorControlCluster.Attribute.currentX) == .unsignedInt(24000))
        #expect(store.get(endpoint: endpoint, cluster: .colorControl, attribute: ColorControlCluster.Attribute.currentY) == .unsignedInt(25000))
        #expect(store.get(endpoint: endpoint, cluster: .colorControl, attribute: ColorControlCluster.Attribute.colorMode) == .unsignedInt(1))
    }

    @Test("moveToColorTemperature clamps to physical range")
    func moveToColorTemperatureClamps() throws {
        let handler = ColorControlHandler(physicalMinMireds: 153, physicalMaxMireds: 500)
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        // Below min
        let fields1 = TLVElement.structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(100))
        ])
        _ = try handler.handleCommand(
            commandID: ColorControlCluster.Command.moveToColorTemperature,
            fields: fields1,
            store: store,
            endpointID: endpoint
        )
        #expect(store.get(endpoint: endpoint, cluster: .colorControl, attribute: ColorControlCluster.Attribute.colorTemperatureMireds) == .unsignedInt(153))

        // Above max
        let fields2 = TLVElement.structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(600))
        ])
        _ = try handler.handleCommand(
            commandID: ColorControlCluster.Command.moveToColorTemperature,
            fields: fields2,
            store: store,
            endpointID: endpoint
        )
        #expect(store.get(endpoint: endpoint, cluster: .colorControl, attribute: ColorControlCluster.Attribute.colorTemperatureMireds) == .unsignedInt(500))
        #expect(store.get(endpoint: endpoint, cluster: .colorControl, attribute: ColorControlCluster.Attribute.colorMode) == .unsignedInt(2))
    }

    @Test("onChange callback fires with correct value")
    func onChangeCallback() throws {
        nonisolated(unsafe) var received: ColorControlChange?
        let handler = ColorControlHandler(onChange: { received = $0 })
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        let fields = TLVElement.structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(200))
        ])
        _ = try handler.handleCommand(
            commandID: ColorControlCluster.Command.moveToSaturation,
            fields: fields,
            store: store,
            endpointID: endpoint
        )

        if case .saturation(let v) = received {
            #expect(v == 200)
        } else {
            Issue.record("Expected saturation change")
        }
    }
}

// MARK: - Thermostat Tests

@Suite("ThermostatHandler")
struct ThermostatHandlerTests {

    let endpoint = EndpointID(rawValue: 1)

    @Test("initialAttributes has correct defaults")
    func initialAttributes() {
        let handler = ThermostatHandler()
        let attrs = Dictionary(uniqueKeysWithValues: handler.initialAttributes())

        #expect(attrs[ThermostatCluster.Attribute.localTemperature] == .signedInt(2000))
        #expect(attrs[ThermostatCluster.Attribute.occupiedHeatingSetpoint] == .signedInt(2000))
        #expect(attrs[ThermostatCluster.Attribute.occupiedCoolingSetpoint] == .signedInt(2600))
        #expect(attrs[ThermostatCluster.Attribute.systemMode] == .unsignedInt(1))
    }

    @Test("setpointRaiseLower adjusts heating setpoint")
    func raiseHeatingSetpoint() throws {
        let handler = ThermostatHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        // Mode 0 = heat, amount +5 (0.5°C = 50 hundredths)
        let fields = TLVElement.structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(0)),
            .init(tag: .contextSpecific(1), value: .signedInt(5))
        ])

        _ = try handler.handleCommand(
            commandID: ThermostatCluster.Command.setpointRaiseLower,
            fields: fields,
            store: store,
            endpointID: endpoint
        )

        let val = store.get(endpoint: endpoint, cluster: .thermostat, attribute: ThermostatCluster.Attribute.occupiedHeatingSetpoint)
        #expect(val == .signedInt(2050)) // 2000 + 5*10
    }

    @Test("setpointRaiseLower mode 2 adjusts both setpoints")
    func raiseBothSetpoints() throws {
        let handler = ThermostatHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        let fields = TLVElement.structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(2)),
            .init(tag: .contextSpecific(1), value: .signedInt(-3))
        ])

        _ = try handler.handleCommand(
            commandID: ThermostatCluster.Command.setpointRaiseLower,
            fields: fields,
            store: store,
            endpointID: endpoint
        )

        let heat = store.get(endpoint: endpoint, cluster: .thermostat, attribute: ThermostatCluster.Attribute.occupiedHeatingSetpoint)
        let cool = store.get(endpoint: endpoint, cluster: .thermostat, attribute: ThermostatCluster.Attribute.occupiedCoolingSetpoint)
        #expect(heat == .signedInt(1970)) // 2000 - 30
        #expect(cool == .signedInt(2570)) // 2600 - 30
    }

    @Test("validateWrite allows systemMode and setpoints")
    func validateWriteAllows() {
        let handler = ThermostatHandler()
        #expect(handler.validateWrite(attributeID: ThermostatCluster.Attribute.systemMode, value: .unsignedInt(4)) == .allowed)
        #expect(handler.validateWrite(attributeID: ThermostatCluster.Attribute.occupiedHeatingSetpoint, value: .signedInt(2100)) == .allowed)
        #expect(handler.validateWrite(attributeID: ThermostatCluster.Attribute.localTemperature, value: .signedInt(2000)) == .unsupportedWrite)
    }
}

// MARK: - DoorLock Tests

@Suite("DoorLockHandler")
struct DoorLockHandlerTests {

    let endpoint = EndpointID(rawValue: 1)

    @Test("initialAttributes has locked state")
    func initialAttributes() {
        let handler = DoorLockHandler()
        let attrs = Dictionary(uniqueKeysWithValues: handler.initialAttributes())

        #expect(attrs[DoorLockCluster.Attribute.lockState] == .unsignedInt(1))
        #expect(attrs[DoorLockCluster.Attribute.actuatorEnabled] == .bool(true))
    }

    @Test("lockDoor sets lockState to 1")
    func lockDoor() throws {
        let handler = DoorLockHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        // First unlock
        _ = try handler.handleCommand(commandID: DoorLockCluster.Command.unlockDoor, fields: nil, store: store, endpointID: endpoint)
        // Then lock
        _ = try handler.handleCommand(commandID: DoorLockCluster.Command.lockDoor, fields: nil, store: store, endpointID: endpoint)

        #expect(store.get(endpoint: endpoint, cluster: .doorLock, attribute: DoorLockCluster.Attribute.lockState) == .unsignedInt(1))
    }

    @Test("unlockDoor sets lockState to 2")
    func unlockDoor() throws {
        let handler = DoorLockHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        _ = try handler.handleCommand(commandID: DoorLockCluster.Command.unlockDoor, fields: nil, store: store, endpointID: endpoint)

        #expect(store.get(endpoint: endpoint, cluster: .doorLock, attribute: DoorLockCluster.Attribute.lockState) == .unsignedInt(2))
    }

    @Test("onChange callback fires")
    func onChangeCallback() throws {
        nonisolated(unsafe) var received: UInt8?
        let handler = DoorLockHandler(onChange: { received = $0 })
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        _ = try handler.handleCommand(commandID: DoorLockCluster.Command.unlockDoor, fields: nil, store: store, endpointID: endpoint)

        #expect(received == 2)
    }
}

// MARK: - WindowCovering Tests

@Suite("WindowCoveringHandler")
struct WindowCoveringHandlerTests {

    let endpoint = EndpointID(rawValue: 1)

    @Test("upOrOpen sets position to 0")
    func upOrOpen() throws {
        let handler = WindowCoveringHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        // Close first
        _ = try handler.handleCommand(commandID: WindowCoveringCluster.Command.downOrClose, fields: nil, store: store, endpointID: endpoint)
        // Then open
        _ = try handler.handleCommand(commandID: WindowCoveringCluster.Command.upOrOpen, fields: nil, store: store, endpointID: endpoint)

        #expect(store.get(endpoint: endpoint, cluster: .windowCovering, attribute: WindowCoveringCluster.Attribute.currentPositionLiftPercent100ths) == .unsignedInt(0))
    }

    @Test("downOrClose sets position to 10000")
    func downOrClose() throws {
        let handler = WindowCoveringHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        _ = try handler.handleCommand(commandID: WindowCoveringCluster.Command.downOrClose, fields: nil, store: store, endpointID: endpoint)

        #expect(store.get(endpoint: endpoint, cluster: .windowCovering, attribute: WindowCoveringCluster.Attribute.currentPositionLiftPercent100ths) == .unsignedInt(10000))
        #expect(store.get(endpoint: endpoint, cluster: .windowCovering, attribute: WindowCoveringCluster.Attribute.targetPositionLiftPercent100ths) == .unsignedInt(10000))
    }

    @Test("goToLiftPercentage clamps to 0-10000")
    func goToLiftPercentageClamps() throws {
        let handler = WindowCoveringHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        let fields = TLVElement.structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(15000))
        ])
        _ = try handler.handleCommand(commandID: WindowCoveringCluster.Command.goToLiftPercentage, fields: fields, store: store, endpointID: endpoint)

        #expect(store.get(endpoint: endpoint, cluster: .windowCovering, attribute: WindowCoveringCluster.Attribute.currentPositionLiftPercent100ths) == .unsignedInt(10000))
    }

    @Test("goToLiftPercentage sets valid position")
    func goToLiftPercentageValid() throws {
        let handler = WindowCoveringHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: endpoint)

        let fields = TLVElement.structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(5000))
        ])
        _ = try handler.handleCommand(commandID: WindowCoveringCluster.Command.goToLiftPercentage, fields: fields, store: store, endpointID: endpoint)

        #expect(store.get(endpoint: endpoint, cluster: .windowCovering, attribute: WindowCoveringCluster.Attribute.currentPositionLiftPercent100ths) == .unsignedInt(5000))
    }
}

// MARK: - FanControl Tests

@Suite("FanControlHandler")
struct FanControlHandlerTests {

    @Test("initialAttributes has correct defaults")
    func initialAttributes() {
        let handler = FanControlHandler(speedMax: 5)
        let attrs = Dictionary(uniqueKeysWithValues: handler.initialAttributes())

        #expect(attrs[FanControlCluster.Attribute.fanMode] == .unsignedInt(0))
        #expect(attrs[FanControlCluster.Attribute.speedMax] == .unsignedInt(5))
        #expect(attrs[FanControlCluster.Attribute.percentSetting] == .unsignedInt(0))
    }

    @Test("validateWrite allows fanMode in range")
    func validateWriteFanMode() {
        let handler = FanControlHandler()
        #expect(handler.validateWrite(attributeID: FanControlCluster.Attribute.fanMode, value: .unsignedInt(3)) == .allowed)
        #expect(handler.validateWrite(attributeID: FanControlCluster.Attribute.fanMode, value: .unsignedInt(6)) == .constraintError)
    }

    @Test("validateWrite allows percentSetting in range")
    func validateWritePercent() {
        let handler = FanControlHandler()
        #expect(handler.validateWrite(attributeID: FanControlCluster.Attribute.percentSetting, value: .unsignedInt(50)) == .allowed)
        #expect(handler.validateWrite(attributeID: FanControlCluster.Attribute.percentSetting, value: .unsignedInt(101)) == .constraintError)
    }

    @Test("validateWrite allows speedSetting up to speedMax")
    func validateWriteSpeed() {
        let handler = FanControlHandler(speedMax: 5)
        #expect(handler.validateWrite(attributeID: FanControlCluster.Attribute.speedSetting, value: .unsignedInt(5)) == .allowed)
        #expect(handler.validateWrite(attributeID: FanControlCluster.Attribute.speedSetting, value: .unsignedInt(6)) == .constraintError)
    }

    @Test("validateWrite rejects read-only attributes")
    func validateWriteRejectsReadOnly() {
        let handler = FanControlHandler()
        #expect(handler.validateWrite(attributeID: FanControlCluster.Attribute.percentCurrent, value: .unsignedInt(50)) == .unsupportedWrite)
        #expect(handler.validateWrite(attributeID: FanControlCluster.Attribute.speedCurrent, value: .unsignedInt(5)) == .unsupportedWrite)
        #expect(handler.validateWrite(attributeID: FanControlCluster.Attribute.speedMax, value: .unsignedInt(10)) == .unsupportedWrite)
    }
}

// MARK: - Sensor Handler Tests

@Suite("TemperatureMeasurementHandler")
struct TemperatureMeasurementHandlerTests {

    @Test("initialAttributes has correct defaults")
    func initialAttributes() {
        let handler = TemperatureMeasurementHandler()
        let attrs = Dictionary(uniqueKeysWithValues: handler.initialAttributes())

        #expect(attrs[TemperatureMeasurementCluster.Attribute.measuredValue] == .signedInt(0))
        #expect(attrs[TemperatureMeasurementCluster.Attribute.minMeasuredValue] == .signedInt(-27315))
        #expect(attrs[TemperatureMeasurementCluster.Attribute.maxMeasuredValue] == .signedInt(32767))
    }

    @Test("validateWrite rejects all writes")
    func validateWriteRejects() {
        let handler = TemperatureMeasurementHandler()
        #expect(handler.validateWrite(attributeID: TemperatureMeasurementCluster.Attribute.measuredValue, value: .signedInt(2200)) == .unsupportedWrite)
    }
}

@Suite("RelativeHumidityMeasurementHandler")
struct RelativeHumidityMeasurementHandlerTests {

    @Test("initialAttributes has correct defaults")
    func initialAttributes() {
        let handler = RelativeHumidityMeasurementHandler()
        let attrs = Dictionary(uniqueKeysWithValues: handler.initialAttributes())

        #expect(attrs[RelativeHumidityMeasurementCluster.Attribute.measuredValue] == .unsignedInt(0))
        #expect(attrs[RelativeHumidityMeasurementCluster.Attribute.maxMeasuredValue] == .unsignedInt(10000))
    }
}

@Suite("IlluminanceMeasurementHandler")
struct IlluminanceMeasurementHandlerTests {

    @Test("initialAttributes has correct defaults")
    func initialAttributes() {
        let handler = IlluminanceMeasurementHandler()
        let attrs = Dictionary(uniqueKeysWithValues: handler.initialAttributes())

        #expect(attrs[IlluminanceMeasurementCluster.Attribute.measuredValue] == .unsignedInt(0))
        #expect(attrs[IlluminanceMeasurementCluster.Attribute.minMeasuredValue] == .unsignedInt(1))
        #expect(attrs[IlluminanceMeasurementCluster.Attribute.maxMeasuredValue] == .unsignedInt(0xFFFE))
    }
}

@Suite("OccupancySensingHandler")
struct OccupancySensingHandlerTests {

    @Test("initialAttributes uses configurable sensor type")
    func initialAttributesSensorType() {
        let handler = OccupancySensingHandler(sensorType: 2) // PIR + Ultrasonic
        let attrs = Dictionary(uniqueKeysWithValues: handler.initialAttributes())

        #expect(attrs[OccupancySensingCluster.Attribute.occupancy] == .unsignedInt(0))
        #expect(attrs[OccupancySensingCluster.Attribute.occupancySensorType] == .unsignedInt(2))
    }

    @Test("validateWrite rejects all writes")
    func validateWriteRejects() {
        let handler = OccupancySensingHandler()
        #expect(handler.validateWrite(attributeID: OccupancySensingCluster.Attribute.occupancy, value: .unsignedInt(1)) == .unsupportedWrite)
    }
}

@Suite("BooleanStateHandler")
struct BooleanStateHandlerTests {

    @Test("initialAttributes defaults to false")
    func initialAttributes() {
        let handler = BooleanStateHandler()
        let attrs = Dictionary(uniqueKeysWithValues: handler.initialAttributes())

        #expect(attrs[BooleanStateCluster.Attribute.stateValue] == .bool(false))
    }

    @Test("validateWrite rejects all writes")
    func validateWriteRejects() {
        let handler = BooleanStateHandler()
        #expect(handler.validateWrite(attributeID: BooleanStateCluster.Attribute.stateValue, value: .bool(true)) == .unsupportedWrite)
    }
}
