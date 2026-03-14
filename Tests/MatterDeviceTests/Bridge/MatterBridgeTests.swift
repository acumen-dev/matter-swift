// MatterBridgeTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterModel
import MatterProtocol
@testable import MatterDevice

@Suite("MatterBridge Tests")
struct MatterBridgeTests {

    private let testFabric = FabricIndex(rawValue: 1)
    private let testSession: UInt16 = 1

    // MARK: - Init

    @Test("Bridge creates root and aggregator endpoints at init")
    func bridgeCreatesRootAndAggregator() {
        let bridge = MatterBridge()

        // Root endpoint 0
        #expect(bridge.store.hasEndpoint(EndpointID(rawValue: 0)))
        // Aggregator endpoint 1
        #expect(bridge.store.hasEndpoint(EndpointManager.aggregatorEndpoint))
        // No dynamic endpoints yet
        #expect(bridge.allBridgedEndpoints.isEmpty)
    }

    @Test("Root endpoint has Descriptor with rootNode device type")
    func rootEndpointDescriptor() {
        let bridge = MatterBridge()

        let deviceTypeList = bridge.store.get(
            endpoint: EndpointID(rawValue: 0),
            cluster: .descriptor,
            attribute: DescriptorCluster.Attribute.deviceTypeList
        )
        #expect(deviceTypeList != nil)
    }

    // MARK: - Add Endpoints

    @Test("addDimmableLight creates endpoint with OnOff, LevelControl, BridgedDeviceBasicInfo, Descriptor")
    func addDimmableLight() {
        let bridge = MatterBridge()
        let light = bridge.addDimmableLight(name: "Kitchen Pendant")

        #expect(light.name == "Kitchen Pendant")
        #expect(bridge.store.hasEndpoint(light.endpointID))

        // OnOff cluster present
        let onOff = bridge.store.get(
            endpoint: light.endpointID,
            cluster: .onOff,
            attribute: OnOffCluster.Attribute.onOff
        )
        #expect(onOff?.boolValue == false)

        // LevelControl present
        let level = bridge.store.get(
            endpoint: light.endpointID,
            cluster: .levelControl,
            attribute: LevelControlCluster.Attribute.currentLevel
        )
        #expect(level != nil)

        // BridgedDeviceBasicInfo present
        let label = bridge.store.get(
            endpoint: light.endpointID,
            cluster: .bridgedDeviceBasicInformation,
            attribute: BridgedDeviceBasicInfoCluster.Attribute.nodeLabel
        )
        #expect(label?.stringValue == "Kitchen Pendant")

        // Reachable defaults to true
        let reachable = bridge.store.get(
            endpoint: light.endpointID,
            cluster: .bridgedDeviceBasicInformation,
            attribute: BridgedDeviceBasicInfoCluster.Attribute.reachable
        )
        #expect(reachable?.boolValue == true)
    }

    @Test("addOnOffLight creates endpoint without LevelControl")
    func addOnOffLight() {
        let bridge = MatterBridge()
        let light = bridge.addOnOffLight(name: "Hallway Light")

        #expect(light.name == "Hallway Light")

        // OnOff cluster present
        let onOff = bridge.store.get(
            endpoint: light.endpointID,
            cluster: .onOff,
            attribute: OnOffCluster.Attribute.onOff
        )
        #expect(onOff?.boolValue == false)

        // No LevelControl
        #expect(!bridge.store.hasCluster(endpoint: light.endpointID, cluster: .levelControl))
    }

    @Test("Multiple lights get sequential endpoint IDs starting at 3")
    func sequentialEndpointIDs() {
        let bridge = MatterBridge()
        let light1 = bridge.addDimmableLight(name: "Light 1")
        let light2 = bridge.addDimmableLight(name: "Light 2")
        let light3 = bridge.addOnOffLight(name: "Light 3")

        #expect(light1.endpointID.rawValue == 3)
        #expect(light2.endpointID.rawValue == 4)
        #expect(light3.endpointID.rawValue == 5)
    }

    // MARK: - PartsList

    @Test("Aggregator PartsList updates when endpoints are added")
    func aggregatorPartsListOnAdd() {
        let bridge = MatterBridge()
        let light1 = bridge.addDimmableLight(name: "Light 1")
        let light2 = bridge.addOnOffLight(name: "Light 2")

        let partsList = bridge.store.get(
            endpoint: EndpointManager.aggregatorEndpoint,
            cluster: .descriptor,
            attribute: DescriptorCluster.Attribute.partsList
        )

        guard case .array(let elements) = partsList else {
            Issue.record("PartsList should be an array")
            return
        }

        let endpointIDs = elements.compactMap { $0.uintValue }.map { UInt16($0) }
        #expect(endpointIDs.contains(light1.endpointID.rawValue))
        #expect(endpointIDs.contains(light2.endpointID.rawValue))
    }

    @Test("Aggregator PartsList updates when endpoints are removed")
    func aggregatorPartsListOnRemove() {
        let bridge = MatterBridge()
        let light1 = bridge.addDimmableLight(name: "Light 1")
        let _ = bridge.addDimmableLight(name: "Light 2")

        bridge.removeEndpoint(light1)

        let partsList = bridge.store.get(
            endpoint: EndpointManager.aggregatorEndpoint,
            cluster: .descriptor,
            attribute: DescriptorCluster.Attribute.partsList
        )

        guard case .array(let elements) = partsList else {
            Issue.record("PartsList should be an array")
            return
        }

        let endpointIDs = elements.compactMap { $0.uintValue }.map { UInt16($0) }
        #expect(!endpointIDs.contains(light1.endpointID.rawValue))
        #expect(endpointIDs.count == 1)
    }

    // MARK: - Remove Endpoint

    @Test("Remove endpoint clears data from store")
    func removeEndpointClearsStore() {
        let bridge = MatterBridge()
        let light = bridge.addDimmableLight(name: "Light")

        #expect(bridge.store.hasEndpoint(light.endpointID))
        bridge.removeEndpoint(light.endpointID)
        #expect(!bridge.store.hasEndpoint(light.endpointID))
        #expect(bridge.bridgedEndpoint(for: light.endpointID) == nil)
    }

    // MARK: - Bridge-Side Attribute Setting

    @Test("BridgedEndpoint.setOnOff updates store")
    func setOnOff() async {
        let bridge = MatterBridge()
        let light = bridge.addDimmableLight(name: "Light")

        await light.setOnOff(true)

        let val = bridge.store.get(
            endpoint: light.endpointID,
            cluster: .onOff,
            attribute: OnOffCluster.Attribute.onOff
        )
        #expect(val?.boolValue == true)
    }

    @Test("BridgedEndpoint.setLevel updates store")
    func setLevel() async {
        let bridge = MatterBridge()
        let light = bridge.addDimmableLight(name: "Light")

        await light.setLevel(200)

        let val = bridge.store.get(
            endpoint: light.endpointID,
            cluster: .levelControl,
            attribute: LevelControlCluster.Attribute.currentLevel
        )
        #expect(val?.uintValue == 200)
    }

    @Test("BridgedEndpoint.setReachable updates store")
    func setReachable() async {
        let bridge = MatterBridge()
        let light = bridge.addDimmableLight(name: "Light")

        await light.setReachable(false)

        let val = bridge.store.get(
            endpoint: light.endpointID,
            cluster: .bridgedDeviceBasicInformation,
            attribute: BridgedDeviceBasicInfoCluster.Attribute.reachable
        )
        #expect(val?.boolValue == false)
    }

    // MARK: - IM Read Through Bridge

    @Test("handleIM ReadRequest reads bridged light attributes")
    func readThroughBridge() async throws {
        let bridge = MatterBridge()
        let light = bridge.addDimmableLight(name: "Light")
        await light.setOnOff(true)

        let request = ReadRequest(attributeRequests: [
            AttributePath(
                endpointID: light.endpointID,
                clusterID: .onOff,
                attributeID: OnOffCluster.Attribute.onOff
            )
        ])

        let responses = try await bridge.handleIM(
            opcode: .readRequest,
            payload: request.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric
        ).allPairs

        #expect(responses.count == 1)
        let report = try ReportData.fromTLV(responses[0].1)
        #expect(report.attributeReports.count == 1)
        #expect(report.attributeReports[0].attributeData?.data.boolValue == true)
    }

    // MARK: - IM Invoke Through Bridge

    @Test("handleIM InvokeRequest executes command on bridged light")
    func invokeThroughBridge() async throws {
        let bridge = MatterBridge()
        let light = bridge.addDimmableLight(name: "Light")

        let cmd = CommandDataIB(
            commandPath: CommandPath(
                endpointID: light.endpointID,
                clusterID: .onOff,
                commandID: OnOffCluster.Command.on
            )
        )
        let request = InvokeRequest(invokeRequests: [cmd])

        let responses = try await bridge.handleIM(
            opcode: .invokeRequest,
            payload: request.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric
        ).allPairs

        #expect(responses.count == 1)
        let invokeResp = try InvokeResponse.fromTLV(responses[0].1)
        #expect(invokeResp.invokeResponses[0].status?.status == .success)

        // Verify state changed
        let val = bridge.store.get(
            endpoint: light.endpointID,
            cluster: .onOff,
            attribute: OnOffCluster.Attribute.onOff
        )
        #expect(val?.boolValue == true)
    }

    // MARK: - New Device Type Factory Methods

    @Test("addColorTemperatureLight creates endpoint with ColorControl cluster")
    func addColorTemperatureLight() {
        let bridge = MatterBridge()
        let light = bridge.addColorTemperatureLight(name: "CT Light")

        #expect(light.name == "CT Light")
        #expect(bridge.store.hasCluster(endpoint: light.endpointID, cluster: .onOff))
        #expect(bridge.store.hasCluster(endpoint: light.endpointID, cluster: .levelControl))
        #expect(bridge.store.hasCluster(endpoint: light.endpointID, cluster: .colorControl))
        #expect(bridge.store.hasCluster(endpoint: light.endpointID, cluster: .bridgedDeviceBasicInformation))
    }

    @Test("addExtendedColorLight creates endpoint with ColorControl cluster")
    func addExtendedColorLight() {
        let bridge = MatterBridge()
        let light = bridge.addExtendedColorLight(name: "RGB Light")

        #expect(bridge.store.hasCluster(endpoint: light.endpointID, cluster: .colorControl))
        #expect(bridge.store.hasCluster(endpoint: light.endpointID, cluster: .onOff))
    }

    @Test("addOnOffPlugInUnit creates endpoint with OnOff only")
    func addOnOffPlugInUnit() {
        let bridge = MatterBridge()
        let plug = bridge.addOnOffPlugInUnit(name: "Smart Plug")

        #expect(plug.name == "Smart Plug")
        #expect(bridge.store.hasCluster(endpoint: plug.endpointID, cluster: .onOff))
        #expect(!bridge.store.hasCluster(endpoint: plug.endpointID, cluster: .levelControl))
    }

    @Test("addThermostat creates endpoint with Thermostat cluster")
    func addThermostat() {
        let bridge = MatterBridge()
        let thermo = bridge.addThermostat(name: "Living Room Thermostat")

        #expect(bridge.store.hasCluster(endpoint: thermo.endpointID, cluster: .thermostat))
        let temp = bridge.store.get(
            endpoint: thermo.endpointID,
            cluster: .thermostat,
            attribute: ThermostatCluster.Attribute.localTemperature
        )
        #expect(temp?.intValue == 2000)
    }

    @Test("addDoorLock creates endpoint with DoorLock cluster")
    func addDoorLock() {
        let bridge = MatterBridge()
        let lock = bridge.addDoorLock(name: "Front Door")

        #expect(bridge.store.hasCluster(endpoint: lock.endpointID, cluster: .doorLock))
        let state = bridge.store.get(
            endpoint: lock.endpointID,
            cluster: .doorLock,
            attribute: DoorLockCluster.Attribute.lockState
        )
        #expect(state?.uintValue == 1) // Locked
    }

    @Test("addWindowCovering creates endpoint with WindowCovering cluster")
    func addWindowCovering() {
        let bridge = MatterBridge()
        let covering = bridge.addWindowCovering(name: "Bedroom Blinds")

        #expect(bridge.store.hasCluster(endpoint: covering.endpointID, cluster: .windowCovering))
    }

    @Test("addFan creates endpoint with FanControl cluster")
    func addFan() {
        let bridge = MatterBridge()
        let fan = bridge.addFan(name: "Ceiling Fan")

        #expect(bridge.store.hasCluster(endpoint: fan.endpointID, cluster: .fanControl))
        let mode = bridge.store.get(
            endpoint: fan.endpointID,
            cluster: .fanControl,
            attribute: FanControlCluster.Attribute.fanMode
        )
        #expect(mode?.uintValue == 0) // Off
    }

    @Test("addContactSensor creates endpoint with BooleanState cluster")
    func addContactSensor() {
        let bridge = MatterBridge()
        let sensor = bridge.addContactSensor(name: "Door Sensor")

        #expect(bridge.store.hasCluster(endpoint: sensor.endpointID, cluster: .booleanState))
    }

    @Test("addOccupancySensor creates endpoint with OccupancySensing cluster")
    func addOccupancySensor() {
        let bridge = MatterBridge()
        let sensor = bridge.addOccupancySensor(name: "Motion")

        #expect(bridge.store.hasCluster(endpoint: sensor.endpointID, cluster: .occupancySensing))
    }

    @Test("addTemperatureSensor creates endpoint with TemperatureMeasurement cluster")
    func addTemperatureSensor() {
        let bridge = MatterBridge()
        let sensor = bridge.addTemperatureSensor(name: "Temp")

        #expect(bridge.store.hasCluster(endpoint: sensor.endpointID, cluster: .temperatureMeasurement))
    }

    @Test("addHumiditySensor creates endpoint with RelativeHumidityMeasurement cluster")
    func addHumiditySensor() {
        let bridge = MatterBridge()
        let sensor = bridge.addHumiditySensor(name: "Humidity")

        #expect(bridge.store.hasCluster(endpoint: sensor.endpointID, cluster: .relativeHumidityMeasurement))
    }

    @Test("addLightSensor creates endpoint with IlluminanceMeasurement cluster")
    func addLightSensor() {
        let bridge = MatterBridge()
        let sensor = bridge.addLightSensor(name: "Lux")

        #expect(bridge.store.hasCluster(endpoint: sensor.endpointID, cluster: .illuminanceMeasurement))
    }

    // MARK: - New BridgedEndpoint Setters

    @Test("setColorTemperature updates store and colorMode")
    func setColorTemperature() async {
        let bridge = MatterBridge()
        let light = bridge.addColorTemperatureLight(name: "Light")

        await light.setColorTemperature(300)

        #expect(bridge.store.get(endpoint: light.endpointID, cluster: .colorControl, attribute: ColorControlCluster.Attribute.colorTemperatureMireds)?.uintValue == 300)
        #expect(bridge.store.get(endpoint: light.endpointID, cluster: .colorControl, attribute: ColorControlCluster.Attribute.colorMode)?.uintValue == 2)
    }

    @Test("setHue updates store and colorMode")
    func setHue() async {
        let bridge = MatterBridge()
        let light = bridge.addExtendedColorLight(name: "Light")

        await light.setHue(120)

        #expect(bridge.store.get(endpoint: light.endpointID, cluster: .colorControl, attribute: ColorControlCluster.Attribute.currentHue)?.uintValue == 120)
        #expect(bridge.store.get(endpoint: light.endpointID, cluster: .colorControl, attribute: ColorControlCluster.Attribute.colorMode)?.uintValue == 0)
    }

    @Test("setCurrentXY updates store and colorMode")
    func setCurrentXY() async {
        let bridge = MatterBridge()
        let light = bridge.addExtendedColorLight(name: "Light")

        await light.setCurrentXY(x: 24000, y: 25000)

        #expect(bridge.store.get(endpoint: light.endpointID, cluster: .colorControl, attribute: ColorControlCluster.Attribute.currentX)?.uintValue == 24000)
        #expect(bridge.store.get(endpoint: light.endpointID, cluster: .colorControl, attribute: ColorControlCluster.Attribute.currentY)?.uintValue == 25000)
        #expect(bridge.store.get(endpoint: light.endpointID, cluster: .colorControl, attribute: ColorControlCluster.Attribute.colorMode)?.uintValue == 1)
    }

    @Test("setLocalTemperature updates store")
    func setLocalTemperature() async {
        let bridge = MatterBridge()
        let thermo = bridge.addThermostat(name: "Thermo")

        await thermo.setLocalTemperature(2200)

        #expect(bridge.store.get(endpoint: thermo.endpointID, cluster: .thermostat, attribute: ThermostatCluster.Attribute.localTemperature)?.intValue == 2200)
    }

    @Test("setLockState updates store")
    func setLockState() async {
        let bridge = MatterBridge()
        let lock = bridge.addDoorLock(name: "Lock")

        await lock.setLockState(2) // Unlocked

        #expect(bridge.store.get(endpoint: lock.endpointID, cluster: .doorLock, attribute: DoorLockCluster.Attribute.lockState)?.uintValue == 2)
    }

    @Test("setLiftPosition updates store")
    func setLiftPosition() async {
        let bridge = MatterBridge()
        let cover = bridge.addWindowCovering(name: "Blind")

        await cover.setLiftPosition(5000) // 50%

        #expect(bridge.store.get(endpoint: cover.endpointID, cluster: .windowCovering, attribute: WindowCoveringCluster.Attribute.currentPositionLiftPercent100ths)?.uintValue == 5000)
    }

    @Test("setFanMode updates store")
    func setFanMode() async {
        let bridge = MatterBridge()
        let fan = bridge.addFan(name: "Fan")

        await fan.setFanMode(3) // High

        #expect(bridge.store.get(endpoint: fan.endpointID, cluster: .fanControl, attribute: FanControlCluster.Attribute.fanMode)?.uintValue == 3)
    }

    @Test("setFanPercent updates setting and current")
    func setFanPercent() async {
        let bridge = MatterBridge()
        let fan = bridge.addFan(name: "Fan")

        await fan.setFanPercent(75)

        #expect(bridge.store.get(endpoint: fan.endpointID, cluster: .fanControl, attribute: FanControlCluster.Attribute.percentSetting)?.uintValue == 75)
        #expect(bridge.store.get(endpoint: fan.endpointID, cluster: .fanControl, attribute: FanControlCluster.Attribute.percentCurrent)?.uintValue == 75)
    }

    @Test("setTemperature updates store")
    func setTemperature() async {
        let bridge = MatterBridge()
        let sensor = bridge.addTemperatureSensor(name: "Temp")

        await sensor.setTemperature(2350) // 23.50°C

        #expect(bridge.store.get(endpoint: sensor.endpointID, cluster: .temperatureMeasurement, attribute: TemperatureMeasurementCluster.Attribute.measuredValue)?.intValue == 2350)
    }

    @Test("setHumidity updates store")
    func setHumidity() async {
        let bridge = MatterBridge()
        let sensor = bridge.addHumiditySensor(name: "Humid")

        await sensor.setHumidity(6500) // 65.00%

        #expect(bridge.store.get(endpoint: sensor.endpointID, cluster: .relativeHumidityMeasurement, attribute: RelativeHumidityMeasurementCluster.Attribute.measuredValue)?.uintValue == 6500)
    }

    @Test("setOccupancy updates store")
    func setOccupancy() async {
        let bridge = MatterBridge()
        let sensor = bridge.addOccupancySensor(name: "Motion")

        await sensor.setOccupancy(1)

        #expect(bridge.store.get(endpoint: sensor.endpointID, cluster: .occupancySensing, attribute: OccupancySensingCluster.Attribute.occupancy)?.uintValue == 1)
    }

    @Test("setStateValue updates store")
    func setStateValue() async {
        let bridge = MatterBridge()
        let sensor = bridge.addContactSensor(name: "Door")

        await sensor.setStateValue(true) // Open

        #expect(bridge.store.get(endpoint: sensor.endpointID, cluster: .booleanState, attribute: BooleanStateCluster.Attribute.stateValue)?.boolValue == true)
    }

    @Test("setIlluminance updates store")
    func setIlluminance() async {
        let bridge = MatterBridge()
        let sensor = bridge.addLightSensor(name: "Lux")

        await sensor.setIlluminance(5000)

        #expect(bridge.store.get(endpoint: sensor.endpointID, cluster: .illuminanceMeasurement, attribute: IlluminanceMeasurementCluster.Attribute.measuredValue)?.uintValue == 5000)
    }
}
