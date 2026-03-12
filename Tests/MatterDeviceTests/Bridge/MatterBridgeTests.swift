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
        )

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
        )

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
}
