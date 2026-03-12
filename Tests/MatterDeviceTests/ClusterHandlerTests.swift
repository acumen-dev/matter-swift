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
