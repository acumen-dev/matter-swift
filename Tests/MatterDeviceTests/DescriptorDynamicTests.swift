// DescriptorDynamicTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterModel
@testable import MatterDevice

@Suite("Descriptor Cluster Dynamic Updates")
struct DescriptorDynamicTests {

    // MARK: - Helpers

    private func makeManager() -> (EndpointManager, AttributeStore) {
        let store = AttributeStore()
        let manager = EndpointManager(store: store)

        // Root endpoint (0)
        let rootConfig = EndpointConfig(
            endpointID: EndpointID(rawValue: 0),
            deviceTypes: [(.rootNode, 1)],
            clusterHandlers: [
                DescriptorHandler(deviceTypes: [(.rootNode, 1)], serverClusters: [.descriptor])
            ]
        )
        manager.addEndpoint(rootConfig)

        // Aggregator endpoint (1)
        let aggConfig = EndpointConfig(
            endpointID: EndpointManager.aggregatorEndpoint,
            deviceTypes: [(.aggregator, 1)],
            clusterHandlers: [
                DescriptorHandler(deviceTypes: [(.aggregator, 1)], serverClusters: [.descriptor])
            ]
        )
        manager.addEndpoint(aggConfig)

        return (manager, store)
    }

    private func makeOnOffEndpoint(id: EndpointID) -> EndpointConfig {
        EndpointConfig(
            endpointID: id,
            deviceTypes: [(.onOffLight, 1)],
            clusterHandlers: [
                DescriptorHandler(deviceTypes: [(.onOffLight, 1)], serverClusters: [.onOff, .descriptor]),
                OnOffHandler()
            ]
        )
    }

    private func partsList(store: AttributeStore) -> [UInt16] {
        guard case .array(let elements) = store.get(
            endpoint: EndpointManager.aggregatorEndpoint,
            cluster: .descriptor,
            attribute: DescriptorCluster.Attribute.partsList
        ) else { return [] }
        return elements.compactMap { $0.uintValue.map { UInt16($0) } }
    }

    private func serverList(store: AttributeStore, endpoint: EndpointID) -> [UInt32] {
        guard case .array(let elements) = store.get(
            endpoint: endpoint,
            cluster: .descriptor,
            attribute: DescriptorCluster.Attribute.serverList
        ) else { return [] }
        return elements.compactMap { $0.uintValue.map { UInt32($0) } }
    }

    // MARK: - Test 1: Adding endpoint updates aggregator PartsList

    @Test("Adding an endpoint to the bridge updates aggregator PartsList")
    func addEndpointUpdatesPartsList() {
        let (manager, store) = makeManager()

        let ep3 = EndpointID(rawValue: 3)
        let ep4 = EndpointID(rawValue: 4)

        // Initially empty
        let empty = partsList(store: store)
        #expect(empty.isEmpty)

        // Add first endpoint
        manager.addEndpoint(makeOnOffEndpoint(id: ep3))
        let afterFirst = partsList(store: store)
        #expect(afterFirst.count == 1)
        #expect(afterFirst.contains(3))

        // Add second endpoint
        manager.addEndpoint(makeOnOffEndpoint(id: ep4))
        let afterSecond = partsList(store: store)
        #expect(afterSecond.count == 2)
        #expect(afterSecond.contains(3))
        #expect(afterSecond.contains(4))
    }

    // MARK: - Test 2: Removing endpoint updates aggregator PartsList

    @Test("Removing an endpoint updates aggregator PartsList")
    func removeEndpointUpdatesPartsList() {
        let (manager, store) = makeManager()

        let ep3 = EndpointID(rawValue: 3)
        let ep4 = EndpointID(rawValue: 4)
        let ep5 = EndpointID(rawValue: 5)

        manager.addEndpoint(makeOnOffEndpoint(id: ep3))
        manager.addEndpoint(makeOnOffEndpoint(id: ep4))
        manager.addEndpoint(makeOnOffEndpoint(id: ep5))

        var parts = partsList(store: store)
        #expect(parts.count == 3)
        #expect(parts.contains(3))
        #expect(parts.contains(4))
        #expect(parts.contains(5))

        // Remove ep4
        manager.removeEndpoint(ep4)
        parts = partsList(store: store)
        #expect(parts.count == 2)
        #expect(parts.contains(3))
        #expect(!parts.contains(4))
        #expect(parts.contains(5))

        // Remove ep3
        manager.removeEndpoint(ep3)
        parts = partsList(store: store)
        #expect(parts.count == 1)
        #expect(!parts.contains(3))
        #expect(parts.contains(5))

        // Remove last
        manager.removeEndpoint(ep5)
        parts = partsList(store: store)
        #expect(parts.isEmpty)
    }

    // MARK: - Test 3: ServerClusterList matches registered handler cluster IDs

    @Test("Registered endpoint has ServerClusterList matching its handler cluster IDs")
    func serverClusterListMatchesHandlers() {
        let (manager, store) = makeManager()

        let ep3 = EndpointID(rawValue: 3)

        // EndpointConfig with OnOff + LevelControl + Descriptor handlers
        let config = EndpointConfig(
            endpointID: ep3,
            deviceTypes: [(.dimmableLight, 1)],
            clusterHandlers: [
                OnOffHandler(),
                LevelControlHandler(),
                DescriptorHandler(deviceTypes: [(.dimmableLight, 1)], serverClusters: [])
            ]
        )
        manager.addEndpoint(config)

        let serverClusters = serverList(store: store, endpoint: ep3)

        // Should contain all three handler cluster IDs
        let expectedIDs: Set<UInt32> = [
            ClusterID.onOff.rawValue,
            ClusterID.levelControl.rawValue,
            ClusterID.descriptor.rawValue
        ]
        let actualIDs = Set(serverClusters)
        #expect(actualIDs == expectedIDs)

        // Should be sorted ascending
        #expect(serverClusters == serverClusters.sorted())
    }

    // MARK: - Additional: Bridge PartsList through MatterBridge

    @Test("MatterBridge addDimmableLight updates aggregator PartsList")
    func matterBridgeAddUpdatesPartsList() {
        let bridge = MatterBridge()

        // Initially no bridged endpoints
        let empty = partsList(store: bridge.store)
        #expect(empty.isEmpty)

        // Add a light
        let light = bridge.addDimmableLight(name: "Kitchen")
        let afterAdd = partsList(store: bridge.store)
        #expect(afterAdd.count == 1)
        #expect(afterAdd.contains(light.endpointID.rawValue))

        // Remove it
        bridge.removeEndpoint(light)
        let afterRemove = partsList(store: bridge.store)
        #expect(afterRemove.isEmpty)
    }

    @Test("MatterBridge endpoints have ServerClusterList populated from handlers")
    func matterBridgeServerClusterListPopulated() {
        let bridge = MatterBridge()
        let light = bridge.addDimmableLight(name: "Bedroom")

        let srvList = serverList(store: bridge.store, endpoint: light.endpointID)

        // Dimmable light should have OnOff, LevelControl, Groups, BridgedDeviceBasicInformation, Descriptor
        let expectedIDs: Set<UInt32> = [
            ClusterID.onOff.rawValue,
            ClusterID.levelControl.rawValue,
            ClusterID.groups.rawValue,
            ClusterID.bridgedDeviceBasicInformation.rawValue,
            ClusterID.descriptor.rawValue
        ]
        let actualIDs = Set(srvList)
        #expect(actualIDs == expectedIDs)
    }
}
