// EndpointManagerTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import MatterTypes
import MatterModel
import MatterProtocol
@testable import MatterDevice

@Suite("Endpoint Manager")
struct EndpointManagerTests {

    // MARK: - Helpers

    /// Create a test endpoint with OnOff + Descriptor clusters.
    private func makeOnOffEndpoint(id: EndpointID) -> EndpointConfig {
        EndpointConfig(
            endpointID: id,
            deviceTypes: [(.onOffLight, 1)],
            clusterHandlers: [
                DescriptorHandler(deviceTypes: [(.onOffLight, 1)], serverClusters: [.onOff]),
                OnOffHandler()
            ]
        )
    }

    /// Create an aggregator endpoint with Descriptor cluster.
    private func makeAggregatorEndpoint() -> EndpointConfig {
        EndpointConfig(
            endpointID: EndpointManager.aggregatorEndpoint,
            deviceTypes: [(.aggregator, 1)],
            clusterHandlers: [
                DescriptorHandler(deviceTypes: [(.aggregator, 1)], serverClusters: [.descriptor])
            ]
        )
    }

    /// Create an EndpointManager pre-loaded with an aggregator endpoint.
    private func makeManager() -> (EndpointManager, AttributeStore) {
        let store = AttributeStore()
        let manager = EndpointManager(store: store)
        manager.addEndpoint(makeAggregatorEndpoint())
        return (manager, store)
    }

    // MARK: - Registration Tests

    @Test("Add endpoint populates attribute store with initial attributes")
    func addEndpointPopulatesStore() {
        let (manager, store) = makeManager()
        let ep = EndpointID(rawValue: 3)
        manager.addEndpoint(makeOnOffEndpoint(id: ep))

        // OnOff initial attribute should be present
        let onOff = store.get(endpoint: ep, cluster: .onOff, attribute: OnOffCluster.Attribute.onOff)
        #expect(onOff == .bool(false))

        // Descriptor device type list should be present
        let deviceTypes = store.get(endpoint: ep, cluster: .descriptor, attribute: DescriptorCluster.Attribute.deviceTypeList)
        #expect(deviceTypes != nil)
        if case .array(let elements) = deviceTypes {
            #expect(elements.count == 1)
        } else {
            Issue.record("deviceTypeList should be an array")
        }
    }

    @Test("nextEndpointID increments correctly")
    func nextEndpointIDIncrements() {
        let store = AttributeStore()
        let manager = EndpointManager(store: store)

        let first = manager.nextEndpointID()
        let second = manager.nextEndpointID()
        let third = manager.nextEndpointID()

        #expect(first.rawValue == 3)
        #expect(second.rawValue == 4)
        #expect(third.rawValue == 5)
    }

    // MARK: - Read Tests

    @Test("Read attribute returns correct value")
    func readAttributeReturnsValue() {
        let (manager, _) = makeManager()
        let ep = EndpointID(rawValue: 3)
        manager.addEndpoint(makeOnOffEndpoint(id: ep))

        let reports = manager.readAttributes([
            AttributePath(endpointID: ep, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff)
        ])

        #expect(reports.count == 1)
        #expect(reports[0].attributeData?.data == .bool(false))
        #expect(reports[0].attributeData?.path.endpointID == ep)
    }

    @Test("Read with non-existent endpoint returns unsupported endpoint status")
    func readNonExistentEndpoint() {
        let (manager, _) = makeManager()
        let badEP = EndpointID(rawValue: 99)

        let reports = manager.readAttributes([
            AttributePath(endpointID: badEP, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff)
        ])

        #expect(reports.count == 1)
        #expect(reports[0].attributeStatus?.status == .unsupportedEndpoint)
    }

    @Test("Read with non-existent cluster returns unsupported cluster status")
    func readNonExistentCluster() {
        let (manager, _) = makeManager()
        let ep = EndpointID(rawValue: 3)
        manager.addEndpoint(makeOnOffEndpoint(id: ep))

        let reports = manager.readAttributes([
            AttributePath(endpointID: ep, clusterID: .levelControl, attributeID: AttributeID(rawValue: 0))
        ])

        #expect(reports.count == 1)
        #expect(reports[0].attributeStatus?.status == .unsupportedCluster)
    }

    @Test("Read with wildcard endpointID returns data from all endpoints")
    func readWildcardEndpoint() {
        let (manager, _) = makeManager()
        let ep3 = EndpointID(rawValue: 3)
        let ep4 = EndpointID(rawValue: 4)
        manager.addEndpoint(makeOnOffEndpoint(id: ep3))
        manager.addEndpoint(makeOnOffEndpoint(id: ep4))

        // Wildcard read (endpointID = nil)
        let reports = manager.readAttributes([
            AttributePath(endpointID: nil, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff)
        ])

        // Should get data from ep3 and ep4 (aggregator doesn't have onOff)
        let dataReports = reports.filter { $0.attributeData != nil }
        #expect(dataReports.count == 2)

        let endpointIDs = Set(dataReports.compactMap { $0.attributeData?.path.endpointID })
        #expect(endpointIDs.contains(ep3))
        #expect(endpointIDs.contains(ep4))
    }

    @Test("Read non-existent attribute returns unsupported attribute status")
    func readNonExistentAttribute() {
        let (manager, _) = makeManager()
        let ep = EndpointID(rawValue: 3)
        manager.addEndpoint(makeOnOffEndpoint(id: ep))

        let reports = manager.readAttributes([
            AttributePath(endpointID: ep, clusterID: .onOff, attributeID: AttributeID(rawValue: 0xFFFF))
        ])

        #expect(reports.count == 1)
        #expect(reports[0].attributeStatus?.status == .unsupportedAttribute)
    }

    // MARK: - Write Tests

    @Test("Write to writable attribute succeeds")
    func writeWritableAttribute() {
        let (manager, store) = makeManager()
        let ep = EndpointID(rawValue: 3)
        manager.addEndpoint(makeOnOffEndpoint(id: ep))

        let statuses = manager.writeAttributes([
            AttributeDataIB(
                dataVersion: DataVersion(rawValue: 0),
                path: AttributePath(endpointID: ep, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff),
                data: .bool(true)
            )
        ])

        #expect(statuses.count == 1)
        #expect(statuses[0].status == .success)

        // Verify the value was written
        let value = store.get(endpoint: ep, cluster: .onOff, attribute: OnOffCluster.Attribute.onOff)
        #expect(value == .bool(true))
    }

    @Test("Write to read-only attribute returns error")
    func writeReadOnlyAttribute() {
        let (manager, _) = makeManager()
        let ep = EndpointID(rawValue: 3)
        manager.addEndpoint(makeOnOffEndpoint(id: ep))

        // Descriptor attributes are read-only
        let statuses = manager.writeAttributes([
            AttributeDataIB(
                dataVersion: DataVersion(rawValue: 0),
                path: AttributePath(endpointID: ep, clusterID: .descriptor, attributeID: DescriptorCluster.Attribute.deviceTypeList),
                data: .array([])
            )
        ])

        #expect(statuses.count == 1)
        #expect(statuses[0].status == .unsupportedWrite)
    }

    @Test("Write to non-existent endpoint returns unsupported endpoint")
    func writeNonExistentEndpoint() {
        let (manager, _) = makeManager()

        let statuses = manager.writeAttributes([
            AttributeDataIB(
                dataVersion: DataVersion(rawValue: 0),
                path: AttributePath(endpointID: EndpointID(rawValue: 99), clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff),
                data: .bool(true)
            )
        ])

        #expect(statuses.count == 1)
        #expect(statuses[0].status == .unsupportedEndpoint)
    }

    // MARK: - Command Tests

    @Test("Invoke On command changes attribute in store")
    func invokeOnCommand() async throws {
        let (manager, store) = makeManager()
        let ep = EndpointID(rawValue: 3)
        manager.addEndpoint(makeOnOffEndpoint(id: ep))

        _ = try await manager.handleCommand(
            path: CommandPath(endpointID: ep, clusterID: .onOff, commandID: OnOffCluster.Command.on),
            fields: nil
        )

        let value = store.get(endpoint: ep, cluster: .onOff, attribute: OnOffCluster.Attribute.onOff)
        #expect(value == .bool(true))
    }

    @Test("Invoke Toggle command flips state")
    func invokeToggleCommand() async throws {
        let (manager, store) = makeManager()
        let ep = EndpointID(rawValue: 3)
        manager.addEndpoint(makeOnOffEndpoint(id: ep))

        // Initial state is false, toggle should make it true
        _ = try await manager.handleCommand(
            path: CommandPath(endpointID: ep, clusterID: .onOff, commandID: OnOffCluster.Command.toggle),
            fields: nil
        )

        let value1 = store.get(endpoint: ep, cluster: .onOff, attribute: OnOffCluster.Attribute.onOff)
        #expect(value1 == .bool(true))

        // Toggle again should make it false
        _ = try await manager.handleCommand(
            path: CommandPath(endpointID: ep, clusterID: .onOff, commandID: OnOffCluster.Command.toggle),
            fields: nil
        )

        let value2 = store.get(endpoint: ep, cluster: .onOff, attribute: OnOffCluster.Attribute.onOff)
        #expect(value2 == .bool(false))
    }

    @Test("Handle command on non-existent endpoint returns nil response")
    func commandNonExistentEndpoint() async throws {
        let (manager, _) = makeManager()

        let (response, _) = try await manager.handleCommand(
            path: CommandPath(endpointID: EndpointID(rawValue: 99), clusterID: .onOff, commandID: OnOffCluster.Command.on),
            fields: nil
        )

        #expect(response == nil)
    }

    // MARK: - Remove & PartsList Tests

    @Test("Remove endpoint clears store and updates PartsList")
    func removeEndpointClearsStoreAndUpdatesParts() {
        let (manager, store) = makeManager()
        let ep = EndpointID(rawValue: 3)
        manager.addEndpoint(makeOnOffEndpoint(id: ep))

        // Verify endpoint exists in store
        #expect(store.hasEndpoint(ep))

        // Remove
        manager.removeEndpoint(ep)

        // Store should be cleared for this endpoint
        #expect(!store.hasEndpoint(ep))

        // Manager should no longer know about it
        #expect(manager.endpoint(for: ep) == nil)

        // PartsList should be empty (no dynamic endpoints left)
        let partsList = store.get(
            endpoint: EndpointManager.aggregatorEndpoint,
            cluster: .descriptor,
            attribute: DescriptorCluster.Attribute.partsList
        )
        #expect(partsList == .array([]))
    }

    @Test("PartsList reflects current dynamic endpoints")
    func partsListReflectsDynamicEndpoints() {
        let (manager, store) = makeManager()

        let ep3 = EndpointID(rawValue: 3)
        let ep4 = EndpointID(rawValue: 4)
        let ep5 = EndpointID(rawValue: 5)

        manager.addEndpoint(makeOnOffEndpoint(id: ep3))
        manager.addEndpoint(makeOnOffEndpoint(id: ep4))
        manager.addEndpoint(makeOnOffEndpoint(id: ep5))

        // PartsList should contain 3, 4, 5
        let partsList = store.get(
            endpoint: EndpointManager.aggregatorEndpoint,
            cluster: .descriptor,
            attribute: DescriptorCluster.Attribute.partsList
        )
        guard case .array(let elements) = partsList else {
            Issue.record("PartsList should be an array")
            return
        }

        let ids = elements.compactMap { $0.uintValue }.map { UInt16($0) }
        #expect(ids.contains(3))
        #expect(ids.contains(4))
        #expect(ids.contains(5))
        #expect(ids.count == 3)

        // Remove one
        manager.removeEndpoint(ep4)

        let updatedPartsList = store.get(
            endpoint: EndpointManager.aggregatorEndpoint,
            cluster: .descriptor,
            attribute: DescriptorCluster.Attribute.partsList
        )
        guard case .array(let updatedElements) = updatedPartsList else {
            Issue.record("Updated PartsList should be an array")
            return
        }

        let updatedIDs = updatedElements.compactMap { $0.uintValue }.map { UInt16($0) }
        #expect(updatedIDs.contains(3))
        #expect(!updatedIDs.contains(4))
        #expect(updatedIDs.contains(5))
        #expect(updatedIDs.count == 2)
    }

    // MARK: - Multiple Endpoints

    @Test("Multiple endpoints work independently")
    func multipleEndpointsIndependent() async throws {
        let (manager, store) = makeManager()
        let ep3 = EndpointID(rawValue: 3)
        let ep4 = EndpointID(rawValue: 4)
        manager.addEndpoint(makeOnOffEndpoint(id: ep3))
        manager.addEndpoint(makeOnOffEndpoint(id: ep4))

        // Turn on ep3 only
        _ = try await manager.handleCommand(
            path: CommandPath(endpointID: ep3, clusterID: .onOff, commandID: OnOffCluster.Command.on),
            fields: nil
        )

        // ep3 should be on
        let value3 = store.get(endpoint: ep3, cluster: .onOff, attribute: OnOffCluster.Attribute.onOff)
        #expect(value3 == .bool(true))

        // ep4 should still be off
        let value4 = store.get(endpoint: ep4, cluster: .onOff, attribute: OnOffCluster.Attribute.onOff)
        #expect(value4 == .bool(false))
    }
}
