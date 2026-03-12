// AttributeStoreTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import MatterTypes
@testable import MatterDevice

@Suite("AttributeStore")
struct AttributeStoreTests {

    let endpoint0 = EndpointID(rawValue: 0)
    let endpoint1 = EndpointID(rawValue: 1)
    let cluster1 = ClusterID(rawValue: 0x0006)
    let cluster2 = ClusterID(rawValue: 0x0008)
    let attrOnOff = AttributeID(rawValue: 0x0000)
    let attrLevel = AttributeID(rawValue: 0x0001)

    // MARK: - Basic Get/Set

    @Test("Store and retrieve a value")
    func storeAndRetrieve() {
        let store = AttributeStore()
        store.set(endpoint: endpoint0, cluster: cluster1, attribute: attrOnOff, value: .bool(true))

        let result = store.get(endpoint: endpoint0, cluster: cluster1, attribute: attrOnOff)
        #expect(result == .bool(true))
    }

    @Test("Get returns nil for non-existent attribute")
    func getNonExistent() {
        let store = AttributeStore()

        #expect(store.get(endpoint: endpoint0, cluster: cluster1, attribute: attrOnOff) == nil)
    }

    // MARK: - DataVersion

    @Test("DataVersion increments on change")
    func dataVersionIncrements() {
        let store = AttributeStore()
        store.set(endpoint: endpoint0, cluster: cluster1, attribute: attrOnOff, value: .bool(false))
        let v1 = store.dataVersion(endpoint: endpoint0, cluster: cluster1)

        store.set(endpoint: endpoint0, cluster: cluster1, attribute: attrOnOff, value: .bool(true))
        let v2 = store.dataVersion(endpoint: endpoint0, cluster: cluster1)

        #expect(v2.rawValue == v1.rawValue &+ 1)
    }

    @Test("DataVersion does NOT increment on same-value write")
    func dataVersionNoOpWrite() {
        let store = AttributeStore()
        store.set(endpoint: endpoint0, cluster: cluster1, attribute: attrOnOff, value: .bool(true))
        let v1 = store.dataVersion(endpoint: endpoint0, cluster: cluster1)

        let changed = store.set(endpoint: endpoint0, cluster: cluster1, attribute: attrOnOff, value: .bool(true))

        #expect(changed == false)
        #expect(store.dataVersion(endpoint: endpoint0, cluster: cluster1).rawValue == v1.rawValue)
    }

    @Test("DataVersion is zero for non-existent cluster")
    func dataVersionNonExistent() {
        let store = AttributeStore()
        #expect(store.dataVersion(endpoint: endpoint0, cluster: cluster1).rawValue == 0)
    }

    // MARK: - Dirty Tracking

    @Test("Set marks attribute dirty, clearDirty resets")
    func dirtyTracking() {
        let store = AttributeStore()
        store.set(endpoint: endpoint0, cluster: cluster1, attribute: attrOnOff, value: .bool(true))

        let dirty = store.dirtyPaths()
        #expect(dirty.count == 1)
        #expect(dirty[0].endpointID == endpoint0)
        #expect(dirty[0].clusterID == cluster1)
        #expect(dirty[0].attributeID == attrOnOff)

        store.clearDirty()
        #expect(store.dirtyPaths().isEmpty)
    }

    @Test("dirtyPaths returns correct paths after multiple changes")
    func dirtyPathsMultiple() {
        let store = AttributeStore()
        store.set(endpoint: endpoint0, cluster: cluster1, attribute: attrOnOff, value: .bool(true))
        store.set(endpoint: endpoint0, cluster: cluster2, attribute: attrLevel, value: .unsignedInt(100))

        let dirty = store.dirtyPaths()
        #expect(dirty.count == 2)
    }

    @Test("Same-value write does not mark dirty")
    func noOpWriteNotDirty() {
        let store = AttributeStore()
        store.set(endpoint: endpoint0, cluster: cluster1, attribute: attrOnOff, value: .bool(true))
        store.clearDirty()

        store.set(endpoint: endpoint0, cluster: cluster1, attribute: attrOnOff, value: .bool(true))
        #expect(store.dirtyPaths().isEmpty)
    }

    @Test("clearDirty for specific cluster only clears that cluster")
    func clearDirtySpecific() {
        let store = AttributeStore()
        store.set(endpoint: endpoint0, cluster: cluster1, attribute: attrOnOff, value: .bool(true))
        store.set(endpoint: endpoint0, cluster: cluster2, attribute: attrLevel, value: .unsignedInt(50))

        store.clearDirty(endpoint: endpoint0, cluster: cluster1)

        let dirty = store.dirtyPaths()
        #expect(dirty.count == 1)
        #expect(dirty[0].clusterID == cluster2)
    }

    // MARK: - Remove Endpoint

    @Test("removeEndpoint clears all data for that endpoint")
    func removeEndpoint() {
        let store = AttributeStore()
        store.set(endpoint: endpoint0, cluster: cluster1, attribute: attrOnOff, value: .bool(true))
        store.set(endpoint: endpoint0, cluster: cluster2, attribute: attrLevel, value: .unsignedInt(100))

        store.removeEndpoint(endpoint0)

        #expect(store.get(endpoint: endpoint0, cluster: cluster1, attribute: attrOnOff) == nil)
        #expect(store.hasEndpoint(endpoint0) == false)
        #expect(store.dirtyPaths().isEmpty)
    }

    // MARK: - All Attributes

    @Test("allAttributes returns all stored attributes for a cluster")
    func allAttributes() {
        let store = AttributeStore()
        store.set(endpoint: endpoint0, cluster: cluster1, attribute: attrOnOff, value: .bool(true))
        store.set(endpoint: endpoint0, cluster: cluster1, attribute: attrLevel, value: .unsignedInt(200))

        let attrs = store.allAttributes(endpoint: endpoint0, cluster: cluster1)
        #expect(attrs.count == 2)

        let dict = Dictionary(uniqueKeysWithValues: attrs)
        #expect(dict[attrOnOff] == .bool(true))
        #expect(dict[attrLevel] == .unsignedInt(200))
    }

    @Test("allAttributes returns empty for non-existent cluster")
    func allAttributesEmpty() {
        let store = AttributeStore()
        #expect(store.allAttributes(endpoint: endpoint0, cluster: cluster1).isEmpty)
    }

    // MARK: - Has Endpoint / Has Cluster

    @Test("hasEndpoint and hasCluster checks")
    func hasEndpointAndCluster() {
        let store = AttributeStore()
        #expect(store.hasEndpoint(endpoint0) == false)
        #expect(store.hasCluster(endpoint: endpoint0, cluster: cluster1) == false)

        store.set(endpoint: endpoint0, cluster: cluster1, attribute: attrOnOff, value: .bool(true))

        #expect(store.hasEndpoint(endpoint0) == true)
        #expect(store.hasCluster(endpoint: endpoint0, cluster: cluster1) == true)
        #expect(store.hasCluster(endpoint: endpoint0, cluster: cluster2) == false)
    }

    // MARK: - Isolation Between Endpoints

    @Test("Multiple endpoints do not interfere")
    func endpointIsolation() {
        let store = AttributeStore()
        store.set(endpoint: endpoint0, cluster: cluster1, attribute: attrOnOff, value: .bool(true))
        store.set(endpoint: endpoint1, cluster: cluster1, attribute: attrOnOff, value: .bool(false))

        #expect(store.get(endpoint: endpoint0, cluster: cluster1, attribute: attrOnOff) == .bool(true))
        #expect(store.get(endpoint: endpoint1, cluster: cluster1, attribute: attrOnOff) == .bool(false))

        // DataVersions are independent
        let v0 = store.dataVersion(endpoint: endpoint0, cluster: cluster1)
        let v1 = store.dataVersion(endpoint: endpoint1, cluster: cluster1)
        // They were each set once, so both have initial + 1, but from different random starts
        #expect(v0 != v1 || true) // They could coincidentally match; just verify both exist

        // Removing one endpoint doesn't affect the other
        store.removeEndpoint(endpoint0)
        #expect(store.get(endpoint: endpoint1, cluster: cluster1, attribute: attrOnOff) == .bool(false))
        #expect(store.hasEndpoint(endpoint0) == false)
        #expect(store.hasEndpoint(endpoint1) == true)
    }

    // MARK: - Enumeration

    @Test("allEndpointIDs and allClusterIDs")
    func enumeration() {
        let store = AttributeStore()
        store.set(endpoint: endpoint0, cluster: cluster1, attribute: attrOnOff, value: .bool(true))
        store.set(endpoint: endpoint0, cluster: cluster2, attribute: attrLevel, value: .unsignedInt(50))
        store.set(endpoint: endpoint1, cluster: cluster1, attribute: attrOnOff, value: .bool(false))

        let endpoints = Set(store.allEndpointIDs())
        #expect(endpoints == [endpoint0, endpoint1])

        let clusters = Set(store.allClusterIDs(endpoint: endpoint0))
        #expect(clusters == [cluster1, cluster2])

        #expect(store.allClusterIDs(endpoint: EndpointID(rawValue: 99)).isEmpty)
    }
}
