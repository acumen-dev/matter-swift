// BridgeAttributeCacheTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterModel
import MatterProtocol
import MatterTestSupport
@testable import MatterDevice

/// A restart must not restore a stale endpoint set from the attribute cache, and
/// endpoint-set changes reach subscribers and the cache (acumen-dev/matter-swift#55, part 2).
///
/// Waits have no deadlines of their own: the suite's `.timeLimit` is the only hang guard.
@Suite("Bridge Attribute Cache", .timeLimit(.minutes(1)))
struct BridgeAttributeCacheTests {

    // MARK: - Helpers

    private func ep(_ raw: UInt16) -> EndpointID { EndpointID(rawValue: raw) }

    private func makeServer(_ bridge: MatterBridge) -> (MatterDeviceServer, MockServerDiscovery) {
        let discovery = MockServerDiscovery()
        let server = MatterDeviceServer(
            bridge: bridge,
            transport: MockServerUDPTransport(),
            discovery: discovery,
            config: .init(discriminator: 3840, passcode: 20202021, port: 5540)
        )
        return (server, discovery)
    }

    /// Stop once the window-open advertisement has landed, so `stop()` doesn't race it.
    private func stop(_ server: MatterDeviceServer, _ discovery: MockServerDiscovery) async throws {
        try await pollUntil { await discovery.isAdvertising }
        await server.stop()
    }

    private func partsList(_ bridge: MatterBridge, on endpoint: EndpointID) -> [UInt64]? {
        bridge.store.get(endpoint: endpoint, cluster: .descriptor, attribute: DescriptorCluster.Attribute.partsList)?
            .arrayElements?.compactMap { $0.uintValue }
    }

    private func readPartsList(_ bridge: MatterBridge, on endpoint: EndpointID) throws -> (parts: [UInt64], version: DataVersion) {
        let reports = bridge.endpoints.readAttributes([
            AttributePath(endpointID: endpoint, clusterID: .descriptor, attributeID: DescriptorCluster.Attribute.partsList)
        ])
        let data = try #require(reports.first?.attributeData)
        let elements = try #require(data.data.arrayElements)
        let version = try #require(data.dataVersion)
        return (elements.compactMap { $0.uintValue }, version)
    }

    private func bridgedString(_ bridge: MatterBridge, _ endpoint: EndpointID, _ attribute: AttributeID) -> String? {
        bridge.store.get(endpoint: endpoint, cluster: .bridgedDeviceBasicInformation, attribute: attribute)?.stringValue
    }

    private func cachedEndpoints(_ store: InMemoryAttributeStore) async throws -> Set<UInt16> {
        guard let data = try await store.load() else { return [] }
        return Set(data.clusters.keys.map(\.endpointID))
    }

    // MARK: - Restart With a Stale Cache

    @Test("After a restart with a stale cache, PartsList reflects the live set with a bumped DataVersion")
    func restartReflectsLiveEndpointSet() async throws {
        let fabricStore = InMemoryFabricStore()
        let attributeStore = InMemoryAttributeStore()

        // Run 1: A and B, cached as at commissioning.
        let first = try await MatterBridge(fabricStore: fabricStore, attributeStore: attributeStore)
        let a = first.addOnOffLight(name: "A", uniqueID: "dev-a")
        let b = first.addOnOffLight(name: "B", uniqueID: "dev-b")
        #expect(a.endpointID == ep(3))
        #expect(b.endpointID == ep(4))
        await a.setOnOff(true)
        await first.store.saveToStore()
        let cachedVersion = first.store.dataVersion(endpoint: ep(1), cluster: .descriptor)

        // Run 2: B is gone, C is new, A is renamed.
        let second = try await MatterBridge(fabricStore: fabricStore, attributeStore: attributeStore)
        second.addOnOffLight(name: "A (renamed)", uniqueID: "dev-a")
        let c = second.addOnOffLight(name: "C", uniqueID: "dev-c")
        #expect(c.endpointID == ep(5))

        let (server, discovery) = makeServer(second)
        try await server.start()

        let aggregator = try readPartsList(second, on: ep(1))
        #expect(aggregator.parts == [3, 5])
        #expect(aggregator.version.rawValue == cachedVersion.rawValue &+ 1)
        #expect(partsList(second, on: ep(0)) == [1, 3, 5])

        // The removed endpoint's cached values are not restored.
        #expect(!second.store.hasEndpoint(ep(4)))

        // A's cached state is restored; its identity follows the live registration.
        #expect(second.store.get(endpoint: ep(3), cluster: .onOff, attribute: OnOffCluster.Attribute.onOff) == .bool(true))
        #expect(bridgedString(second, ep(3), BridgedDeviceBasicInfoCluster.Attribute.nodeLabel) == "A (renamed)")

        try await stop(server, discovery)
    }

    @Test("An endpoint now held by a different device does not take the old device's cached identity or state")
    func renumberedEndpointKeepsLiveIdentity() async throws {
        // No fabric store: IDs are sequential, so B lands on A's old endpoint.
        let attributeStore = InMemoryAttributeStore()

        let first = MatterBridge(attributeStore: attributeStore)
        let a = first.addOnOffLight(name: "A", uniqueID: "dev-a")
        await a.setOnOff(true)
        await first.store.saveToStore()
        let cachedVersion = first.store.dataVersion(endpoint: ep(3), cluster: .bridgedDeviceBasicInformation)

        let second = MatterBridge(attributeStore: attributeStore)
        let b = second.addOnOffLight(name: "B", uniqueID: "dev-b")
        #expect(b.endpointID == ep(3))

        let (server, discovery) = makeServer(second)
        try await server.start()

        #expect(bridgedString(second, ep(3), BridgedDeviceBasicInfoCluster.Attribute.uniqueID) == "dev-b")
        #expect(bridgedString(second, ep(3), BridgedDeviceBasicInfoCluster.Attribute.nodeLabel) == "B")
        #expect(second.store.get(endpoint: ep(3), cluster: .onOff, attribute: OnOffCluster.Attribute.onOff) == .bool(false))
        #expect(second.store.dataVersion(endpoint: ep(3), cluster: .bridgedDeviceBasicInformation) != cachedVersion)

        try await stop(server, discovery)
    }

    @Test("A cluster whose restored contents match the cache keeps the cached DataVersion")
    func unchangedClusterKeepsCachedVersion() async throws {
        let fabricStore = InMemoryFabricStore()
        let attributeStore = InMemoryAttributeStore()

        let first = try await MatterBridge(fabricStore: fabricStore, attributeStore: attributeStore)
        first.addOnOffLight(name: "A", uniqueID: "dev-a")
        await first.store.saveToStore()
        let cachedOnOff = first.store.dataVersion(endpoint: ep(3), cluster: .onOff)
        let cachedAggregator = first.store.dataVersion(endpoint: ep(1), cluster: .descriptor)

        let second = try await MatterBridge(fabricStore: fabricStore, attributeStore: attributeStore)
        second.addOnOffLight(name: "A", uniqueID: "dev-a")
        let (server, discovery) = makeServer(second)
        try await server.start()

        #expect(second.store.dataVersion(endpoint: ep(3), cluster: .onOff) == cachedOnOff)
        #expect(second.store.dataVersion(endpoint: ep(1), cluster: .descriptor) == cachedAggregator)

        try await stop(server, discovery)
    }

    // MARK: - Persisting the Cache

    @Test("The attribute cache is saved on stop()")
    func cacheSavedOnStop() async throws {
        let attributeStore = InMemoryAttributeStore()
        let bridge = MatterBridge(attributeStore: attributeStore)
        bridge.addOnOffLight(name: "A", uniqueID: "dev-a")

        let (server, discovery) = makeServer(bridge)
        try await server.start()
        try await stop(server, discovery)

        #expect(try await cachedEndpoints(attributeStore).contains(3))
    }

    @Test("The attribute cache is saved when the endpoint set changes after start, never before")
    func cacheSavedOnEndpointSetChange() async throws {
        let attributeStore = InMemoryAttributeStore()
        let bridge = MatterBridge(attributeStore: attributeStore)
        let a = bridge.addOnOffLight(name: "A", uniqueID: "dev-a")
        // Before the cache has been loaded, saving would replace it with fresh values.
        #expect(await attributeStore.saveCount == 0)

        let (server, discovery) = makeServer(bridge)
        try await server.start()

        let b = bridge.addOnOffLight(name: "B", uniqueID: "dev-b")
        try await pollUntil { try await cachedEndpoints(attributeStore).contains(b.endpointID.rawValue) }

        bridge.removeEndpoint(a)
        try await pollUntil { try await !cachedEndpoints(attributeStore).contains(a.endpointID.rawValue) }

        try await stop(server, discovery)
    }

    // MARK: - Subscribers

    @Test("A subscriber to the aggregator Descriptor receives a report when an endpoint is added at runtime")
    func subscriberReportedOnRuntimeAdd() async throws {
        let bridge = MatterBridge()
        bridge.addOnOffLight(name: "A", uniqueID: "dev-a")

        let subscribe = SubscribeRequest(
            minIntervalFloor: 0,
            maxIntervalCeiling: 60,
            attributeRequests: [
                AttributePath(endpointID: ep(1), clusterID: .descriptor, attributeID: DescriptorCluster.Attribute.partsList)
            ]
        )
        let responses = try await bridge.handleIM(
            opcode: .subscribeRequest,
            payload: subscribe.tlvEncode(),
            sessionID: 1,
            fabricIndex: FabricIndex(rawValue: 1)
        ).allPairs
        let subscriptionID = try SubscribeResponse.fromTLV(responses[1].1).subscriptionID
        bridge.store.clearDirty()
        #expect(await bridge.pendingReports().isEmpty)

        bridge.addOnOffLight(name: "B", uniqueID: "dev-b")

        try await pollUntil { await !bridge.pendingReports().isEmpty }
        let pending = await bridge.pendingReports()
        #expect(pending.first?.subscriptionID == subscriptionID)
        let first = try #require(pending.first)
        let chunks = try #require(await bridge.buildReport(for: first))
        let parts = chunks.flatMap(\.attributeReports).compactMap(\.attributeData)
            .compactMap { $0.data.arrayElements?.compactMap { $0.uintValue } }
        #expect(parts == [[3, 4]])
    }

    @Test("Removing an endpoint updates both PartsLists and reports it to subscribers")
    func removalUpdatesBothPartsLists() async throws {
        let bridge = MatterBridge()
        let a = bridge.addOnOffLight(name: "A", uniqueID: "dev-a")
        bridge.addOnOffLight(name: "B", uniqueID: "dev-b")

        let subscribe = SubscribeRequest(
            minIntervalFloor: 0,
            maxIntervalCeiling: 60,
            attributeRequests: [
                AttributePath(endpointID: ep(0), clusterID: .descriptor, attributeID: DescriptorCluster.Attribute.partsList)
            ]
        )
        _ = try await bridge.handleIM(
            opcode: .subscribeRequest,
            payload: subscribe.tlvEncode(),
            sessionID: 1,
            fabricIndex: FabricIndex(rawValue: 1)
        )
        bridge.store.clearDirty()

        bridge.removeEndpoint(a)

        #expect(partsList(bridge, on: ep(0)) == [1, 4])
        #expect(partsList(bridge, on: ep(1)) == [4])
        try await pollUntil { await !bridge.pendingReports().isEmpty }
    }
}
