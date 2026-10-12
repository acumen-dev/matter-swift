// CommissioningCleanupTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
@testable import MatterDevice
import MatterModel
import MatterTypes
import MatterCrypto

/// State a failed or finished commissioning must not leave behind.
///
/// A non-zero Breadcrumb tells a commissioner (the Matter SDK's AutoCommissioner) that
/// an earlier attempt got past AddNOC, so it skips arming the fail-safe and goes
/// straight to operational discovery for a node that was never issued — every later
/// pairing then times out. A removed fabric's operational advert and CommissionedFabrics
/// count must likewise not outlive the fabric.
@Suite("Commissioning cleanup")
struct CommissioningCleanupTests {

    private let ep0 = EndpointID(rawValue: 0)

    private func breadcrumb(_ store: AttributeStore) -> UInt64? {
        store.get(
            endpoint: ep0, cluster: GeneralCommissioningCluster.id,
            attribute: GeneralCommissioningCluster.Attribute.breadcrumb
        )?.uintValue
    }

    private func setBreadcrumb(_ store: AttributeStore, _ value: UInt64) {
        store.set(
            endpoint: ep0, cluster: GeneralCommissioningCluster.id,
            attribute: GeneralCommissioningCluster.Attribute.breadcrumb, value: .unsignedInt(value)
        )
    }

    private func makeServer(bridge: MatterBridge) -> (MatterDeviceServer, MockServerDiscovery) {
        let discovery = MockServerDiscovery()
        let server = MatterDeviceServer(
            bridge: bridge,
            transport: MockServerUDPTransport(),
            discovery: discovery,
            config: .init(discriminator: 3840, passcode: 20202021, port: 5540)
        )
        return (server, discovery)
    }

    /// Poll until `condition` holds. The ceiling is a hang guard, not a latency budget:
    /// passing runs return as soon as the condition is true, and loaded CI runners can
    /// take several seconds to schedule the server's callback tasks.
    private func waitUntil(
        timeout: Duration = .seconds(30),
        _ condition: () async -> Bool
    ) async throws {
        let deadline = ContinuousClock.now + timeout
        while !(await condition()) {
            guard ContinuousClock.now < deadline else { return }
            try await Task.sleep(for: .milliseconds(20))
        }
    }

    private func commitTestFabric(_ state: CommissioningState) throws {
        let (testFabric, _) = try FabricInfo.generateTestFabric()
        state.armFailSafe(expiresAt: Date().addingTimeInterval(60))
        _ = state.generateOperationalKey(csrNonce: Data(repeating: 0x01, count: 32))
        state.stagedRCAC = testFabric.rcac.tlvEncode()
        state.stagedNOC = testFabric.noc.tlvEncode()
        state.stagedIPK = Data(repeating: 0, count: 16)
        state.stagedCaseAdminSubject = 100
        state.stagedAdminVendorId = 0xFFF1
        state.commitCommissioning()
    }

    // MARK: - Breadcrumb

    @Test("CommissioningComplete resets Breadcrumb to zero")
    func commissioningCompleteResetsBreadcrumb() throws {
        let state = CommissioningState()
        state.armFailSafe(expiresAt: Date().addingTimeInterval(60))
        let handler = GeneralCommissioningHandler(commissioningState: state)
        let store = AttributeStore()
        for (attr, value) in handler.initialAttributes() {
            store.set(endpoint: ep0, cluster: GeneralCommissioningCluster.id, attribute: attr, value: value)
        }
        setBreadcrumb(store, 13)

        _ = try handler.handleCommand(
            commandID: GeneralCommissioningCluster.Command.commissioningComplete,
            fields: nil, store: store, endpointID: ep0
        )

        #expect(breadcrumb(store) == 0)
    }

    @Test("Fail-safe expiry resets Breadcrumb to zero")
    func failSafeExpiryResetsBreadcrumb() async throws {
        let bridge = MatterBridge()
        let (server, _) = makeServer(bridge: bridge)
        try await server.start()

        bridge.commissioningState.armFailSafe(expiresAt: Date().addingTimeInterval(1))
        setBreadcrumb(bridge.store, 13)

        try await waitUntil { breadcrumb(bridge.store) == 0 }
        #expect(breadcrumb(bridge.store) == 0)
        #expect(!bridge.commissioningState.isFailSafeArmed)

        await server.stop()
    }

    @Test("A persisted non-zero Breadcrumb is cleared at start — no fail-safe survives a restart")
    func persistedBreadcrumbClearedAtStart() async throws {
        let memStore = InMemoryAttributeStore()
        let previous = AttributeStore(attributeStore: memStore)
        setBreadcrumb(previous, 13)
        await previous.saveToStore()

        let bridge = MatterBridge(attributeStore: memStore)
        let (server, _) = makeServer(bridge: bridge)
        try await server.start()

        #expect(breadcrumb(bridge.store) == 0)

        await server.stop()
    }

    // MARK: - Fabric removal

    @Test("Removing a fabric withdraws its operational advert and updates CommissionedFabrics")
    func fabricRemovalCleansUp() async throws {
        let bridge = MatterBridge()
        try commitTestFabric(bridge.commissioningState)
        let fabricIndex = try #require(bridge.commissioningState.fabrics.keys.first)

        let (server, discovery) = makeServer(bridge: bridge)
        try await server.start()
        try await waitUntil { await !discovery.services(ofType: .operational).isEmpty }
        #expect(await discovery.services(ofType: .operational).count == 1)

        // Remove through CommissioningState directly, as an admin flow does — not via the
        // RemoveFabric command, so the cleanup must live on the shared removal path.
        #expect(bridge.commissioningState.removeFabric(fabricIndex))

        try await waitUntil { await discovery.services(ofType: .operational).isEmpty }
        #expect(await discovery.services(ofType: .operational).isEmpty)

        try await waitUntil {
            bridge.store.get(
                endpoint: ep0, cluster: .operationalCredentials,
                attribute: OperationalCredentialsCluster.Attribute.commissionedFabrics
            )?.uintValue == 0
        }
        let commissioned = bridge.store.get(
            endpoint: ep0, cluster: .operationalCredentials,
            attribute: OperationalCredentialsCluster.Attribute.commissionedFabrics
        )
        #expect(commissioned?.uintValue == 0)

        await server.stop()
    }
}
