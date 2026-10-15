// BridgeEndpointIdentityTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterModel
import MatterProtocol
import MatterTestSupport
@testable import MatterDevice

/// Stable bridged endpoint IDs, keyed by `uniqueID` and persisted through the
/// fabric store (acumen-dev/matter-swift#55, part 1).
///
/// Waits have no deadlines of their own: the suite's `.timeLimit` is the only hang guard.
@Suite("Bridge Endpoint Identity", .timeLimit(.minutes(1)))
struct BridgeEndpointIdentityTests {

    // MARK: - Helpers

    private func ep(_ raw: UInt16) -> EndpointID { EndpointID(rawValue: raw) }

    /// Wait until the fabric store's saved state satisfies `condition`.
    private func waitForSaved(
        _ store: InMemoryFabricStore,
        _ condition: @escaping @Sendable (StoredDeviceState) -> Bool
    ) async throws {
        try await pollUntil {
            guard let state = try await store.load() else { return false }
            return condition(state)
        }
    }

    // MARK: - Stable IDs Across Restarts

    @Test("Adding a device ahead of an existing one keeps the existing endpoint's ID across a restart")
    func existingIDSurvivesInsertionAhead() async throws {
        let fabricStore = InMemoryFabricStore()

        let first = try await MatterBridge(fabricStore: fabricStore)
        let switchA = first.addOnOffPlugInUnit(name: "Switch A", uniqueID: "dev-a")
        #expect(switchA.endpointID == ep(3))
        try await waitForSaved(fabricStore) { $0.bridgedEndpointIDs["dev-a"] == 3 }

        // Restart: the host now registers a new device before the existing one.
        let second = try await MatterBridge(fabricStore: fabricStore)
        let lightB = second.addOnOffLight(name: "Light B", uniqueID: "dev-b")
        let switchA2 = second.addOnOffPlugInUnit(name: "Switch A", uniqueID: "dev-a")

        #expect(switchA2.endpointID == ep(3))
        #expect(lightB.endpointID == ep(4))
    }

    @Test("Removing a device then adding a different one never reuses its ID, in-run or across a restart")
    func removedIDIsNeverReused() async throws {
        let fabricStore = InMemoryFabricStore()

        let first = try await MatterBridge(fabricStore: fabricStore)
        let a = first.addOnOffLight(name: "A", uniqueID: "dev-a")
        #expect(a.endpointID == ep(3))
        first.removeEndpoint(a)
        let b = first.addOnOffLight(name: "B", uniqueID: "dev-b")
        #expect(b.endpointID == ep(4))
        try await waitForSaved(fabricStore) {
            $0.bridgedEndpointIDs["dev-b"] == 4 && $0.highestBridgedEndpointID == 4
        }

        // Restart with only a brand-new device: it must not land on 3 (A's) or 4 (B's).
        let second = try await MatterBridge(fabricStore: fabricStore)
        let c = second.addOnOffLight(name: "C", uniqueID: "dev-c")
        #expect(c.endpointID == ep(5))

        // A returning device gets its own ID back.
        let aAgain = second.addOnOffLight(name: "A", uniqueID: "dev-a")
        #expect(aAgain.endpointID == ep(3))
    }

    @Test("Without a fabric store, IDs are sequential from 3 in call order, as before")
    func noStoreIsSequential() async throws {
        let bridge = MatterBridge()
        let a = bridge.addOnOffLight(name: "A", uniqueID: "dev-a")
        let b = bridge.addOnOffLight(name: "B", uniqueID: "dev-b")
        #expect(a.endpointID == ep(3))
        #expect(b.endpointID == ep(4))

        bridge.removeEndpoint(a)
        let aAgain = bridge.addOnOffLight(name: "A", uniqueID: "dev-a")
        let unkeyed = bridge.addOnOffLight(name: "No ID")
        #expect(aAgain.endpointID == ep(5))
        #expect(unkeyed.endpointID == ep(6))

        // Loading is a no-op without a store and does not change allocation.
        try await bridge.loadPersistedState()
        #expect(bridge.addOnOffLight(name: "D", uniqueID: "dev-d").endpointID == ep(7))
    }

    @Test("An empty stored map assigns in call order (existing installations keep their numbers)")
    func emptyMapAssignsInCallOrder() async throws {
        let fabricStore = InMemoryFabricStore(state: StoredDeviceState(nextFabricIndex: 2))
        let bridge = try await MatterBridge(fabricStore: fabricStore)
        #expect(bridge.addOnOffLight(name: "A", uniqueID: "dev-a").endpointID == ep(3))
        #expect(bridge.addOnOffLight(name: "B", uniqueID: "dev-b").endpointID == ep(4))
        try await waitForSaved(fabricStore) {
            $0.bridgedEndpointIDs == ["dev-a": 3, "dev-b": 4] && $0.highestBridgedEndpointID == 4
        }
    }

    @Test("Saving an allocation goes through the fabric store and keeps the fabric state")
    func allocationSaveKeepsFabricState() async throws {
        let salt = Data(repeating: 0xAB, count: 16)
        let fabricStore = InMemoryFabricStore(state: StoredDeviceState(
            nextFabricIndex: 5,
            pbkdfSalt: salt,
            pbkdfIterations: 2000
        ))
        let bridge = try await MatterBridge(fabricStore: fabricStore)
        bridge.addOnOffLight(name: "A", uniqueID: "dev-a")

        try await waitForSaved(fabricStore) { $0.bridgedEndpointIDs["dev-a"] == 3 }
        let saved = try #require(try await fabricStore.load())
        #expect(saved.nextFabricIndex == 5)
        #expect(saved.pbkdfSalt == salt)
        #expect(saved.pbkdfIterations == 2000)
    }

    @Test("Two live devices with the same uniqueID never share an endpoint")
    func duplicateUniqueIDGetsDistinctEndpoint() async throws {
        let fabricStore = InMemoryFabricStore()
        let bridge = try await MatterBridge(fabricStore: fabricStore)
        let first = bridge.addOnOffLight(name: "A", uniqueID: "dev-a")
        let second = bridge.addOnOffLight(name: "A again", uniqueID: "dev-a")
        #expect(first.endpointID == ep(3))
        #expect(second.endpointID == ep(4))
    }

    @Test("Endpoints added before an injected store's state is loaded keep their IDs and are recorded")
    func registeredBeforeLoadAreAdopted() async throws {
        let fabricStore = InMemoryFabricStore()
        // Only reachable by injecting a CommissioningState that has a store: the
        // store-taking initializer loads before returning.
        let bridge = MatterBridge(commissioningState: CommissioningState(fabricStore: fabricStore))
        let a = bridge.addOnOffLight(name: "A", uniqueID: "dev-a")
        #expect(a.endpointID == ep(3))
        // Nothing may be saved before the stored state is loaded — it would replace the fabrics.
        #expect(await fabricStore.saveCount == 0)

        try await bridge.loadPersistedState()
        try await waitForSaved(fabricStore) { $0.bridgedEndpointIDs["dev-a"] == 3 }
        #expect(bridge.addOnOffLight(name: "B", uniqueID: "dev-b").endpointID == ep(4))
    }

    // MARK: - Backward-Compatible Decoding

    @Test("StoredDeviceState JSON saved before endpoint allocation still decodes")
    func legacyDeviceStateDecodes() throws {
        let legacy = """
        {"acls":[],"fabrics":[],"nextFabricIndex":3,"pbkdfIterations":1000,"pbkdfSalt":"AAECAwQFBgcICQoLDA0ODw=="}
        """
        let decoded = try JSONDecoder().decode(StoredDeviceState.self, from: Data(legacy.utf8))
        #expect(decoded.nextFabricIndex == 3)
        #expect(decoded.pbkdfIterations == 1000)
        #expect(decoded.bridgedEndpointIDs.isEmpty)
        #expect(decoded.highestBridgedEndpointID == 0)
    }

    @Test("StoredDeviceState endpoint allocation fields round-trip through JSON")
    func deviceStateAllocationRoundTrip() throws {
        let state = StoredDeviceState(
            nextFabricIndex: 2,
            bridgedEndpointIDs: ["dev-a": 3, "dev-b": 7],
            highestBridgedEndpointID: 9
        )
        let data = try JSONEncoder().encode(state)
        let decoded = try JSONDecoder().decode(StoredDeviceState.self, from: data)
        #expect(decoded == state)
    }
}
