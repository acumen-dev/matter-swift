// BridgeEndpointIdentityTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
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

    /// A fabric that `CommissioningState.loadFromStore()` can parse (real P-256 key).
    private func storedFabric(index: UInt8 = 1) -> StoredFabric {
        StoredFabric(
            fabricIndex: index,
            nocTLV: Data(repeating: 0xBB, count: 64),
            icacTLV: nil,
            rcacTLV: Data(repeating: 0xAA, count: 64),
            operationalKeyRaw: P256.Signing.PrivateKey().rawRepresentation,
            ipkEpochKey: Data(repeating: 0x11, count: 16),
            caseAdminSubject: 0x1234,
            adminVendorId: 0xFFF1
        )
    }

    private func storedACL(index: UInt8 = 1) -> StoredFabricACLs {
        StoredFabricACLs(fabricIndex: index, entries: [
            StoredACLEntry(privilege: 5, authMode: 2, subjects: [0x1234], targets: nil, fabricIndex: index)
        ])
    }

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

    @Test("A removed device's number is freed but not reused before a wrap, in-run or across a restart")
    func removedIDIsNotReusedBeforeWrap() async throws {
        let fabricStore = InMemoryFabricStore()

        let first = try await MatterBridge(fabricStore: fabricStore)
        let a = first.addOnOffLight(name: "A", uniqueID: "dev-a")
        #expect(a.endpointID == ep(3))
        first.removeEndpoint(a)
        let b = first.addOnOffLight(name: "B", uniqueID: "dev-b")
        #expect(b.endpointID == ep(4))
        try await waitForSaved(fabricStore) {
            $0.bridgedEndpointIDs == ["dev-b": 4] && $0.highestBridgedEndpointID == 4
        }

        // Restart with a brand-new device: it must not land on 3 (A's) or 4 (B's).
        let second = try await MatterBridge(fabricStore: fabricStore)
        let c = second.addOnOffLight(name: "C", uniqueID: "dev-c")
        #expect(c.endpointID == ep(5))

        // A was removed, so it is a new device now.
        let aAgain = second.addOnOffLight(name: "A", uniqueID: "dev-a")
        #expect(aAgain.endpointID == ep(6))
    }

    @Test("A device that is only not re-added after a restart keeps its number")
    func unservedDeviceKeepsNumber() async throws {
        let fabricStore = InMemoryFabricStore(state: StoredDeviceState(
            bridgedEndpointIDs: ["dev-a": 3, "dev-b": 4],
            highestBridgedEndpointID: 4
        ))
        let bridge = try await MatterBridge(fabricStore: fabricStore)
        #expect(bridge.addOnOffLight(name: "New", uniqueID: "dev-new").endpointID == ep(5))
        #expect(bridge.addOnOffLight(name: "A", uniqueID: "dev-a").endpointID == ep(3))
        try await waitForSaved(fabricStore) { $0.bridgedEndpointIDs["dev-new"] == 5 }
        #expect(try await fabricStore.load()?.bridgedEndpointIDs["dev-b"] == 4)
    }

    // MARK: - Wrapping at 0xFFFE (Matter Core § 9.2.10)

    @Test("After 0xFFFE, new numbers continue with the lowest free number and 0xFFFF is never issued")
    func wrapsToLowestFree() async throws {
        let fabricStore = InMemoryFabricStore(state: StoredDeviceState(
            bridgedEndpointIDs: ["dev-a": 3, "dev-b": 5, "dev-top": 0xFFFD],
            highestBridgedEndpointID: 0xFFFD
        ))
        let bridge = try await MatterBridge(fabricStore: fabricStore)
        #expect(bridge.addOnOffLight(name: "Last", uniqueID: "dev-last").endpointID == ep(0xFFFE))
        #expect(bridge.addOnOffLight(name: "Wrapped", uniqueID: "dev-wrap-1").endpointID == ep(4))
        #expect(bridge.addOnOffLight(name: "Wrapped", uniqueID: "dev-wrap-2").endpointID == ep(6))
        try await waitForSaved(fabricStore) {
            $0.bridgedEndpointIDs["dev-wrap-2"] == 6 && $0.highestBridgedEndpointID == 0xFFFE
        }
    }

    @Test("A removed device's number is reused only after a wrap")
    func removedNumberReusedAfterWrap() async throws {
        let fabricStore = InMemoryFabricStore(state: StoredDeviceState(
            bridgedEndpointIDs: ["dev-a": 3, "dev-b": 4, "dev-top": 0xFFFE],
            highestBridgedEndpointID: 0xFFFE
        ))
        let bridge = try await MatterBridge(fabricStore: fabricStore)
        let a = bridge.addOnOffLight(name: "A", uniqueID: "dev-a")
        #expect(a.endpointID == ep(3))
        // Before removal, 3 is held by A even though A is not the newest device.
        #expect(bridge.addOnOffLight(name: "C", uniqueID: "dev-c").endpointID == ep(5))

        bridge.removeEndpoint(a)
        #expect(bridge.addOnOffLight(name: "D", uniqueID: "dev-d").endpointID == ep(3))
    }

    @Test("Stored numbers outside 3...0xFFFE are ignored and a corrupt mark restarts from the valid numbers")
    func outOfRangeStoredNumbersIgnored() async throws {
        let fabricStore = InMemoryFabricStore(state: StoredDeviceState(
            bridgedEndpointIDs: ["dev-a": 7, "dev-ffff": 0xFFFF, "dev-zero": 0, "dev-agg": 1],
            highestBridgedEndpointID: 0xFFFF
        ))
        let bridge = try await MatterBridge(fabricStore: fabricStore)
        // The corrupt mark (0xFFFF) is replaced by the highest valid stored number, 7.
        #expect(bridge.addOnOffLight(name: "New", uniqueID: "dev-new").endpointID == ep(8))
        // A device whose stored number was invalid is a new device.
        #expect(bridge.addOnOffLight(name: "FFFF", uniqueID: "dev-ffff").endpointID == ep(9))
        #expect(bridge.addOnOffLight(name: "A", uniqueID: "dev-a").endpointID == ep(7))
        try await waitForSaved(fabricStore) {
            $0.bridgedEndpointIDs == ["dev-a": 7, "dev-new": 8, "dev-ffff": 9] && $0.highestBridgedEndpointID == 9
        }
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
        let c = bridge.addOnOffLight(name: "C", uniqueID: "dev-c")
        #expect(aAgain.endpointID == ep(5))
        #expect(c.endpointID == ep(6))

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
        let fabric = storedFabric()
        let acl = storedACL()
        let fabricStore = InMemoryFabricStore(state: StoredDeviceState(
            fabrics: [fabric],
            acls: [acl],
            nextFabricIndex: 5,
            pbkdfSalt: salt,
            pbkdfIterations: 2000
        ))
        let bridge = try await MatterBridge(fabricStore: fabricStore)
        bridge.addOnOffLight(name: "A", uniqueID: "dev-a")

        try await waitForSaved(fabricStore) { $0.bridgedEndpointIDs["dev-a"] == 3 }
        let saved = try #require(try await fabricStore.load())
        #expect(saved.fabrics == [fabric])
        #expect(saved.acls == [acl])
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

    @Test("A restart where every device is already known writes nothing to the fabric store")
    func knownDevicesDoNotSave() async throws {
        let fabricStore = InMemoryFabricStore(state: StoredDeviceState(
            fabrics: [storedFabric()],
            acls: [storedACL()],
            nextFabricIndex: 2,
            bridgedEndpointIDs: ["dev-a": 3, "dev-b": 4],
            highestBridgedEndpointID: 4
        ))
        let bridge = try await MatterBridge(fabricStore: fabricStore)
        #expect(bridge.addOnOffLight(name: "B", uniqueID: "dev-b").endpointID == ep(4))
        #expect(bridge.addOnOffLight(name: "A", uniqueID: "dev-a").endpointID == ep(3))
        await bridge.commissioningState.flush()
        #expect(await fabricStore.saveCount == 0)
    }

    @Test("A high-water mark behind the stored map never re-issues a stored ID")
    func laggingHighWaterMark() async throws {
        let fabricStore = InMemoryFabricStore(state: StoredDeviceState(
            bridgedEndpointIDs: ["dev-a": 7],
            highestBridgedEndpointID: 0
        ))
        let bridge = try await MatterBridge(fabricStore: fabricStore)
        #expect(bridge.addOnOffLight(name: "New", uniqueID: "dev-new").endpointID == ep(8))
    }

    @Test("Endpoints added before an injected store's state is loaded keep their IDs and are recorded")
    func registeredBeforeLoadAreAdopted() async throws {
        // Only reachable inside the module: `CommissioningState(fabricStore:)` is internal,
        // and the public store-taking initializer loads before returning.
        let fabricStore = InMemoryFabricStore(state: StoredDeviceState(
            fabrics: [storedFabric()],
            nextFabricIndex: 2,
            bridgedEndpointIDs: ["dev-x": 3, "dev-a": 6],
            highestBridgedEndpointID: 9
        ))
        let bridge = MatterBridge(commissioningState: CommissioningState(fabricStore: fabricStore))
        let a = bridge.addOnOffLight(name: "A", uniqueID: "dev-a")
        #expect(a.endpointID == ep(3))
        // Nothing may be saved before the stored state is loaded — it would replace the fabrics.
        #expect(await fabricStore.saveCount == 0)

        try await bridge.loadPersistedState()
        let saved = try #require(try await fabricStore.load())
        // A keeps the ID the host holds; the device that held 3 loses it, and the mark stands.
        #expect(saved.bridgedEndpointIDs == ["dev-a": 3])
        #expect(saved.highestBridgedEndpointID == 9)
        #expect(saved.fabrics.count == 1)
        #expect(bridge.addOnOffLight(name: "B", uniqueID: "dev-b").endpointID == ep(10))
    }

    // MARK: - Concurrency

    @Test("Concurrent add* during fabric commits and ACL updates never loses the fabric from the store")
    func concurrentAllocationKeepsFabric() async throws {
        let fabricStore = InMemoryFabricStore()
        let bridge = try await MatterBridge(fabricStore: fabricStore)
        let state = bridge.commissioningState
        let deviceCount = 200

        // The host adds devices on its own task while the owning context commissions.
        let host = Task.detached {
            for i in 0..<deviceCount {
                bridge.addOnOffLight(name: "Device \(i)", uniqueID: "dev-\(i)")
            }
        }

        state.armFailSafe(expiresAt: Date().addingTimeInterval(120))
        state.stagedRCAC = Data(repeating: 0xAA, count: 64)
        state.stagedNOC = Data(repeating: 0xBB, count: 64)
        state.stagedIPK = Data(repeating: 0x11, count: 16)
        state.stagedCaseAdminSubject = 0x1234
        _ = state.generateOperationalKey(csrNonce: Data(repeating: 0, count: 32))
        state.commitCommissioning()
        let fabricIndex = FabricIndex(rawValue: 1)
        for round in 0..<200 {
            state.updateCommittedACLs(fabricIndex: fabricIndex, entries: [
                AccessControlCluster.AccessControlEntry(
                    privilege: .administer,
                    authMode: .case,
                    subjects: [UInt64(round)],
                    targets: nil,
                    fabricIndex: fabricIndex
                )
            ])
            await Task.yield()
        }

        await host.value
        await state.flush()

        let saved = try #require(try await fabricStore.load())
        #expect(saved.fabrics.map(\.fabricIndex) == [1])
        #expect(saved.acls.first?.entries.first?.subjects == [199])
        #expect(saved.bridgedEndpointIDs.count == deviceCount)
        #expect(saved.highestBridgedEndpointID == UInt16(2 + deviceCount))
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
