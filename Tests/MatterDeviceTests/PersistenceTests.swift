// PersistenceTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
import MatterTypes
import MatterProtocol
import MatterCrypto
@testable import MatterDevice

@Suite("Device Persistence")
struct PersistenceTests {

    // MARK: - AttributeStore Persistence

    @Test("AttributeStore save and load roundtrip")
    func attributeStoreRoundtrip() async throws {
        let memStore = InMemoryAttributeStore()

        // Populate an attribute store
        let store1 = AttributeStore(attributeStore: memStore)
        let ep0 = EndpointID(rawValue: 0)
        let ep1 = EndpointID(rawValue: 1)
        let clOnOff = ClusterID(rawValue: 0x0006)
        let clLevel = ClusterID(rawValue: 0x0008)
        let attrOnOff = AttributeID(rawValue: 0)
        let attrLevel = AttributeID(rawValue: 0)

        store1.set(endpoint: ep0, cluster: clOnOff, attribute: attrOnOff, value: .bool(true))
        store1.set(endpoint: ep1, cluster: clLevel, attribute: attrLevel, value: .unsignedInt(200))

        let v1 = store1.dataVersion(endpoint: ep0, cluster: clOnOff)

        // Save
        await store1.saveToStore()
        let saveCount = await memStore.saveCount
        #expect(saveCount == 1)

        // Load into a new store
        let store2 = AttributeStore(attributeStore: memStore)
        try await store2.loadFromStore()

        // Verify values restored
        let restored1 = store2.get(endpoint: ep0, cluster: clOnOff, attribute: attrOnOff)
        #expect(restored1 == .bool(true))

        let restored2 = store2.get(endpoint: ep1, cluster: clLevel, attribute: attrLevel)
        #expect(restored2 == .unsignedInt(200))

        // Verify data version preserved
        let v2 = store2.dataVersion(endpoint: ep0, cluster: clOnOff)
        #expect(v2.rawValue == v1.rawValue)
    }

    @Test("AttributeStore save is no-op without store")
    func attributeStoreNoStore() async {
        let store = AttributeStore()
        store.set(
            endpoint: EndpointID(rawValue: 0),
            cluster: ClusterID(rawValue: 0x0006),
            attribute: AttributeID(rawValue: 0),
            value: .bool(true)
        )
        // Should not crash
        await store.saveToStore()
    }

    @Test("AttributeStore load is no-op without store")
    func attributeStoreLoadNoStore() async throws {
        let store = AttributeStore()
        // Should not crash
        try await store.loadFromStore()
    }

    @Test("AttributeStore load with empty store returns nothing")
    func attributeStoreEmptyStore() async throws {
        let memStore = InMemoryAttributeStore()
        let store = AttributeStore(attributeStore: memStore)
        try await store.loadFromStore()

        #expect(store.allEndpointIDs().isEmpty)
    }

    // MARK: - CommissioningState Persistence

    @Test("CommissioningState save and load roundtrip")
    func commissioningStateRoundtrip() async throws {
        let memStore = InMemoryFabricStore()

        // Create a commissioning state and commit a fabric
        let state1 = CommissioningState(fabricStore: memStore)
        let ipk = Data(repeating: 0, count: 16)

        // Simulate commissioning flow: arm → stage → commit
        state1.armFailSafe(expiresAt: Date().addingTimeInterval(120))
        state1.stagedRCAC = Data(repeating: 0xAA, count: 100)
        state1.stagedNOC = Data(repeating: 0xBB, count: 100)
        state1.stagedICAC = nil
        state1.stagedIPK = ipk
        state1.stagedCaseAdminSubject = 1
        state1.stagedAdminVendorId = 0xFFF1
        // Set the operational key via CSR flow
        let key = state1.generateOperationalKey(csrNonce: Data(repeating: 0, count: 32))
        state1.commitCommissioning()

        #expect(state1.fabrics.count == 1)

        // Save
        await state1.saveToStore()
        let saveCount = await memStore.saveCount
        #expect(saveCount == 1)

        // Load into a fresh state
        let state2 = CommissioningState(fabricStore: memStore)
        try await state2.loadFromStore()

        // Verify fabric restored
        #expect(state2.fabrics.count == 1)
        let fabric = state2.fabrics[FabricIndex(rawValue: 1)]
        #expect(fabric != nil)
        #expect(fabric?.fabricIndex.rawValue == 1)
        #expect(fabric?.nocTLV == Data(repeating: 0xBB, count: 100))
        #expect(fabric?.rcacTLV == Data(repeating: 0xAA, count: 100))
        #expect(fabric?.ipkEpochKey == ipk)
        #expect(fabric?.caseAdminSubject == 1)
        #expect(fabric?.adminVendorId == 0xFFF1)

        // Verify operational key restored (raw bytes match)
        #expect(fabric?.operationalKey.rawRepresentation == key.rawRepresentation)
    }

    @Test("CommissioningState preserves nextFabricIndex across restarts")
    func nextFabricIndexPreserved() async throws {
        let memStore = InMemoryFabricStore()
        let state1 = CommissioningState(fabricStore: memStore)

        // Commit two fabrics
        for i in 0..<2 {
            state1.armFailSafe(expiresAt: Date().addingTimeInterval(120))
            state1.stagedRCAC = Data(repeating: UInt8(i), count: 50)
            state1.stagedNOC = Data(repeating: UInt8(i + 10), count: 50)
            state1.stagedIPK = Data(repeating: 0, count: 16)
            state1.stagedCaseAdminSubject = UInt64(i + 1)
            state1.stagedAdminVendorId = 0xFFF1
            _ = state1.generateOperationalKey(csrNonce: Data(repeating: 0, count: 32))
            state1.commitCommissioning()
        }

        #expect(state1.fabrics.count == 2)
        await state1.saveToStore()

        // Restore and commit another fabric — should get index 3, not 1
        let state2 = CommissioningState(fabricStore: memStore)
        try await state2.loadFromStore()
        #expect(state2.fabrics.count == 2)

        state2.armFailSafe(expiresAt: Date().addingTimeInterval(120))
        state2.stagedRCAC = Data(repeating: 0xFF, count: 50)
        state2.stagedNOC = Data(repeating: 0xFE, count: 50)
        state2.stagedIPK = Data(repeating: 0, count: 16)
        state2.stagedCaseAdminSubject = 3
        state2.stagedAdminVendorId = 0xFFF1
        _ = state2.generateOperationalKey(csrNonce: Data(repeating: 0, count: 32))
        state2.commitCommissioning()

        #expect(state2.fabrics.count == 3)
        // The third fabric should have index 3, not 1
        #expect(state2.fabrics[FabricIndex(rawValue: 3)] != nil)
    }

    // MARK: - StoredTypes Codable Roundtrip

    @Test("StoredControllerState JSON roundtrip")
    func storedControllerStateRoundtrip() throws {
        let identity = StoredControllerIdentity(
            rootKeyRaw: Data(repeating: 0x11, count: 32),
            fabricIndex: 1,
            fabricID: 100,
            controllerNodeID: 1,
            rcacTLV: Data(repeating: 0x22, count: 64),
            nocTLV: Data(repeating: 0x33, count: 64),
            operationalKeyRaw: Data(repeating: 0x44, count: 32),
            vendorID: 0xFFF1,
            ipkEpochKey: Data(repeating: 0, count: 16)
        )

        let device = StoredCommissionedDevice(
            nodeID: 42,
            fabricIndex: 1,
            vendorID: 0xFFF1,
            productID: nil,
            operationalHost: "192.168.1.100",
            operationalPort: 5540,
            label: "Test Light",
            commissionedAt: Date(timeIntervalSince1970: 1000000)
        )

        let state = StoredControllerState(
            identity: identity,
            devices: [device],
            nextNodeID: 43
        )

        let encoder = JSONEncoder()
        let data = try encoder.encode(state)
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(StoredControllerState.self, from: data)

        #expect(decoded == state)
        #expect(decoded.identity.rootKeyRaw == Data(repeating: 0x11, count: 32))
        #expect(decoded.devices.count == 1)
        #expect(decoded.devices[0].nodeID == 42)
        #expect(decoded.devices[0].operationalHost == "192.168.1.100")
        #expect(decoded.nextNodeID == 43)
    }

    @Test("StoredDeviceState JSON roundtrip")
    func storedDeviceStateRoundtrip() throws {
        let fabric = StoredFabric(
            fabricIndex: 1,
            nocTLV: Data(repeating: 0xBB, count: 80),
            icacTLV: nil,
            rcacTLV: Data(repeating: 0xAA, count: 80),
            operationalKeyRaw: Data(repeating: 0xCC, count: 32),
            ipkEpochKey: Data(repeating: 0, count: 16),
            caseAdminSubject: 1,
            adminVendorId: 0xFFF1
        )

        let acl = StoredACLEntry(
            privilege: 5, // administer
            authMode: 2,  // CASE
            subjects: [1],
            targets: nil,
            fabricIndex: 1
        )

        let state = StoredDeviceState(
            fabrics: [fabric],
            acls: [StoredFabricACLs(fabricIndex: 1, entries: [acl])],
            nextFabricIndex: 2
        )

        let encoder = JSONEncoder()
        let data = try encoder.encode(state)
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(StoredDeviceState.self, from: data)

        #expect(decoded == state)
        #expect(decoded.fabrics.count == 1)
        #expect(decoded.acls.count == 1)
        #expect(decoded.nextFabricIndex == 2)
    }

    @Test("StoredAttributeData JSON roundtrip")
    func storedAttributeDataRoundtrip() throws {
        let key = StoredClusterKey(endpointID: 0, clusterID: 0x0006)
        let value = TLVElement.bool(true)
        let encoded = TLVEncoder.encode(value)

        let clusterData = StoredClusterData(
            dataVersion: 42,
            attributes: [0: encoded]
        )

        let attrData = StoredAttributeData(clusters: [key: clusterData])

        let encoder = JSONEncoder()
        let data = try encoder.encode(attrData)
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(StoredAttributeData.self, from: data)

        #expect(decoded == attrData)
        #expect(decoded.clusters[key]?.dataVersion == 42)
        #expect(decoded.clusters[key]?.attributes[0] == encoded)
    }

    // MARK: - InMemoryStore

    @Test("InMemoryFabricStore tracks save count")
    func inMemoryFabricStoreSaveCount() async throws {
        let store = InMemoryFabricStore()
        let state = StoredDeviceState(fabrics: [], acls: [], nextFabricIndex: 1)

        try await store.save(state)
        try await store.save(state)
        try await store.save(state)

        let count = await store.saveCount
        #expect(count == 3)
    }

    @Test("InMemoryControllerStore save and load")
    func inMemoryControllerStore() async throws {
        let store = InMemoryControllerStore()

        let loaded1 = try await store.load()
        #expect(loaded1 == nil)

        let identity = StoredControllerIdentity(
            rootKeyRaw: Data(repeating: 0, count: 32),
            fabricIndex: 1,
            fabricID: 1,
            controllerNodeID: 1,
            rcacTLV: Data(repeating: 0, count: 32),
            nocTLV: Data(repeating: 0, count: 32),
            operationalKeyRaw: Data(repeating: 0, count: 32),
            vendorID: 0xFFF1,
            ipkEpochKey: Data(repeating: 0, count: 16)
        )

        let state = StoredControllerState(
            identity: identity,
            devices: [],
            nextNodeID: 2
        )

        try await store.save(state)
        let loaded2 = try await store.load()
        #expect(loaded2 == state)
    }
}
