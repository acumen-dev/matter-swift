// ControllerPersistenceTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
import MatterTypes
import MatterCrypto
@testable import MatterController

@Suite("Controller Persistence")
struct ControllerPersistenceTests {

    // MARK: - FabricManager Stored-State Roundtrip

    @Test("FabricManager export and restore roundtrip")
    func fabricManagerRoundtrip() async throws {
        // Create a fresh fabric manager
        let rootKey = P256.Signing.PrivateKey()
        let fm1 = try FabricManager(
            rootKey: rootKey,
            fabricID: FabricID(rawValue: 100),
            controllerNodeID: NodeID(rawValue: 1),
            vendorID: .test
        )

        // Allocate a couple of node IDs
        let _ = await fm1.allocateNodeID()  // 2
        let _ = await fm1.allocateNodeID()  // 3

        // Export
        let stored = fm1.toStoredIdentity()
        let nextNodeID = await fm1.nextNodeID

        #expect(nextNodeID == 4)
        #expect(stored.fabricIndex == 1)
        #expect(stored.fabricID == 100)
        #expect(stored.controllerNodeID == 1)
        #expect(stored.vendorID == VendorID.test.rawValue)
        #expect(stored.rootKeyRaw == rootKey.rawRepresentation)

        // Restore from stored state
        let fm2 = try FabricManager(stored: stored, nextNodeID: nextNodeID)

        // Verify identity preserved
        #expect(fm2.controllerFabricInfo.fabricID == FabricID(rawValue: 100))
        #expect(fm2.controllerFabricInfo.nodeID == NodeID(rawValue: 1))
        #expect(fm2.fabricIndex == FabricIndex(rawValue: 1))
        #expect(fm2.vendorID == .test)

        // Verify next node ID continues from where we left off
        let nextNode = await fm2.allocateNodeID()
        #expect(nextNode.rawValue == 4)

        // Verify IPK derivation produces the same result
        #expect(fm1.deriveIPK() == fm2.deriveIPK())

        // Verify compressed fabric ID matches
        #expect(fm1.compressedFabricID() == fm2.compressedFabricID())
    }

    @Test("FabricManager NOC generation works after restore")
    func nocGenerationAfterRestore() async throws {
        let rootKey = P256.Signing.PrivateKey()
        let fm1 = try FabricManager(
            rootKey: rootKey,
            fabricID: FabricID(rawValue: 1),
            controllerNodeID: NodeID(rawValue: 1),
            vendorID: .test
        )

        let stored = fm1.toStoredIdentity()
        let nextNodeID = await fm1.nextNodeID
        let fm2 = try FabricManager(stored: stored, nextNodeID: nextNodeID)

        // Generate a NOC from the restored fabric manager
        let deviceKey = P256.Signing.PrivateKey()
        let nodeID = await fm2.allocateNodeID()
        let noc = try await fm2.generateNOC(
            nodePublicKey: deviceKey.publicKey,
            nodeID: nodeID
        )

        // Verify the NOC has meaningful subject/issuer fields
        #expect(noc.subject.nodeID != nil)
        #expect(noc.issuer.nodeID != nil || noc.issuer.fabricID != nil)
    }

    // MARK: - DeviceRegistry Stored-State Roundtrip

    @Test("DeviceRegistry export and restore roundtrip")
    func deviceRegistryRoundtrip() async {
        let registry1 = DeviceRegistry()
        let device1 = CommissionedDevice(
            nodeID: NodeID(rawValue: 10),
            fabricIndex: FabricIndex(rawValue: 1),
            vendorID: VendorID(rawValue: 0xFFF1),
            productID: ProductID(rawValue: 42),
            operationalHost: "192.168.1.100",
            operationalPort: 5540,
            label: "Kitchen Light"
        )
        let device2 = CommissionedDevice(
            nodeID: NodeID(rawValue: 20),
            fabricIndex: FabricIndex(rawValue: 1),
            label: "Study Lamp"
        )

        await registry1.register(device1)
        await registry1.register(device2)

        // Export
        let stored = await registry1.toStoredDevices()
        #expect(stored.count == 2)

        // Restore
        let registry2 = DeviceRegistry(storedDevices: stored)

        let d1 = await registry2.device(for: NodeID(rawValue: 10))
        #expect(d1 != nil)
        #expect(d1?.vendorID?.rawValue == 0xFFF1)
        #expect(d1?.productID?.rawValue == 42)
        #expect(d1?.operationalHost == "192.168.1.100")
        #expect(d1?.operationalPort == 5540)
        #expect(d1?.label == "Kitchen Light")

        let d2 = await registry2.device(for: NodeID(rawValue: 20))
        #expect(d2 != nil)
        #expect(d2?.label == "Study Lamp")

        let count = await registry2.count
        #expect(count == 2)
    }

    // MARK: - StoredControllerState Full Roundtrip

    @Test("Full controller state save and load via InMemoryControllerStore")
    func fullControllerStateRoundtrip() async throws {
        let store = InMemoryControllerStore()

        // Create controller components and export state
        let rootKey = P256.Signing.PrivateKey()
        let fm = try FabricManager(
            rootKey: rootKey,
            fabricID: FabricID(rawValue: 1),
            controllerNodeID: NodeID(rawValue: 1),
            vendorID: .test
        )

        let nodeID = await fm.allocateNodeID()  // 2

        let registry = DeviceRegistry()
        let device = CommissionedDevice(
            nodeID: nodeID,
            fabricIndex: fm.fabricIndex,
            operationalHost: "10.0.0.1",
            operationalPort: 5540
        )
        await registry.register(device)

        // Build and save state
        let state = StoredControllerState(
            identity: fm.toStoredIdentity(),
            devices: await registry.toStoredDevices(),
            nextNodeID: await fm.nextNodeID
        )
        try await store.save(state)

        // Load and verify
        let loaded = try await store.load()
        #expect(loaded != nil)
        #expect(loaded?.identity.rootKeyRaw == rootKey.rawRepresentation)
        #expect(loaded?.devices.count == 1)
        #expect(loaded?.devices.first?.nodeID == nodeID.rawValue)
        #expect(loaded?.nextNodeID == 3)

        // Reconstruct fabric manager from loaded state
        let fm2 = try FabricManager(
            stored: loaded!.identity,
            nextNodeID: loaded!.nextNodeID
        )
        let nextNode = await fm2.allocateNodeID()
        #expect(nextNode.rawValue == 3)

        // Reconstruct registry from loaded state
        let registry2 = DeviceRegistry(storedDevices: loaded!.devices)
        let d = await registry2.device(for: nodeID)
        #expect(d?.operationalHost == "10.0.0.1")
    }

    // MARK: - StoredControllerIdentity JSON Roundtrip

    @Test("StoredControllerIdentity JSON encode/decode preserves all fields")
    func storedIdentityJSON() throws {
        let identity = StoredControllerIdentity(
            rootKeyRaw: Data(repeating: 0xAB, count: 32),
            fabricIndex: 3,
            fabricID: 42,
            controllerNodeID: 7,
            rcacTLV: Data(repeating: 0xCC, count: 100),
            nocTLV: Data(repeating: 0xDD, count: 100),
            operationalKeyRaw: Data(repeating: 0xEE, count: 32),
            vendorID: 0xFFF4,
            ipkEpochKey: Data(repeating: 0x01, count: 16)
        )

        let encoder = JSONEncoder()
        let data = try encoder.encode(identity)
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(StoredControllerIdentity.self, from: data)

        #expect(decoded == identity)
        #expect(decoded.fabricIndex == 3)
        #expect(decoded.fabricID == 42)
        #expect(decoded.controllerNodeID == 7)
        #expect(decoded.vendorID == 0xFFF4)
    }
}
