// DeviceRegistryTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
@testable import MatterController
import MatterTypes
import MatterTransport

@Suite("DeviceRegistry")
struct DeviceRegistryTests {

    private func makeDevice(
        nodeID: UInt64 = 1,
        fabricIndex: UInt8 = 1,
        label: String? = nil
    ) -> CommissionedDevice {
        CommissionedDevice(
            nodeID: NodeID(rawValue: nodeID),
            fabricIndex: FabricIndex(rawValue: fabricIndex),
            label: label
        )
    }

    @Test("Register and lookup")
    func registerAndLookup() async {
        let registry = DeviceRegistry()
        let device = makeDevice(nodeID: 42)

        await registry.register(device)
        let found = await registry.device(for: NodeID(rawValue: 42))

        #expect(found != nil)
        #expect(found?.nodeID.rawValue == 42)
    }

    @Test("Lookup returns nil for unknown device")
    func lookupMissing() async {
        let registry = DeviceRegistry()
        let found = await registry.device(for: NodeID(rawValue: 999))
        #expect(found == nil)
    }

    @Test("Update address")
    func updateAddress() async {
        let registry = DeviceRegistry()
        let device = makeDevice(nodeID: 10)
        await registry.register(device)

        let address = MatterAddress(host: "192.168.1.100", port: 5540)
        await registry.updateAddress(for: NodeID(rawValue: 10), address: address)

        let found = await registry.device(for: NodeID(rawValue: 10))
        #expect(found?.operationalAddress?.host == "192.168.1.100")
        #expect(found?.operationalAddress?.port == 5540)
    }

    @Test("Update label")
    func updateLabel() async {
        let registry = DeviceRegistry()
        let device = makeDevice(nodeID: 10)
        await registry.register(device)

        await registry.updateLabel(for: NodeID(rawValue: 10), label: "Kitchen Light")

        let found = await registry.device(for: NodeID(rawValue: 10))
        #expect(found?.label == "Kitchen Light")
    }

    @Test("Remove device")
    func removeDevice() async {
        let registry = DeviceRegistry()
        let device = makeDevice(nodeID: 10)
        await registry.register(device)

        let removed = await registry.remove(nodeID: NodeID(rawValue: 10))
        #expect(removed != nil)

        let found = await registry.device(for: NodeID(rawValue: 10))
        #expect(found == nil)
    }

    @Test("Remove non-existent returns nil")
    func removeNonExistent() async {
        let registry = DeviceRegistry()
        let removed = await registry.remove(nodeID: NodeID(rawValue: 999))
        #expect(removed == nil)
    }

    @Test("Snapshot returns sorted by node ID")
    func snapshot() async {
        let registry = DeviceRegistry()
        await registry.register(makeDevice(nodeID: 30))
        await registry.register(makeDevice(nodeID: 10))
        await registry.register(makeDevice(nodeID: 20))

        let snap = await registry.snapshot()
        #expect(snap.count == 3)
        #expect(snap[0].nodeID.rawValue == 10)
        #expect(snap[1].nodeID.rawValue == 20)
        #expect(snap[2].nodeID.rawValue == 30)
    }

    @Test("Duplicate registration replaces existing")
    func duplicateRegistration() async {
        let registry = DeviceRegistry()
        let device1 = makeDevice(nodeID: 10, label: "First")
        let device2 = makeDevice(nodeID: 10, label: "Second")

        await registry.register(device1)
        await registry.register(device2)

        let count = await registry.count
        #expect(count == 1)

        let found = await registry.device(for: NodeID(rawValue: 10))
        #expect(found?.label == "Second")
    }

    @Test("CommissionedDevice address convenience")
    func addressConvenience() {
        var device = CommissionedDevice(
            nodeID: NodeID(rawValue: 1),
            fabricIndex: FabricIndex(rawValue: 1)
        )

        #expect(device.operationalAddress == nil)

        device.setOperationalAddress(MatterAddress(host: "10.0.0.1", port: 5540))
        #expect(device.operationalHost == "10.0.0.1")
        #expect(device.operationalPort == 5540)
        #expect(device.operationalAddress?.host == "10.0.0.1")
    }

    @Test("CommissionedDevice is Codable")
    func codable() throws {
        let device = CommissionedDevice(
            nodeID: NodeID(rawValue: 42),
            fabricIndex: FabricIndex(rawValue: 1),
            vendorID: .test,
            operationalHost: "192.168.1.1",
            operationalPort: 5540,
            label: "Test Device"
        )

        let encoder = JSONEncoder()
        let data = try encoder.encode(device)
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(CommissionedDevice.self, from: data)

        #expect(decoded.nodeID == device.nodeID)
        #expect(decoded.fabricIndex == device.fabricIndex)
        #expect(decoded.vendorID == device.vendorID)
        #expect(decoded.operationalHost == "192.168.1.1")
        #expect(decoded.operationalPort == 5540)
        #expect(decoded.label == "Test Device")
    }
}
