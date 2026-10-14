// ControllerMRPParametersTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterProtocol
@testable import MatterController

@Suite("Controller MRP parameters")
struct ControllerMRPParametersTests {

    let sleepy = MRPParameters(
        sessionIdleInterval: .milliseconds(5000),
        sessionActiveInterval: .milliseconds(300),
        sessionActiveThreshold: .milliseconds(4000)
    )

    @Test("Configuration defaults to the spec MRP config (4 retransmissions)")
    func configurationDefault() {
        let configuration = MatterController.Configuration(fabricID: FabricID(rawValue: 1))
        #expect(configuration.mrp.maxRetransmissions == 4)
        #expect(configuration.mrp.peer == .default)
    }

    @Test("A device's MRP parameters survive the stored-device round trip")
    func persisted() async throws {
        let registry = DeviceRegistry()
        await registry.register(CommissionedDevice(nodeID: NodeID(rawValue: 5), fabricIndex: FabricIndex(rawValue: 1), mrpParameters: sleepy))
        let stored = await registry.toStoredDevices()
        #expect(stored.first?.mrpIdleIntervalMs == 5000)
        #expect(stored.first?.mrpActiveIntervalMs == 300)
        #expect(stored.first?.mrpActiveThresholdMs == 4000)

        let restored = try DeviceRegistry(storedDevices: stored)
        #expect(await restored.device(for: NodeID(rawValue: 5))?.mrpParameters == sleepy)
    }

    @Test("updateMRPParameters sets and clears")
    func update() async {
        let registry = DeviceRegistry()
        await registry.register(CommissionedDevice(nodeID: NodeID(rawValue: 5), fabricIndex: FabricIndex(rawValue: 1)))
        await registry.updateMRPParameters(for: NodeID(rawValue: 5), parameters: sleepy)
        #expect(await registry.device(for: NodeID(rawValue: 5))?.mrpParameters == sleepy)
        await registry.updateMRPParameters(for: NodeID(rawValue: 5), parameters: nil)
        #expect(await registry.device(for: NodeID(rawValue: 5))?.mrpParameters == nil)
    }

    @Test("Records persisted before MRP fields existed still decode, with no parameters")
    func legacyRecord() async throws {
        let json = #"{"nodeID":7,"fabricIndex":1,"commissionedAt":0}"#
        let decoded = try JSONDecoder().decode(StoredCommissionedDevice.self, from: Data(json.utf8))
        #expect(decoded.mrpIdleIntervalMs == nil)
        let restored = try DeviceRegistry(storedDevices: [decoded])
        #expect(await restored.device(for: NodeID(rawValue: 7))?.mrpParameters == nil)
    }

    @Test("peerUnreachable names the node")
    func peerUnreachableError() {
        #expect(ControllerError.peerUnreachable(NodeID(rawValue: 9)) != ControllerError.peerUnreachable(NodeID(rawValue: 8)))
    }
}
