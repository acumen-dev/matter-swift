// MatterControllerTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
@testable import MatterController
@testable import MatterProtocol
import MatterTransport
import MatterTypes

@Suite("MatterController")
struct MatterControllerTests {

    // MARK: - Construction

    @Test("Construction with mocks succeeds")
    func construction() async throws {
        let transport = MockUDPTransport()
        let discovery = MockDiscovery()

        let controller = try MatterController(
            transport: transport,
            discovery: discovery,
            configuration: .init(fabricID: FabricID(rawValue: 1))
        )

        // Should be able to query empty registry
        let devices = await controller.allDevices()
        #expect(devices.isEmpty)
    }

    // MARK: - Discovery

    @Test("Discovery browse returns mocked records")
    func discoveryBrowse() async throws {
        let transport = MockUDPTransport()
        let discovery = MockDiscovery()

        let record = MatterServiceRecord(
            name: "test-device",
            serviceType: .commissionable,
            host: "192.168.1.100",
            port: 5540
        )
        await discovery.addBrowseRecord(record)

        let controller = try MatterController(
            transport: transport,
            discovery: discovery,
            configuration: .init(fabricID: FabricID(rawValue: 1))
        )

        var found: [MatterServiceRecord] = []
        let stream = await controller.discoverCommissionable()
        for await rec in stream {
            found.append(rec)
        }

        #expect(found.count == 1)
        #expect(found.first?.name == "test-device")
    }

    @Test("Discovery resolve returns mocked address")
    func discoveryResolve() async throws {
        let transport = MockUDPTransport()
        let discovery = MockDiscovery()

        let address = MatterAddress(host: "192.168.1.100", port: 5540)
        await discovery.setResolveResult(name: "test-device", address: address)

        let controller = try MatterController(
            transport: transport,
            discovery: discovery,
            configuration: .init(fabricID: FabricID(rawValue: 1))
        )

        let record = MatterServiceRecord(
            name: "test-device",
            serviceType: .commissionable,
            host: "",
            port: 0
        )
        let resolved = try await controller.resolve(record)
        #expect(resolved.host == "192.168.1.100")
        #expect(resolved.port == 5540)
    }

    // MARK: - Device Registry

    @Test("Device registry — register, lookup, remove")
    func deviceRegistry() async throws {
        let transport = MockUDPTransport()
        let discovery = MockDiscovery()

        let controller = try MatterController(
            transport: transport,
            discovery: discovery,
            configuration: .init(fabricID: FabricID(rawValue: 1))
        )

        // Initially empty
        #expect(await controller.allDevices().isEmpty)
        #expect(await controller.device(for: NodeID(rawValue: 42)) == nil)

        // Remove non-existent device is a no-op
        await controller.removeDevice(nodeID: NodeID(rawValue: 42))
        #expect(await controller.allDevices().isEmpty)
    }

    // MARK: - Error: Device Not Found

    @Test("readAttribute throws deviceNotFound for unknown node")
    func readAttributeDeviceNotFound() async throws {
        let transport = MockUDPTransport()
        let discovery = MockDiscovery()

        let controller = try MatterController(
            transport: transport,
            discovery: discovery,
            configuration: .init(fabricID: FabricID(rawValue: 1))
        )

        await #expect(throws: ControllerError.deviceNotFound) {
            _ = try await controller.readAttribute(
                nodeID: NodeID(rawValue: 999),
                endpointID: .root,
                clusterID: ClusterID(rawValue: 0x0006),
                attributeID: AttributeID(rawValue: 0)
            )
        }
    }

    @Test("writeAttribute throws deviceNotFound for unknown node")
    func writeAttributeDeviceNotFound() async throws {
        let transport = MockUDPTransport()
        let discovery = MockDiscovery()

        let controller = try MatterController(
            transport: transport,
            discovery: discovery,
            configuration: .init(fabricID: FabricID(rawValue: 1))
        )

        await #expect(throws: ControllerError.deviceNotFound) {
            _ = try await controller.writeAttribute(
                nodeID: NodeID(rawValue: 999),
                endpointID: .root,
                clusterID: ClusterID(rawValue: 0x0006),
                attributeID: AttributeID(rawValue: 0),
                value: .bool(true)
            )
        }
    }

    @Test("invokeCommand throws deviceNotFound for unknown node")
    func invokeCommandDeviceNotFound() async throws {
        let transport = MockUDPTransport()
        let discovery = MockDiscovery()

        let controller = try MatterController(
            transport: transport,
            discovery: discovery,
            configuration: .init(fabricID: FabricID(rawValue: 1))
        )

        await #expect(throws: ControllerError.deviceNotFound) {
            _ = try await controller.invokeCommand(
                nodeID: NodeID(rawValue: 999),
                endpointID: .root,
                clusterID: ClusterID(rawValue: 0x0006),
                commandID: CommandID(rawValue: 0)
            )
        }
    }
}

// MARK: - Session Cache Tests

@Suite("SessionCache")
struct SessionCacheTests {

    @Test("Store and retrieve session")
    func storeAndRetrieve() {
        var cache = SessionCache()
        let nodeID = NodeID(rawValue: 42)

        let session = SecureSession(
            localSessionID: 100,
            peerSessionID: 200,
            establishment: .case,
            peerNodeID: nodeID,
            timeout: .seconds(3600)
        )

        cache.store(session, for: nodeID)
        let retrieved = cache.session(for: nodeID)
        #expect(retrieved != nil)
        #expect(retrieved?.localSessionID == 100)
        #expect(retrieved?.peerSessionID == 200)
    }

    @Test("Session not found for unknown node")
    func sessionNotFound() {
        let cache = SessionCache()
        #expect(cache.session(for: NodeID(rawValue: 99)) == nil)
    }

    @Test("Remove invalidates session")
    func removeSession() {
        var cache = SessionCache()
        let nodeID = NodeID(rawValue: 42)

        let session = SecureSession(
            localSessionID: 100,
            peerSessionID: 200,
            establishment: .case,
            peerNodeID: nodeID
        )

        cache.store(session, for: nodeID)
        #expect(cache.session(for: nodeID) != nil)

        cache.remove(for: nodeID)
        #expect(cache.session(for: nodeID) == nil)
    }

    @Test("A session's timeout does not evict it: cached sessions live until removed")
    func timeoutDoesNotEvict() {
        var cache = SessionCache()
        let nodeID = NodeID(rawValue: 42)

        // A 0-second timeout used to read as immediately expired.
        let session = SecureSession(
            localSessionID: 100,
            peerSessionID: 200,
            establishment: .case,
            peerNodeID: nodeID,
            timeout: .seconds(0)
        )

        cache.store(session, for: nodeID)
        #expect(cache.session(for: nodeID) === session)
        cache.remove(for: nodeID)
        #expect(cache.session(for: nodeID) == nil)
    }

    @Test("Session ID allocation is sequential")
    func sessionIDAllocation() {
        var cache = SessionCache()

        let id1 = cache.reserveSessionID(excluding: [])
        let id2 = cache.reserveSessionID(excluding: [])
        let id3 = cache.reserveSessionID(excluding: [])

        #expect(id1 == 100)
        #expect(id2 == 101)
        #expect(id3 == 102)
    }

    @Test("Allocation near the wrap skips registered, cached and reserved IDs")
    func allocationSkipsInUseIDsAcrossWrap() {
        var cache = SessionCache(nextSessionID: UInt16.max - 2)
        let cached = SecureSession(
            localSessionID: UInt16.max - 1,
            peerSessionID: 200,
            establishment: .case,
            peerNodeID: NodeID(rawValue: 42)
        )
        cache.store(cached, for: NodeID(rawValue: 42))
        let registered: Set<UInt16> = [UInt16.max, 100]

        let first = cache.reserveSessionID(excluding: registered)
        #expect(first == UInt16.max - 2)
        // max-1 cached, max registered, wrap, 100 registered.
        let second = cache.reserveSessionID(excluding: registered)
        #expect(second == 101)

        // A further cycle skips the two reserved IDs as well.
        var handedOut: [UInt16] = []
        for _ in 0..<(Int(UInt16.max) - 100 + 1) {
            if let id = cache.reserveSessionID(excluding: registered) {
                handedOut.append(id)
                cache.releaseSessionID(id)
            }
        }
        let inUse: Set<UInt16> = [UInt16.max - 2, UInt16.max - 1, UInt16.max, 100, 101]
        #expect(!handedOut.contains { inUse.contains($0) })
        #expect(Set(handedOut).count == Int(UInt16.max) - 100 + 1 - inUse.count)

        // Released, an ID is free again.
        cache.releaseSessionID(101)
        var sawReleased = false
        for _ in 0..<(Int(UInt16.max) - 100 + 1) {
            guard let id = cache.reserveSessionID(excluding: registered) else { break }
            cache.releaseSessionID(id)
            if id == 101 { sawReleased = true; break }
        }
        #expect(sawReleased)
    }

    @Test("Allocation returns nil when every ID is in use")
    func allocationExhausted() {
        var cache = SessionCache()
        #expect(cache.reserveSessionID(excluding: Set(100...UInt16.max)) == nil)
    }
}

// MARK: - Configuration Tests

@Suite("MatterController.Configuration")
struct ConfigurationTests {

    @Test("Default configuration values")
    func defaultValues() {
        let config = MatterController.Configuration(
            fabricID: FabricID(rawValue: 1)
        )

        #expect(config.fabricID == FabricID(rawValue: 1))
        #expect(config.controllerNodeID == NodeID(rawValue: 1))
        #expect(config.vendorID == .test)
        #expect(config.operationTimeout == .seconds(30))
        #expect(config.commissioningTimeout == .seconds(120))
    }

    @Test("Custom configuration values")
    func customValues() {
        let key = P256.Signing.PrivateKey()
        let config = MatterController.Configuration(
            fabricID: FabricID(rawValue: 42),
            controllerNodeID: NodeID(rawValue: 5),
            vendorID: VendorID(rawValue: 0xFFF1),
            rootKey: key,
            operationTimeout: .seconds(10),
            commissioningTimeout: .seconds(60)
        )

        #expect(config.fabricID == FabricID(rawValue: 42))
        #expect(config.controllerNodeID == NodeID(rawValue: 5))
        #expect(config.vendorID == VendorID(rawValue: 0xFFF1))
        #expect(config.operationTimeout == .seconds(10))
        #expect(config.commissioningTimeout == .seconds(60))
    }
}
