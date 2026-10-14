// ControllerStoreConformanceTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
import MatterTypes
import MatterCrypto
import MatterTestSupport
import MatterStoreConformance
import MatterTransport
@testable import MatterController


@Suite("Controller store conformance", .timeLimit(.minutes(5)))
struct ControllerStoreConformanceTests {

    static func tempDirectory() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("controller-store-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    static func permissions(of url: URL) throws -> Int {
        let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs[.posixPermissions] as? NSNumber)?.intValue ?? -1
    }

    static func makeController(store: any MatterControllerStore) async throws -> MatterController {
        try await MatterController.loadOrCreate(
            transport: MockUDPTransport(), discovery: MockDiscovery(),
            configuration: .init(fabricID: FabricID(rawValue: 1)), store: store)
    }

    // MARK: - Conformance

    @Test("InMemoryControllerStore conforms")
    func inMemory() async throws {
        try await MatterControllerStoreConformance.run { InMemoryControllerStore() }
    }

    @Test("JSONFileControllerStore conforms")
    func jsonFile() async throws {
        let made = LockedValue<[URL]>([])
        defer { made.withLock { $0 }.forEach { try? FileManager.default.removeItem(at: $0) } }
        try await MatterControllerStoreConformance.run {
            let dir = try Self.tempDirectory()
            made.withLock { $0.append(dir) }
            return JSONFileControllerStore(directory: dir)
        }
    }

    // MARK: - JSON file permissions

    @Test("a saved JSON file is 0600")
    func fileIs0600() async throws {
        let dir = try Self.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = JSONFileControllerStore(directory: dir)
        try await store.save(MatterControllerStoreConformance.sampleState(seed: 1, deviceCount: 1))
        #expect(try Self.permissions(of: dir.appendingPathComponent("controller.json")) == 0o600)
        // No temporary file is left behind.
        #expect(try FileManager.default.contentsOfDirectory(atPath: dir.path) == ["controller.json"])
    }

    @Test("a save tightens an existing 0644 file to 0600")
    func saveTightensExistingFile() async throws {
        let dir = try Self.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("controller.json")
        try Data("{}".utf8).write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: file.path)
        #expect(try Self.permissions(of: file) == 0o644)

        let store = JSONFileControllerStore(directory: dir)
        let state = MatterControllerStoreConformance.sampleState(seed: 2, deviceCount: 2)
        try await store.save(state)
        #expect(try Self.permissions(of: file) == 0o600)
        #expect(try await store.load() == state)
    }

    @Test("JSONFileControllerStore refuses state from a newer schema")
    func newerSchemaRefused() async throws {
        let dir = try Self.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = JSONFileControllerStore(directory: dir)
        try await store.save(MatterControllerStoreConformance.sampleState(seed: 3, deviceCount: 1))
        let file = dir.appendingPathComponent("controller.json")
        let text = try String(contentsOf: file, encoding: .utf8)
            .replacingOccurrences(of: "\"schemaVersion\" : 2", with: "\"schemaVersion\" : 3")
        try Data(text.utf8).write(to: file)
        await #expect(throws: DecodingError.self) { try await store.load() }
    }

    // MARK: - v1 end to end

    @Test("a v1 file loads through loadOrCreate and a save rewrites it as v2 with the identity intact")
    func v1EndToEnd() async throws {
        let dir = try Self.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let fm = try FabricManager(
            rootKey: P256.Signing.PrivateKey(), fabricID: FabricID(rawValue: 7),
            controllerNodeID: NodeID(rawValue: 1), vendorID: .test)
        _ = await fm.allocateNodeID()
        _ = await fm.allocateNodeID()
        var original = StoredControllerState(
            identity: fm.toStoredIdentity(),
            devices: MatterControllerStoreConformance.sampleState(seed: 9, deviceCount: 3).devices
                .map { var d = $0; d.attestation = nil; return d },
            nextNodeID: await fm.nextNodeID)
        original.devices[0].label = "kept"

        var object = try #require(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(original)) as? [String: Any])
        object["schemaVersion"] = nil
        let file = dir.appendingPathComponent("controller.json")
        try JSONSerialization.data(withJSONObject: object).write(to: file)

        let store = JSONFileControllerStore(directory: dir)
        let controller = try await MatterController.loadOrCreate(
            transport: MockUDPTransport(), discovery: MockDiscovery(),
            configuration: .init(fabricID: FabricID(rawValue: 7)), store: store)
        // Trigger a save: remove a device, then compare with the original minus that device.
        await controller.removeDevice(nodeID: NodeID(rawValue: original.devices[2].nodeID))

        let rewritten = try #require(try await store.load())
        #expect(rewritten.schemaVersion == 2)
        #expect(rewritten.identity == original.identity)
        #expect(rewritten.nextNodeID == original.nextNodeID)
        #expect(rewritten.devices.sorted { $0.nodeID < $1.nodeID } == Array(original.devices.prefix(2)))
        let text = try String(contentsOf: file, encoding: .utf8)
        #expect(text.contains("\"schemaVersion\" : 2"))
    }

    // MARK: - loadOrCreate

    @Test("loadOrCreate saves a fresh identity before any commission")
    func freshIdentitySavedImmediately() async throws {
        let store = InMemoryControllerStore()
        let controller = try await Self.makeController(store: store)
        let saved = try #require(try await store.load())
        #expect(saved.schemaVersion == StoredControllerState.currentSchemaVersion)
        #expect(saved.devices.isEmpty)
        #expect(saved.nextNodeID == (await controller.nextNodeID))
        #expect(saved.nextNodeID == saved.identity.controllerNodeID + 1)
        #expect(await store.saveCount == 1)
    }

    @Test("a fresh identity has a random IPK epoch key, different each time")
    func freshIPKIsRandom() async throws {
        let first = InMemoryControllerStore()
        let second = InMemoryControllerStore()
        _ = try await Self.makeController(store: first)
        _ = try await Self.makeController(store: second)
        let a = try #require(try await first.load()).identity.ipkEpochKey
        let b = try #require(try await second.load()).identity.ipkEpochKey
        #expect(a.count == 16)
        #expect(a != Data(repeating: 0, count: 16))
        #expect(b != Data(repeating: 0, count: 16))
        #expect(a != b)
    }

    @Test("a controller loaded from a stored identity keeps its IPK exactly")
    func loadedIPKKept() async throws {
        let store = InMemoryControllerStore()
        _ = try await Self.makeController(store: store)
        var stored = try #require(try await store.load())
        // A pre-existing fabric whose IPK epoch key is the all-zero default must stay all-zero.
        for ipk in [Data(repeating: 0, count: 16), Data((0..<16).map { UInt8($0) })] {
            let identity = stored.identity
            stored.identity = StoredControllerIdentity(
                rootKeyRaw: identity.rootKeyRaw, fabricIndex: identity.fabricIndex,
                fabricID: identity.fabricID, controllerNodeID: identity.controllerNodeID,
                rcacTLV: identity.rcacTLV, nocTLV: identity.nocTLV,
                operationalKeyRaw: identity.operationalKeyRaw, vendorID: identity.vendorID,
                ipkEpochKey: ipk)
            let reloaded = try await Self.makeController(store: InMemoryControllerStore(state: stored))
            #expect(await reloaded.ipkEpochKey == ipk)
        }
    }

    // MARK: - Registry mapping

    @Test("attestation records round-trip through the registry")
    func registryRoundTrip() async throws {
        let approvedAt = Date(timeIntervalSince1970: 1_700_000_500)
        let state = MatterControllerStoreConformance.sampleState(seed: 4, deviceCount: 3)
        let registry = try DeviceRegistry(storedDevices: state.devices)
        let overridden = await registry.device(for: NodeID(rawValue: 3))
        #expect(overridden?.attestation == .overridden(
            dacFingerprint: Data((0..<32).map { 4 &+ 0x60 &+ UInt8($0) }),
            reason: .untrustedRoot, approvedAt: approvedAt))
        let exported = await registry.toStoredDevices().sorted { $0.nodeID < $1.nodeID }
        #expect(exported.map(\.attestation) == state.devices.map(\.attestation))
    }

    @Test("an unknown stored override reason throws, never defaults")
    func unknownReasonThrows() throws {
        var devices = MatterControllerStoreConformance.sampleState(seed: 5, deviceCount: 2).devices
        devices[1].attestation = .overridden(
            dacFingerprint: Data(repeating: 1, count: 32), reason: "someFutureReason",
            approvedAt: Date(timeIntervalSince1970: 1_700_000_500))
        #expect(throws: ControllerError.corruptStoredState(
            "stored attestation override for node 3 has unknown reason \"someFutureReason\"; the state was written by a newer library or is corrupt")) {
            try DeviceRegistry(storedDevices: devices)
        }
    }
}
