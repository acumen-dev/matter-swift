// MatterControllerStoreConformance.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Testing
import MatterTypes

/// Runs the ``MatterControllerStore`` contract against any implementation.
///
/// `make` returns a fresh, empty store each time it is called. Failures are reported through
/// `Issue.record`, so a caller just awaits `run(make:)` inside a `@Test`.
public enum MatterControllerStoreConformance {

    public static func run(make: @Sendable () async throws -> any MatterControllerStore) async throws {
        // 1. Nothing saved: nil.
        do {
            let store = try await make()
            let loaded = try await store.load()
            #expect(loaded == nil, "load() on an empty store must return nil")
        }

        // 2. Save then load: equal, secrets byte for byte, both attestation record kinds.
        do {
            let store = try await make()
            let state = sampleState(seed: 0x10, deviceCount: 3)
            try await store.save(state)
            let loaded = try await store.load()
            #expect(loaded == state, "a saved state must load back equal")
            #expect(loaded?.identity.rootKeyRaw == state.identity.rootKeyRaw)
            #expect(loaded?.identity.operationalKeyRaw == state.identity.operationalKeyRaw)
            #expect(loaded?.identity.ipkEpochKey == state.identity.ipkEpochKey)
            #expect(loaded?.schemaVersion == StoredControllerState.currentSchemaVersion)
            let kinds = loaded?.devices.map(\.attestation) ?? []
            #expect(kinds.contains { if case .verified = $0 { true } else { false } })
            #expect(kinds.contains { if case .overridden = $0 { true } else { false } })
            #expect(kinds.contains { $0 == nil })
        }

        // 3. A second save replaces the first entirely.
        do {
            let store = try await make()
            try await store.save(sampleState(seed: 0x10, deviceCount: 3))
            let second = sampleState(seed: 0x70, deviceCount: 1)
            try await store.save(second)
            let loaded = try await store.load()
            #expect(loaded == second, "a second save must replace the first, not merge")
            #expect(loaded?.devices.count == 1)
        }

        // 4. A pre-3c blob decodes as schema 1 with no attestation. A Codable check; no store.
        do {
            let decoded = try JSONDecoder().decode(StoredControllerState.self, from: Data(pre3cBlob.utf8))
            #expect(decoded.schemaVersion == 1, "a blob without schemaVersion is version 1")
            #expect(decoded.devices.count == 1)
            #expect(decoded.devices.first?.attestation == nil)
            #expect(decoded.nextNodeID == 5)
        }
    }

    // MARK: - Fixtures

    /// A controller state with `deviceCount` devices cycling verified, overridden, none.
    /// Dates are fixed so a run never depends on the wall clock.
    public static func sampleState(seed: UInt8, deviceCount: Int) -> StoredControllerState {
        func bytes(_ n: Int, _ offset: UInt8) -> Data {
            Data((0..<n).map { seed &+ offset &+ UInt8($0) })
        }
        let identity = StoredControllerIdentity(
            rootKeyRaw: bytes(32, 0x00),
            fabricIndex: 1,
            fabricID: 0x1122_3344_5566_7788,
            controllerNodeID: 1,
            rcacTLV: bytes(40, 0x20),
            nocTLV: bytes(48, 0x30),
            operationalKeyRaw: bytes(32, 0x40),
            vendorID: 0xFFF1,
            ipkEpochKey: bytes(16, 0x50))
        let commissionedAt = Date(timeIntervalSince1970: 1_700_000_000)
        let approvedAt = Date(timeIntervalSince1970: 1_700_000_500)
        let devices = (0..<deviceCount).map { i -> StoredCommissionedDevice in
            let attestation: StoredAttestationRecord?
            switch i % 3 {
            case 0:
                attestation = .verified(paaSubject: "CN=Test PAA,O=Test", vendorID: 0xFFF1, productID: 0x8000)
            case 1:
                attestation = .overridden(
                    dacFingerprint: bytes(32, 0x60), reason: "untrustedRoot", approvedAt: approvedAt)
            default:
                attestation = nil
            }
            return StoredCommissionedDevice(
                nodeID: UInt64(2 + i), fabricIndex: 1,
                vendorID: 0xFFF1, productID: 0x8000,
                operationalHost: "192.0.2.\(10 + i)", operationalPort: 5540,
                label: "device \(i)", commissionedAt: commissionedAt,
                mrpIdleIntervalMs: 500, mrpActiveIntervalMs: 300, mrpActiveThresholdMs: 4000,
                attestation: attestation)
        }
        return StoredControllerState(identity: identity, devices: devices, nextNodeID: UInt64(2 + deviceCount))
    }

    /// State as written before schema versions and attestation records existed.
    public static let pre3cBlob = """
        {
          "identity": {
            "rootKeyRaw": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            "fabricIndex": 1,
            "fabricID": 1,
            "controllerNodeID": 1,
            "rcacTLV": "AQID",
            "nocTLV": "BAUG",
            "operationalKeyRaw": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            "vendorID": 65521,
            "ipkEpochKey": "AAAAAAAAAAAAAAAAAAAAAA=="
          },
          "devices": [
            {
              "nodeID": 2,
              "fabricIndex": 1,
              "vendorID": 65521,
              "productID": 32768,
              "operationalHost": "192.0.2.10",
              "operationalPort": 5540,
              "label": "lamp",
              "commissionedAt": 721692800.5,
              "mrpIdleIntervalMs": 500
            }
          ],
          "nextNodeID": 5
        }
        """
}
