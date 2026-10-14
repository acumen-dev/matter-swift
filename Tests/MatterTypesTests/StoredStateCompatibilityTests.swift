// StoredStateCompatibilityTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
@testable import MatterTypes

@Suite("Stored state compatibility")
struct StoredStateCompatibilityTests {

    /// State as written before schema versions and attestation records existed.
    static let pre3cBlob = """
        {
          "identity": {
            "rootKeyRaw": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            "fabricIndex": 1, "fabricID": 1, "controllerNodeID": 1,
            "rcacTLV": "AQID", "nocTLV": "BAUG",
            "operationalKeyRaw": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            "vendorID": 65521, "ipkEpochKey": "AAAAAAAAAAAAAAAAAAAAAA=="
          },
          "devices": [
            { "nodeID": 2, "fabricIndex": 1, "commissionedAt": 721692800.5 }
          ],
          "nextNodeID": 3
        }
        """

    static func state(schemaVersion: Int?) throws -> Data {
        var object = try #require(
            JSONSerialization.jsonObject(with: Data(pre3cBlob.utf8)) as? [String: Any])
        if let schemaVersion { object["schemaVersion"] = schemaVersion }
        return try JSONSerialization.data(withJSONObject: object)
    }

    @Test("a pre-3c blob decodes as schema 1 with no attestation")
    func pre3cBlobDecodes() throws {
        let decoded = try JSONDecoder().decode(StoredControllerState.self, from: Data(Self.pre3cBlob.utf8))
        #expect(decoded.schemaVersion == 1)
        #expect(decoded.devices.first?.attestation == nil)
        #expect(decoded.nextNodeID == 3)
    }

    @Test("a state written now carries the current schema version")
    func currentVersionRoundTrips() throws {
        #expect(StoredControllerState.currentSchemaVersion == 2)
        let decoded = try JSONDecoder().decode(StoredControllerState.self, from: Data(Self.pre3cBlob.utf8))
        var state = decoded
        state.schemaVersion = StoredControllerState.currentSchemaVersion
        let again = try JSONDecoder().decode(StoredControllerState.self, from: JSONEncoder().encode(state))
        #expect(again == state)
        #expect(again.schemaVersion == 2)
    }

    @Test("a newer schemaVersion throws rather than loading")
    func newerSchemaThrows() throws {
        for version in [3, 99] {
            let data = try Self.state(schemaVersion: version)
            #expect(throws: DecodingError.self) {
                try JSONDecoder().decode(StoredControllerState.self, from: data)
            }
        }
        // The current version and explicit 1 still decode.
        #expect(try JSONDecoder().decode(StoredControllerState.self, from: Self.state(schemaVersion: 2)).schemaVersion == 2)
        #expect(try JSONDecoder().decode(StoredControllerState.self, from: Self.state(schemaVersion: 1)).schemaVersion == 1)
    }

    @Test("a zero or negative schemaVersion throws")
    func invalidSchemaThrows() throws {
        for version in [0, -1] {
            let data = try Self.state(schemaVersion: version)
            #expect(throws: DecodingError.self) {
                try JSONDecoder().decode(StoredControllerState.self, from: data)
            }
        }
    }

    @Test("attestation records round-trip with fixed dates")
    func attestationRoundTrip() throws {
        let approvedAt = Date(timeIntervalSince1970: 1_700_000_500)
        let records: [StoredAttestationRecord] = [
            .verified(paaSubject: "CN=Test PAA", vendorID: 0xFFF1, productID: 0x8000),
            .overridden(dacFingerprint: Data(repeating: 0xAB, count: 32), reason: "untrustedRoot", approvedAt: approvedAt),
        ]
        for record in records {
            let again = try JSONDecoder().decode(StoredAttestationRecord.self, from: JSONEncoder().encode(record))
            #expect(again == record)
        }
    }
}
