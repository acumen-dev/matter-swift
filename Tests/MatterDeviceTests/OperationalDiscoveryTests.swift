// OperationalDiscoveryTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterTransport

@Suite("Operational Discovery")
struct OperationalDiscoveryTests {

    // MARK: - OperationalInstanceName

    @Test("Instance name format: 16 hex chars, dash, 16 hex chars")
    func instanceNameFormat() {
        let name = OperationalInstanceName(
            compressedFabricID: 0x0000000000001234,
            nodeID: 0x000000000000002A
        )

        #expect(name.instanceName == "0000000000001234-000000000000002A")
    }

    @Test("Instance name with large values")
    func instanceNameLargeValues() {
        let name = OperationalInstanceName(
            compressedFabricID: 0xDEADBEEFCAFE1234,
            nodeID: 0xFFFFFFFFFFFFFFFF
        )

        #expect(name.instanceName == "DEADBEEFCAFE1234-FFFFFFFFFFFFFFFF")
    }

    @Test("Instance name with zero values")
    func instanceNameZeros() {
        let name = OperationalInstanceName(
            compressedFabricID: 0,
            nodeID: 0
        )

        #expect(name.instanceName == "0000000000000000-0000000000000000")
    }

    @Test("Fabric subtype format")
    func fabricSubtypeFormat() {
        let name = OperationalInstanceName(
            compressedFabricID: 0xABCDEF0123456789,
            nodeID: 42
        )

        #expect(name.fabricSubtype == "_IABCDEF0123456789._sub._matter._tcp")
    }

    @Test("Parse instance name round-trip")
    func parseRoundTrip() {
        let original = OperationalInstanceName(
            compressedFabricID: 0x1234567890ABCDEF,
            nodeID: 0xFEDCBA9876543210
        )

        let parsed = OperationalInstanceName.parse(original.instanceName)
        #expect(parsed != nil)
        #expect(parsed == original)
        #expect(parsed?.compressedFabricID == original.compressedFabricID)
        #expect(parsed?.nodeID == original.nodeID)
    }

    @Test("Parse invalid instance names returns nil")
    func parseInvalid() {
        // Too short
        #expect(OperationalInstanceName.parse("1234-5678") == nil)

        // Missing separator
        #expect(OperationalInstanceName.parse("0000000000001234_000000000000002A") == nil)

        // Non-hex characters
        #expect(OperationalInstanceName.parse("ZZZZZZZZZZZZZZZZ-0000000000000001") == nil)

        // Empty
        #expect(OperationalInstanceName.parse("") == nil)

        // Too many parts
        #expect(OperationalInstanceName.parse("0000000000001234-000000000000002A-extra") == nil)
    }

    @Test("Equatable conformance")
    func equatable() {
        let a = OperationalInstanceName(compressedFabricID: 100, nodeID: 42)
        let b = OperationalInstanceName(compressedFabricID: 100, nodeID: 42)
        let c = OperationalInstanceName(compressedFabricID: 100, nodeID: 43)

        #expect(a == b)
        #expect(a != c)
    }

    // MARK: - Service Type Constants

    @Test("Operational service type is _matter._tcp")
    func operationalServiceType() {
        #expect(MatterServiceType.operational.rawValue == "_matter._tcp")
    }

    @Test("Commissionable service type is _matterc._udp")
    func commissionableServiceType() {
        #expect(MatterServiceType.commissionable.rawValue == "_matterc._udp")
    }
}
