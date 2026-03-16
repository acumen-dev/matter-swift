// AppleDiscoveryTests.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(Network)
import Testing
import Foundation
import Network
import MatterApple
import MatterTransport

@Suite("AppleDiscovery")
struct AppleDiscoveryTests {

    @Test("Advertise and stop advertising")
    func advertiseAndStop() async throws {
        let discovery = AppleDiscovery()

        let service = MatterServiceRecord(
            name: "TestDevice-3840",
            serviceType: .commissionable,
            host: "",
            port: 5560,
            txtRecords: ["D": "3840", "VP": "65521+32769", "CM": "1"]
        )

        try await discovery.advertise(service: service)
        await discovery.stopAdvertising()
    }

    @Test("Browse discovers advertised service")
    func browseDiscoversService() async throws {
        let advertiser = AppleDiscovery()
        let browser = AppleDiscovery()

        let service = MatterServiceRecord(
            name: "BrowseTest-1234",
            serviceType: .commissionable,
            host: "",
            port: 5562,
            txtRecords: ["D": "1234", "CM": "1"]
        )

        try await advertiser.advertise(service: service)

        // Give mDNS time to propagate
        try await Task.sleep(for: .milliseconds(500))

        let stream = browser.browse(type: .commissionable)
        let found = await withTaskGroup(of: MatterServiceRecord?.self) { group in
            group.addTask {
                for await record in stream {
                    if record.name.contains("BrowseTest-1234") {
                        return record
                    }
                }
                return nil
            }
            group.addTask {
                try? await Task.sleep(for: .seconds(5))
                return nil
            }
            let result = await group.next()!
            group.cancelAll()
            return result
        }

        await advertiser.stopAdvertising()

        #expect(found != nil)
        #expect(found?.name.contains("BrowseTest-1234") == true)
    }

    @Test("Multi-service advertising supports concurrent services")
    func multiServiceAdvertising() async throws {
        let discovery = AppleDiscovery()

        let commissionable = MatterServiceRecord(
            name: "MultiTest-Comm",
            serviceType: .commissionable,
            host: "",
            port: 5570,
            txtRecords: ["D": "3840", "CM": "1"]
        )

        let operational = MatterServiceRecord(
            name: "MultiTest-Op",
            serviceType: .operational,
            host: "",
            port: 5571,
            txtRecords: [:]
        )

        // Both should succeed without replacing each other
        try await discovery.advertise(service: commissionable)
        try await discovery.advertise(service: operational)

        // Selective stop should leave the other running
        await discovery.stopAdvertising(name: "MultiTest-Comm")

        // Clean up
        await discovery.stopAdvertising()
    }

    @Test("TXT record extraction from NWTXTRecord")
    func txtRecordExtraction() async throws {
        // Verify NWTXTRecord round-trips string values correctly
        var txtRecord = NWTXTRecord()
        txtRecord["D"] = "5678"
        txtRecord["VP"] = "65521+32769"
        txtRecord["CM"] = "1"

        // Verify round-trip through NWTXTRecord
        #expect(txtRecord["D"] == "5678")
        #expect(txtRecord["VP"] == "65521+32769")
        #expect(txtRecord["CM"] == "1")
    }
}
#endif
