// DataVersionFilteringTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import MatterTypes
import MatterModel
import MatterProtocol
@testable import MatterDevice

@Suite("DataVersion Filtering")
struct DataVersionFilteringTests {

    // MARK: - Helpers

    /// Build an EndpointManager with a single OnOff endpoint at the given ID.
    private func makeManagerWithOnOff(endpointID: EndpointID = EndpointID(rawValue: 2)) -> (EndpointManager, AttributeStore) {
        let store = AttributeStore()
        let manager = EndpointManager(store: store)

        // Add aggregator (required for PartsList updates)
        let aggregator = EndpointConfig(
            endpointID: EndpointManager.aggregatorEndpoint,
            deviceTypes: [(.aggregator, 1)],
            clusterHandlers: [
                DescriptorHandler(deviceTypes: [(.aggregator, 1)], serverClusters: [.descriptor])
            ]
        )
        manager.addEndpoint(aggregator)

        let onOffEndpoint = EndpointConfig(
            endpointID: endpointID,
            deviceTypes: [(.onOffLight, 1)],
            clusterHandlers: [
                OnOffHandler(),
                DescriptorHandler(deviceTypes: [(.onOffLight, 1)], serverClusters: [.onOff, .descriptor])
            ]
        )
        manager.addEndpoint(onOffEndpoint)
        return (manager, store)
    }

    // MARK: - Test 1: Filter matching current version skips cluster

    @Test("Filter matching current dataVersion omits cluster attributes from response")
    func filterMatchingVersionSkipsCluster() {
        let epID = EndpointID(rawValue: 2)
        let (manager, store) = makeManagerWithOnOff(endpointID: epID)

        // Get the current dataVersion for the OnOff cluster
        let currentVersion = store.dataVersion(endpoint: epID, cluster: .onOff)

        // Read with a filter that matches the current version
        let paths = [AttributePath(endpointID: epID, clusterID: .onOff)]
        let filters = [DataVersionFilter(
            endpointID: epID,
            clusterID: .onOff,
            dataVersion: currentVersion.rawValue
        )]

        let reports = manager.readAttributes(paths, dataVersionFilters: filters)

        // All OnOff attributes should be absent (cluster was filtered out)
        let onOffReports = reports.filter { report in
            report.attributeData?.path.clusterID == .onOff
        }
        #expect(onOffReports.isEmpty, "OnOff cluster should be absent when dataVersion filter matches")
    }

    // MARK: - Test 2: Stale filter version returns attributes

    @Test("Filter with outdated dataVersion does not skip cluster attributes")
    func staleFilterVersionReturnsAttributes() {
        let epID = EndpointID(rawValue: 2)
        let (manager, store) = makeManagerWithOnOff(endpointID: epID)

        // Write to OnOff to ensure its dataVersion is at least 1
        store.set(endpoint: epID, cluster: .onOff, attribute: OnOffCluster.Attribute.onOff, value: .bool(true))
        let currentVersion = store.dataVersion(endpoint: epID, cluster: .onOff)

        // Use a stale version (one less than current)
        let staleVersion = currentVersion.rawValue == 0 ? UInt32.max : currentVersion.rawValue - 1

        let paths = [AttributePath(endpointID: epID, clusterID: .onOff)]
        let filters = [DataVersionFilter(
            endpointID: epID,
            clusterID: .onOff,
            dataVersion: staleVersion
        )]

        let reports = manager.readAttributes(paths, dataVersionFilters: filters)

        // OnOff attributes should be present (stale filter does not skip)
        let onOffReports = reports.filter { report in
            report.attributeData?.path.clusterID == .onOff
        }
        #expect(!onOffReports.isEmpty, "OnOff cluster attributes should be present when filter version is stale")
    }

    // MARK: - Test 3: Write increments dataVersion

    @Test("Writing an attribute increments the cluster dataVersion in AttributeDataIB")
    func writeIncrementsDataVersion() {
        let epID = EndpointID(rawValue: 2)
        let (manager, store) = makeManagerWithOnOff(endpointID: epID)

        // Capture version before write
        let versionBefore = store.dataVersion(endpoint: epID, cluster: .onOff).rawValue

        // Read current version from report
        let pathsBefore = [AttributePath(endpointID: epID, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff)]
        let reportsBefore = manager.readAttributes(pathsBefore)
        let versionInReportBefore = reportsBefore.first?.attributeData?.dataVersion.rawValue

        // Write to OnOff to change its value (forces a version increment)
        store.set(endpoint: epID, cluster: .onOff, attribute: OnOffCluster.Attribute.onOff, value: .bool(true))

        // Capture version after write
        let versionAfter = store.dataVersion(endpoint: epID, cluster: .onOff).rawValue

        // Read again
        let reportsAfter = manager.readAttributes(pathsBefore)
        let versionInReportAfter = reportsAfter.first?.attributeData?.dataVersion.rawValue

        #expect(versionAfter != versionBefore, "dataVersion should change after a write")
        if let before = versionInReportBefore, let after = versionInReportAfter {
            #expect(after != before, "dataVersion in AttributeDataIB should be higher after write")
        }
    }

    // MARK: - Test 4: DataVersionFilter TLV round-trip

    @Test("DataVersionFilter encodes to TLV and decodes back correctly")
    func dataVersionFilterRoundTrip() throws {
        let original = DataVersionFilter(
            endpointID: EndpointID(rawValue: 5),
            clusterID: ClusterID(rawValue: 0x0006),
            dataVersion: 0xDEAD_BEEF
        )

        let encoded = original.toTLVElement()
        let decoded = try DataVersionFilter.fromTLVElement(encoded)

        #expect(decoded == original, "DataVersionFilter should survive a TLV encode/decode round-trip")
        #expect(decoded.endpointID == EndpointID(rawValue: 5))
        #expect(decoded.clusterID == ClusterID(rawValue: 0x0006))
        #expect(decoded.dataVersion == 0xDEAD_BEEF)
    }
}
