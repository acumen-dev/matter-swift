// WildcardReadTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import MatterTypes
import MatterModel
import MatterProtocol
@testable import MatterDevice

@Suite("Wildcard Reads")
struct WildcardReadTests {

    // MARK: - Helpers

    /// Create an OnOff+Descriptor endpoint.
    private func makeOnOffEndpoint(id: EndpointID) -> EndpointConfig {
        EndpointConfig(
            endpointID: id,
            deviceTypes: [(.onOffLight, 1)],
            clusterHandlers: [
                DescriptorHandler(deviceTypes: [(.onOffLight, 1)], serverClusters: [.onOff]),
                OnOffHandler()
            ]
        )
    }

    private func makeAggregatorEndpoint() -> EndpointConfig {
        EndpointConfig(
            endpointID: EndpointManager.aggregatorEndpoint,
            deviceTypes: [(.aggregator, 1)],
            clusterHandlers: [
                DescriptorHandler(deviceTypes: [(.aggregator, 1)], serverClusters: [.descriptor])
            ]
        )
    }

    private func makeManager() -> (EndpointManager, AttributeStore) {
        let store = AttributeStore()
        let manager = EndpointManager(store: store)
        manager.addEndpoint(makeAggregatorEndpoint())
        return (manager, store)
    }

    // MARK: - Wildcard Attribute (specific endpoint + cluster, all attributes)

    @Test("Read all attributes on a specific cluster")
    func readAllAttributesOnCluster() {
        let (manager, _) = makeManager()
        let ep = EndpointID(rawValue: 3)
        manager.addEndpoint(makeOnOffEndpoint(id: ep))

        // Wildcard attribute: endpoint:3, cluster:OnOff, attribute:nil
        let reports = manager.readAttributes([
            AttributePath(endpointID: ep, clusterID: .onOff, attributeID: nil)
        ])

        // OnOff cluster should have at least the onOff attribute
        let dataReports = reports.filter { $0.attributeData != nil }
        #expect(dataReports.count >= 1)

        // All reports should be for endpoint 3, cluster OnOff
        for report in dataReports {
            #expect(report.attributeData?.path.endpointID == ep)
            #expect(report.attributeData?.path.clusterID == .onOff)
        }

        // The onOff attribute specifically should be present
        let onOffReport = dataReports.first {
            $0.attributeData?.path.attributeID == OnOffCluster.Attribute.onOff
        }
        #expect(onOffReport != nil)
        #expect(onOffReport?.attributeData?.data == .bool(false))
    }

    // MARK: - Wildcard Cluster (specific endpoint, all clusters)

    @Test("Read all clusters on a specific endpoint")
    func readAllClustersOnEndpoint() {
        let (manager, _) = makeManager()
        let ep = EndpointID(rawValue: 3)
        manager.addEndpoint(makeOnOffEndpoint(id: ep))

        // Wildcard cluster + attribute: endpoint:3, cluster:nil, attribute:nil
        let reports = manager.readAttributes([
            AttributePath(endpointID: ep, clusterID: nil, attributeID: nil)
        ])

        let dataReports = reports.filter { $0.attributeData != nil }

        // Should have reports from both OnOff and Descriptor clusters
        let clusterIDs = Set(dataReports.compactMap { $0.attributeData?.path.clusterID })
        #expect(clusterIDs.contains(.onOff))
        #expect(clusterIDs.contains(.descriptor))

        // All reports should be for endpoint 3
        for report in dataReports {
            #expect(report.attributeData?.path.endpointID == ep)
        }
    }

    // MARK: - Full Wildcard (all endpoints, all clusters, all attributes)

    @Test("Full wildcard read returns all attributes from all endpoints")
    func readFullWildcard() {
        let (manager, _) = makeManager()
        let ep3 = EndpointID(rawValue: 3)
        let ep4 = EndpointID(rawValue: 4)
        manager.addEndpoint(makeOnOffEndpoint(id: ep3))
        manager.addEndpoint(makeOnOffEndpoint(id: ep4))

        // Full wildcard: endpoint:nil, cluster:nil, attribute:nil
        let reports = manager.readAttributes([
            AttributePath(endpointID: nil, clusterID: nil, attributeID: nil)
        ])

        let dataReports = reports.filter { $0.attributeData != nil }

        // Should have reports from all three endpoints (aggregator + ep3 + ep4)
        let endpointIDs = Set(dataReports.compactMap { $0.attributeData?.path.endpointID })
        #expect(endpointIDs.contains(EndpointManager.aggregatorEndpoint))
        #expect(endpointIDs.contains(ep3))
        #expect(endpointIDs.contains(ep4))

        // Should have many attributes (at least descriptor + onOff from each)
        #expect(dataReports.count >= 4)
    }

    // MARK: - Specific Cluster Across All Endpoints

    @Test("Read specific cluster across all endpoints")
    func readSpecificClusterAcrossEndpoints() {
        let (manager, _) = makeManager()
        let ep3 = EndpointID(rawValue: 3)
        let ep4 = EndpointID(rawValue: 4)
        manager.addEndpoint(makeOnOffEndpoint(id: ep3))
        manager.addEndpoint(makeOnOffEndpoint(id: ep4))

        // Wildcard endpoint, specific cluster, wildcard attribute
        let reports = manager.readAttributes([
            AttributePath(endpointID: nil, clusterID: .onOff, attributeID: nil)
        ])

        let dataReports = reports.filter { $0.attributeData != nil }

        // OnOff cluster only exists on ep3 and ep4, not on aggregator
        let endpointIDs = Set(dataReports.compactMap { $0.attributeData?.path.endpointID })
        #expect(endpointIDs.contains(ep3))
        #expect(endpointIDs.contains(ep4))
        #expect(!endpointIDs.contains(EndpointManager.aggregatorEndpoint))

        // All reports should be from OnOff cluster
        for report in dataReports {
            #expect(report.attributeData?.path.clusterID == .onOff)
        }
    }

    // MARK: - Error Status Behavior

    @Test("Wildcard reads silently skip missing clusters — no error statuses")
    func wildcardSkipsMissingCluster() {
        let (manager, _) = makeManager()
        let ep3 = EndpointID(rawValue: 3)
        manager.addEndpoint(makeOnOffEndpoint(id: ep3))

        // Wildcard endpoint, specific cluster that only exists on some endpoints
        let reports = manager.readAttributes([
            AttributePath(endpointID: nil, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff)
        ])

        // No error statuses — wildcards silently skip non-matching
        let errorReports = reports.filter { $0.attributeStatus != nil }
        #expect(errorReports.isEmpty)

        // Only data from endpoints that have OnOff
        let dataReports = reports.filter { $0.attributeData != nil }
        #expect(dataReports.count == 1)  // Only ep3 has OnOff
    }

    @Test("Targeted missing cluster still returns error status")
    func targetedMissingClusterReturnsError() {
        let (manager, _) = makeManager()
        let ep = EndpointID(rawValue: 3)
        manager.addEndpoint(makeOnOffEndpoint(id: ep))

        // Targeted read for a cluster that doesn't exist
        let reports = manager.readAttributes([
            AttributePath(endpointID: ep, clusterID: .levelControl, attributeID: AttributeID(rawValue: 0))
        ])

        #expect(reports.count == 1)
        #expect(reports[0].attributeStatus?.status == .unsupportedCluster)
    }

    @Test("Targeted missing attribute still returns error status")
    func targetedMissingAttributeReturnsError() {
        let (manager, _) = makeManager()
        let ep = EndpointID(rawValue: 3)
        manager.addEndpoint(makeOnOffEndpoint(id: ep))

        // Targeted read for an attribute that doesn't exist
        let reports = manager.readAttributes([
            AttributePath(endpointID: ep, clusterID: .onOff, attributeID: AttributeID(rawValue: 0xFFFF))
        ])

        #expect(reports.count == 1)
        #expect(reports[0].attributeStatus?.status == .unsupportedAttribute)
    }

    @Test("Wildcard cluster skips missing — no unsupported cluster errors")
    func wildcardClusterSkipsMissing() {
        let (manager, _) = makeManager()
        let ep = EndpointID(rawValue: 3)
        manager.addEndpoint(makeOnOffEndpoint(id: ep))

        // Specific endpoint, wildcard cluster, specific attribute
        // This reads attribute 0 from ALL clusters on endpoint 3
        let reports = manager.readAttributes([
            AttributePath(endpointID: ep, clusterID: nil, attributeID: AttributeID(rawValue: 0))
        ])

        // Should get data from clusters that have attribute 0, no errors
        let errorReports = reports.filter { $0.attributeStatus != nil }
        #expect(errorReports.isEmpty)

        let dataReports = reports.filter { $0.attributeData != nil }
        #expect(dataReports.count >= 1)
    }

    // MARK: - Data Version

    @Test("Wildcard read includes data version per cluster")
    func wildcardReadIncludesDataVersion() {
        let (manager, store) = makeManager()
        let ep = EndpointID(rawValue: 3)
        manager.addEndpoint(makeOnOffEndpoint(id: ep))

        // Get the expected data versions
        let onOffVersion = store.dataVersion(endpoint: ep, cluster: .onOff)
        let descriptorVersion = store.dataVersion(endpoint: ep, cluster: .descriptor)

        let reports = manager.readAttributes([
            AttributePath(endpointID: ep, clusterID: nil, attributeID: nil)
        ])

        let dataReports = reports.filter { $0.attributeData != nil }

        // Verify each report has the correct data version for its cluster
        for report in dataReports {
            guard let data = report.attributeData else { continue }
            if data.path.clusterID == .onOff {
                #expect(data.dataVersion == onOffVersion)
            } else if data.path.clusterID == .descriptor {
                #expect(data.dataVersion == descriptorVersion)
            }
        }
    }
}
