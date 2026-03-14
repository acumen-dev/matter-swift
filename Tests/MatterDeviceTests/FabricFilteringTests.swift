// FabricFilteringTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterModel
import MatterProtocol
@testable import MatterDevice

@Suite("Fabric-Scoped Attribute Filtering")
struct FabricFilteringTests {

    private let fabric1 = FabricIndex(rawValue: 1)
    private let fabric2 = FabricIndex(rawValue: 2)
    private let testSession: UInt16 = 1
    private let rootEndpoint = EndpointID(rawValue: 0)

    // MARK: - Helpers

    /// Build an IMRequestContext for a CASE session on the given fabric, with admin ACLs for all endpoints.
    private func makeContext(fabricIndex: FabricIndex, isFabricFiltered: Bool = true) -> IMRequestContext {
        IMRequestContext(
            checkerContext: ACLChecker.RequestContext(
                isPASE: false,
                subjectNodeID: 42,
                fabricIndex: fabricIndex
            ),
            acls: [
                AccessControlCluster.AccessControlEntry(
                    privilege: .administer,
                    authMode: .case,
                    subjects: [42],
                    fabricIndex: fabricIndex
                )
            ],
            isFabricFiltered: isFabricFiltered
        )
    }

    /// Build a MatterBridge pre-populated with ACL entries for two fabrics.
    ///
    /// ACL entries for both fabrics are written directly into the attribute store so tests
    /// can verify that reads return only the requesting fabric's entries when filtered.
    private func makeBridgeWithTwoFabricACLs() -> MatterBridge {
        let bridge = MatterBridge()

        // Build two ACL entries — one per fabric — and store them as a TLV array
        let ace1 = AccessControlCluster.AccessControlEntry(
            privilege: .administer,
            authMode: .case,
            subjects: [100],
            fabricIndex: fabric1
        )
        let ace2 = AccessControlCluster.AccessControlEntry(
            privilege: .operate,
            authMode: .case,
            subjects: [200],
            fabricIndex: fabric2
        )

        bridge.store.set(
            endpoint: rootEndpoint,
            cluster: .accessControl,
            attribute: AccessControlCluster.Attribute.acl,
            value: .array([ace1.toTLVElement(), ace2.toTLVElement()])
        )

        return bridge
    }

    /// Build a MatterBridge pre-populated with fabric descriptors for two fabrics.
    private func makeBridgeWithTwoFabrics() -> MatterBridge {
        let bridge = MatterBridge()

        let fab1 = OperationalCredentialsCluster.FabricDescriptor(
            rootPublicKey: Data(repeating: 0x01, count: 65),
            vendorID: 0xFFF1,
            fabricID: FabricID(rawValue: 1),
            nodeID: NodeID(rawValue: 1001),
            label: "Fabric1",
            fabricIndex: fabric1
        )
        let fab2 = OperationalCredentialsCluster.FabricDescriptor(
            rootPublicKey: Data(repeating: 0x02, count: 65),
            vendorID: 0xFFF2,
            fabricID: FabricID(rawValue: 2),
            nodeID: NodeID(rawValue: 2002),
            label: "Fabric2",
            fabricIndex: fabric2
        )

        bridge.store.set(
            endpoint: rootEndpoint,
            cluster: .operationalCredentials,
            attribute: OperationalCredentialsCluster.Attribute.fabrics,
            value: .array([fab1.toTLVElement(), fab2.toTLVElement()])
        )

        return bridge
    }

    // MARK: - Test 1: ACL read with isFabricFiltered=true returns only same-fabric entries

    @Test("ACL read with isFabricFiltered=true returns only requesting fabric's ACL entries")
    func aclReadFabricFiltered() async throws {
        let bridge = makeBridgeWithTwoFabricACLs()
        let ctx = makeContext(fabricIndex: fabric1, isFabricFiltered: true)

        let request = ReadRequest(
            attributeRequests: [
                AttributePath(
                    endpointID: rootEndpoint,
                    clusterID: .accessControl,
                    attributeID: AccessControlCluster.Attribute.acl
                )
            ],
            isFabricFiltered: true
        )

        let responses = try await bridge.handleIM(
            opcode: .readRequest,
            payload: request.tlvEncode(),
            sessionID: testSession,
            fabricIndex: fabric1,
            requestContext: ctx
        ).allPairs

        let report = try ReportData.fromTLV(responses[0].1)
        let dataReports = report.attributeReports.compactMap { $0.attributeData }
        #expect(dataReports.count == 1)

        // The ACL attribute value should be an array containing only fabric1's entry
        guard case .array(let entries) = dataReports[0].data else {
            Issue.record("Expected array for ACL attribute")
            return
        }
        #expect(entries.count == 1)

        // Parse the remaining entry and verify it belongs to fabric1
        let ace = try AccessControlCluster.AccessControlEntry.fromTLVElement(entries[0])
        #expect(ace.fabricIndex == fabric1)
        #expect(ace.privilege == .administer)
    }

    // MARK: - Test 2: ACL read with isFabricFiltered=false returns all entries

    @Test("ACL read with isFabricFiltered=false returns all fabric ACL entries")
    func aclReadNotFabricFiltered() async throws {
        let bridge = makeBridgeWithTwoFabricACLs()
        // Use a context where both fabrics have entries but we request unfiltered
        // We use fabric1 as the session but set isFabricFiltered=false on the request
        let ctx = makeContext(fabricIndex: fabric1, isFabricFiltered: false)

        let request = ReadRequest(
            attributeRequests: [
                AttributePath(
                    endpointID: rootEndpoint,
                    clusterID: .accessControl,
                    attributeID: AccessControlCluster.Attribute.acl
                )
            ],
            isFabricFiltered: false
        )

        let responses = try await bridge.handleIM(
            opcode: .readRequest,
            payload: request.tlvEncode(),
            sessionID: testSession,
            fabricIndex: fabric1,
            requestContext: ctx
        ).allPairs

        let report = try ReportData.fromTLV(responses[0].1)
        let dataReports = report.attributeReports.compactMap { $0.attributeData }
        #expect(dataReports.count == 1)

        // Both ACL entries should be present
        guard case .array(let entries) = dataReports[0].data else {
            Issue.record("Expected array for ACL attribute")
            return
        }
        #expect(entries.count == 2)
    }

    // MARK: - Test 3: OperationalCredentials fabrics list is fabric-filtered

    @Test("OperationalCredentials fabrics list is filtered to requesting fabric only")
    func fabricsListFabricFiltered() async throws {
        let bridge = makeBridgeWithTwoFabrics()
        let ctx = makeContext(fabricIndex: fabric1, isFabricFiltered: true)

        let request = ReadRequest(
            attributeRequests: [
                AttributePath(
                    endpointID: rootEndpoint,
                    clusterID: .operationalCredentials,
                    attributeID: OperationalCredentialsCluster.Attribute.fabrics
                )
            ],
            isFabricFiltered: true
        )

        let responses = try await bridge.handleIM(
            opcode: .readRequest,
            payload: request.tlvEncode(),
            sessionID: testSession,
            fabricIndex: fabric1,
            requestContext: ctx
        ).allPairs

        let report = try ReportData.fromTLV(responses[0].1)
        let dataReports = report.attributeReports.compactMap { $0.attributeData }
        #expect(dataReports.count == 1)

        guard case .array(let entries) = dataReports[0].data else {
            Issue.record("Expected array for fabrics attribute")
            return
        }
        #expect(entries.count == 1)

        let descriptor = try OperationalCredentialsCluster.FabricDescriptor.fromTLVElement(entries[0])
        #expect(descriptor.fabricIndex == fabric1)
        #expect(descriptor.label == "Fabric1")
    }

    // MARK: - Test 4: Subscription report applies fabric filtering

    @Test("Subscription report applies fabric filtering to ACL attribute")
    func subscriptionReportFabricFiltered() async throws {
        let bridge = makeBridgeWithTwoFabricACLs()
        let ctx = makeContext(fabricIndex: fabric1, isFabricFiltered: true)

        // Subscribe to the ACL attribute with fabric filtering
        let subRequest = SubscribeRequest(
            minIntervalFloor: 0,
            maxIntervalCeiling: 60,
            attributeRequests: [
                AttributePath(
                    endpointID: rootEndpoint,
                    clusterID: .accessControl,
                    attributeID: AccessControlCluster.Attribute.acl
                )
            ],
            isFabricFiltered: true
        )

        let subResponses = try await bridge.handleIM(
            opcode: .subscribeRequest,
            payload: subRequest.tlvEncode(),
            sessionID: testSession,
            fabricIndex: fabric1,
            requestContext: ctx
        ).allPairs

        // Verify the initial report in the subscribe response is fabric-filtered
        let initialReport = try ReportData.fromTLV(subResponses[0].1)
        let subResponse = try SubscribeResponse.fromTLV(subResponses[1].1)
        let subscriptionID = subResponse.subscriptionID

        let dataReports = initialReport.attributeReports.compactMap { $0.attributeData }
        #expect(dataReports.count == 1)
        guard case .array(let entries) = dataReports[0].data else {
            Issue.record("Expected array for ACL attribute in subscription initial report")
            return
        }
        // Only fabric1's entry should be present
        #expect(entries.count == 1)

        // Now simulate an attribute change and verify the built report is also fabric-filtered
        let pendingReports = await bridge.pendingReports()
        // Mark the ACL as changed to trigger a report
        await bridge.subscriptions.attributesChanged([
            AttributePath(endpointID: rootEndpoint, clusterID: .accessControl, attributeID: AccessControlCluster.Attribute.acl)
        ])

        let triggeredReports = await bridge.pendingReports()
        #expect(triggeredReports.count >= 1)

        if let pending = triggeredReports.first(where: { $0.subscriptionID == subscriptionID }) {
            let reportChunks = await bridge.buildReport(for: pending)
            #expect(reportChunks != nil)

            if let chunks = reportChunks, let firstChunk = chunks.first {
                let builtReport = firstChunk
                let builtDataReports = builtReport.attributeReports.compactMap { $0.attributeData }
                if !builtDataReports.isEmpty, case .array(let reportedEntries) = builtDataReports[0].data {
                    #expect(reportedEntries.count == 1)
                    let ace = try AccessControlCluster.AccessControlEntry.fromTLVElement(reportedEntries[0])
                    #expect(ace.fabricIndex == fabric1)
                }
            }
        }

        // Clean up
        let _ = pendingReports
    }

    // MARK: - Test 5: Non-fabric-scoped attribute is unaffected by fabric filtering

    @Test("Non-fabric-scoped attribute (OnOff) is unaffected by fabric filtering")
    func nonFabricScopedAttributeUnchanged() async throws {
        let bridge = MatterBridge()
        let light = bridge.addDimmableLight(name: "Test Light")

        // Set OnOff to true
        bridge.store.set(
            endpoint: light.endpointID,
            cluster: .onOff,
            attribute: OnOffCluster.Attribute.onOff,
            value: .bool(true)
        )

        let ctx = makeContext(fabricIndex: fabric1, isFabricFiltered: true)

        let request = ReadRequest(
            attributeRequests: [
                AttributePath(
                    endpointID: light.endpointID,
                    clusterID: .onOff,
                    attributeID: OnOffCluster.Attribute.onOff
                )
            ],
            isFabricFiltered: true
        )

        let responses = try await bridge.handleIM(
            opcode: .readRequest,
            payload: request.tlvEncode(),
            sessionID: testSession,
            fabricIndex: fabric1,
            requestContext: ctx
        ).allPairs

        let report = try ReportData.fromTLV(responses[0].1)
        let dataReports = report.attributeReports.compactMap { $0.attributeData }
        #expect(dataReports.count == 1)
        // OnOff is not fabric-scoped — the value should be the plain bool
        #expect(dataReports[0].data == .bool(true))
    }
}
