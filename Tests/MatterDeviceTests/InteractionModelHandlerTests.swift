// InteractionModelHandlerTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterModel
import MatterProtocol
@testable import MatterDevice

@Suite("Interaction Model Handler")
struct InteractionModelHandlerTests {

    // MARK: - Helpers

    private func makeTestHandler() -> (InteractionModelHandler, AttributeStore, SubscriptionManager) {
        let store = AttributeStore()
        let endpoints = EndpointManager(store: store)
        let subscriptions = SubscriptionManager()

        // Set up aggregator endpoint
        let aggregator = EndpointConfig(
            endpointID: EndpointManager.aggregatorEndpoint,
            deviceTypes: [(.aggregator, 1)],
            clusterHandlers: [
                DescriptorHandler(deviceTypes: [(.aggregator, 1)], serverClusters: [.descriptor])
            ]
        )
        endpoints.addEndpoint(aggregator)

        // Add a bridged dimmable light on endpoint 3
        let light = EndpointConfig(
            endpointID: EndpointID(rawValue: 3),
            deviceTypes: [(.bridgedNode, 1), (.dimmableLight, 1)],
            clusterHandlers: [
                DescriptorHandler(
                    deviceTypes: [(.bridgedNode, 1), (.dimmableLight, 1)],
                    serverClusters: [.onOff, .levelControl, .descriptor]
                ),
                OnOffHandler(),
                LevelControlHandler()
            ]
        )
        endpoints.addEndpoint(light)

        let handler = InteractionModelHandler(endpoints: endpoints, subscriptions: subscriptions, store: store)
        return (handler, store, subscriptions)
    }

    private let testFabric = FabricIndex(rawValue: 1)
    private let testSession: UInt16 = 1
    private let lightEndpoint = EndpointID(rawValue: 3)

    // MARK: - Read Tests

    @Test("Read request returns ReportData with correct attribute value")
    func readRequest() async throws {
        let (handler, _, _) = makeTestHandler()

        let request = ReadRequest(attributeRequests: [
            AttributePath(endpointID: lightEndpoint, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff)
        ])

        let responses = try await handler.handleMessage(
            opcode: .readRequest,
            payload: request.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric
        )

        #expect(responses.count == 1)
        #expect(responses[0].0 == .reportData)

        let report = try ReportData.fromTLV(responses[0].1)
        #expect(report.attributeReports.count == 1)
        #expect(report.attributeReports[0].attributeData?.data == .bool(false))
        #expect(report.suppressResponse == true)
        #expect(report.subscriptionID == nil)
    }

    @Test("Read with wildcard endpoint returns reports from multiple endpoints")
    func readWildcardEndpoint() async throws {
        let (handler, _, _) = makeTestHandler()

        // Wildcard read: endpointID = nil
        let request = ReadRequest(attributeRequests: [
            AttributePath(endpointID: nil, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff)
        ])

        let responses = try await handler.handleMessage(
            opcode: .readRequest,
            payload: request.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric
        )

        #expect(responses.count == 1)

        let report = try ReportData.fromTLV(responses[0].1)
        // Only endpoint 3 has OnOff cluster (aggregator has only Descriptor)
        let dataReports = report.attributeReports.filter { $0.attributeData != nil }
        #expect(dataReports.count == 1)
        #expect(dataReports[0].attributeData?.path.endpointID == lightEndpoint)
    }

    @Test("Read non-existent endpoint returns unsupported endpoint status")
    func readNonExistentEndpoint() async throws {
        let (handler, _, _) = makeTestHandler()

        let request = ReadRequest(attributeRequests: [
            AttributePath(endpointID: EndpointID(rawValue: 99), clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff)
        ])

        let responses = try await handler.handleMessage(
            opcode: .readRequest,
            payload: request.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric
        )

        let report = try ReportData.fromTLV(responses[0].1)
        #expect(report.attributeReports.count == 1)
        #expect(report.attributeReports[0].attributeStatus?.status == .unsupportedEndpoint)
    }

    // MARK: - Write Tests

    @Test("Write request succeeds for writable attribute")
    func writeWritableAttribute() async throws {
        let (handler, store, _) = makeTestHandler()

        let writeData = AttributeDataIB(
            dataVersion: DataVersion(rawValue: 0),
            path: AttributePath(endpointID: lightEndpoint, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff),
            data: .bool(true)
        )
        let request = WriteRequest(writeRequests: [writeData])

        let responses = try await handler.handleMessage(
            opcode: .writeRequest,
            payload: request.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric
        )

        #expect(responses.count == 1)
        #expect(responses[0].0 == .writeResponse)

        let writeResponse = try WriteResponse.fromTLV(responses[0].1)
        #expect(writeResponse.writeResponses.count == 1)
        #expect(writeResponse.writeResponses[0].status == .success)

        // Verify the value was written to the store
        let value = store.get(endpoint: lightEndpoint, cluster: .onOff, attribute: OnOffCluster.Attribute.onOff)
        #expect(value == .bool(true))
    }

    @Test("Write request fails for read-only attribute")
    func writeReadOnlyAttribute() async throws {
        let (handler, _, _) = makeTestHandler()

        let writeData = AttributeDataIB(
            dataVersion: DataVersion(rawValue: 0),
            path: AttributePath(
                endpointID: lightEndpoint,
                clusterID: .descriptor,
                attributeID: DescriptorCluster.Attribute.deviceTypeList
            ),
            data: .array([])
        )
        let request = WriteRequest(writeRequests: [writeData])

        let responses = try await handler.handleMessage(
            opcode: .writeRequest,
            payload: request.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric
        )

        let writeResponse = try WriteResponse.fromTLV(responses[0].1)
        #expect(writeResponse.writeResponses.count == 1)
        #expect(writeResponse.writeResponses[0].status == .unsupportedWrite)
    }

    // MARK: - Invoke Tests

    @Test("Invoke On command changes state and returns success")
    func invokeOnCommand() async throws {
        let (handler, store, _) = makeTestHandler()

        let cmd = CommandDataIB(
            commandPath: CommandPath(endpointID: lightEndpoint, clusterID: .onOff, commandID: OnOffCluster.Command.on)
        )
        let request = InvokeRequest(invokeRequests: [cmd])

        let responses = try await handler.handleMessage(
            opcode: .invokeRequest,
            payload: request.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric
        )

        #expect(responses.count == 1)
        #expect(responses[0].0 == .invokeResponse)

        let invokeResponse = try InvokeResponse.fromTLV(responses[0].1)
        #expect(invokeResponse.invokeResponses.count == 1)
        #expect(invokeResponse.invokeResponses[0].status?.status == .success)

        // Verify state changed
        let value = store.get(endpoint: lightEndpoint, cluster: .onOff, attribute: OnOffCluster.Attribute.onOff)
        #expect(value == .bool(true))
    }

    @Test("Invoke Toggle command flips state")
    func invokeToggleCommand() async throws {
        let (handler, store, _) = makeTestHandler()

        // Initial state: off. Toggle should turn on.
        let cmd = CommandDataIB(
            commandPath: CommandPath(endpointID: lightEndpoint, clusterID: .onOff, commandID: OnOffCluster.Command.toggle)
        )
        let request = InvokeRequest(invokeRequests: [cmd])

        let _ = try await handler.handleMessage(
            opcode: .invokeRequest,
            payload: request.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric
        )

        let value = store.get(endpoint: lightEndpoint, cluster: .onOff, attribute: OnOffCluster.Attribute.onOff)
        #expect(value == .bool(true))

        // Toggle again should turn off
        let _ = try await handler.handleMessage(
            opcode: .invokeRequest,
            payload: request.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric
        )

        let value2 = store.get(endpoint: lightEndpoint, cluster: .onOff, attribute: OnOffCluster.Attribute.onOff)
        #expect(value2 == .bool(false))
    }

    @Test("Invoke MoveToLevel command updates level attribute")
    func invokeMoveToLevel() async throws {
        let (handler, store, _) = makeTestHandler()

        let fields = TLVElement.structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(128)),  // level
        ])
        let cmd = CommandDataIB(
            commandPath: CommandPath(
                endpointID: lightEndpoint,
                clusterID: .levelControl,
                commandID: LevelControlCluster.Command.moveToLevel
            ),
            commandFields: fields
        )
        let request = InvokeRequest(invokeRequests: [cmd])

        let _ = try await handler.handleMessage(
            opcode: .invokeRequest,
            payload: request.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric
        )

        let level = store.get(endpoint: lightEndpoint, cluster: .levelControl, attribute: LevelControlCluster.Attribute.currentLevel)
        #expect(level == .unsignedInt(128))
    }

    // MARK: - Subscribe Tests

    @Test("Subscribe returns initial report and subscribe response")
    func subscribeReturnsTwoMessages() async throws {
        let (handler, _, _) = makeTestHandler()

        let request = SubscribeRequest(
            minIntervalFloor: 1,
            maxIntervalCeiling: 60,
            attributeRequests: [
                AttributePath(endpointID: lightEndpoint, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff)
            ]
        )

        let responses = try await handler.handleMessage(
            opcode: .subscribeRequest,
            payload: request.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric
        )

        // Subscribe produces two responses: ReportData then SubscribeResponse
        #expect(responses.count == 2)
        #expect(responses[0].0 == .reportData)
        #expect(responses[1].0 == .subscribeResponse)
    }

    @Test("Subscribe initial report contains requested attributes with subscriptionID")
    func subscribeInitialReportContainsAttributes() async throws {
        let (handler, _, _) = makeTestHandler()

        let request = SubscribeRequest(
            minIntervalFloor: 1,
            maxIntervalCeiling: 60,
            attributeRequests: [
                AttributePath(endpointID: lightEndpoint, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff)
            ]
        )

        let responses = try await handler.handleMessage(
            opcode: .subscribeRequest,
            payload: request.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric
        )

        // Initial report
        let report = try ReportData.fromTLV(responses[0].1)
        #expect(report.subscriptionID != nil)
        #expect(report.suppressResponse == false)
        #expect(report.attributeReports.count == 1)
        #expect(report.attributeReports[0].attributeData?.data == .bool(false))

        // Subscribe response
        let subResponse = try SubscribeResponse.fromTLV(responses[1].1)
        #expect(subResponse.subscriptionID == report.subscriptionID)
        #expect(subResponse.maxInterval > 0)
    }

    @Test("Write notifies subscription manager of changes")
    func writeNotifiesSubscriptions() async throws {
        let (handler, _, subscriptions) = makeTestHandler()

        // First, create a subscription for the OnOff attribute
        let subRequest = SubscribeRequest(
            minIntervalFloor: 0,
            maxIntervalCeiling: 60,
            attributeRequests: [
                AttributePath(endpointID: lightEndpoint, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff)
            ]
        )

        let _ = try await handler.handleMessage(
            opcode: .subscribeRequest,
            payload: subRequest.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric
        )

        // Now write to the OnOff attribute through the handler
        let writeData = AttributeDataIB(
            dataVersion: DataVersion(rawValue: 0),
            path: AttributePath(endpointID: lightEndpoint, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff),
            data: .bool(true)
        )
        let writeRequest = WriteRequest(writeRequests: [writeData])

        let _ = try await handler.handleMessage(
            opcode: .writeRequest,
            payload: writeRequest.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric
        )

        // Subscription should have a pending report
        let pending = await subscriptions.pendingReports()
        #expect(pending.count == 1)
        #expect(pending[0].reason == .attributeChanged)
    }

    @Test("Invoke command notifies subscription manager of changes")
    func invokeNotifiesSubscriptions() async throws {
        let (handler, _, subscriptions) = makeTestHandler()

        // Create a subscription for OnOff attribute
        let subRequest = SubscribeRequest(
            minIntervalFloor: 0,
            maxIntervalCeiling: 60,
            attributeRequests: [
                AttributePath(endpointID: lightEndpoint, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff)
            ]
        )

        let _ = try await handler.handleMessage(
            opcode: .subscribeRequest,
            payload: subRequest.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric
        )

        // Invoke On command
        let cmd = CommandDataIB(
            commandPath: CommandPath(endpointID: lightEndpoint, clusterID: .onOff, commandID: OnOffCluster.Command.on)
        )
        let invokeRequest = InvokeRequest(invokeRequests: [cmd])

        let _ = try await handler.handleMessage(
            opcode: .invokeRequest,
            payload: invokeRequest.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric
        )

        // Subscription should have a pending report
        let pending = await subscriptions.pendingReports()
        #expect(pending.count == 1)
    }

    // MARK: - Status Response

    @Test("StatusResponse returns empty response array")
    func statusResponseReturnsEmpty() async throws {
        let (handler, _, _) = makeTestHandler()

        let statusMsg = IMStatusResponse.success

        let responses = try await handler.handleMessage(
            opcode: .statusResponse,
            payload: statusMsg.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric
        )

        #expect(responses.isEmpty)
    }

    // MARK: - ACL Enforcement

    /// Create a CASE session context with a single admin ACE for the given subject.
    private func makeAdminContext(subjectNodeID: UInt64 = 42) -> IMRequestContext {
        IMRequestContext(
            checkerContext: ACLChecker.RequestContext(
                isPASE: false,
                subjectNodeID: subjectNodeID,
                fabricIndex: testFabric
            ),
            acls: [
                AccessControlCluster.AccessControlEntry(
                    privilege: .administer,
                    authMode: .case,
                    subjects: [subjectNodeID],
                    fabricIndex: testFabric
                )
            ]
        )
    }

    /// Create a CASE session context with a view-only ACE.
    private func makeViewOnlyContext(subjectNodeID: UInt64 = 42) -> IMRequestContext {
        IMRequestContext(
            checkerContext: ACLChecker.RequestContext(
                isPASE: false,
                subjectNodeID: subjectNodeID,
                fabricIndex: testFabric
            ),
            acls: [
                AccessControlCluster.AccessControlEntry(
                    privilege: .view,
                    authMode: .case,
                    subjects: [subjectNodeID],
                    fabricIndex: testFabric
                )
            ]
        )
    }

    /// Create a CASE session context with no ACLs (completely denied).
    private func makeDeniedContext(subjectNodeID: UInt64 = 42) -> IMRequestContext {
        IMRequestContext(
            checkerContext: ACLChecker.RequestContext(
                isPASE: false,
                subjectNodeID: subjectNodeID,
                fabricIndex: testFabric
            ),
            acls: []
        )
    }

    /// Create a PASE session context (implicit admin, bypass ACLs).
    private func makePASEContext() -> IMRequestContext {
        IMRequestContext(
            checkerContext: ACLChecker.RequestContext(
                isPASE: true,
                subjectNodeID: 0,
                fabricIndex: testFabric
            ),
            acls: []
        )
    }

    @Test("Read allowed with proper ACL")
    func readAllowedWithACL() async throws {
        let (handler, _, _) = makeTestHandler()
        let ctx = makeAdminContext()

        let request = ReadRequest(attributeRequests: [
            AttributePath(endpointID: lightEndpoint, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff)
        ])

        let responses = try await handler.handleMessage(
            opcode: .readRequest,
            payload: request.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric,
            requestContext: ctx
        )

        let report = try ReportData.fromTLV(responses[0].1)
        #expect(report.attributeReports.count == 1)
        #expect(report.attributeReports[0].attributeData?.data == .bool(false))
    }

    @Test("Read denied returns unsupportedAccess for targeted path")
    func readDeniedTargeted() async throws {
        let (handler, _, _) = makeTestHandler()
        let ctx = makeDeniedContext()

        let request = ReadRequest(attributeRequests: [
            AttributePath(endpointID: lightEndpoint, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff)
        ])

        let responses = try await handler.handleMessage(
            opcode: .readRequest,
            payload: request.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric,
            requestContext: ctx
        )

        let report = try ReportData.fromTLV(responses[0].1)
        #expect(report.attributeReports.count == 1)
        #expect(report.attributeReports[0].attributeStatus?.status == .unsupportedAccess)
    }

    @Test("Wildcard read silently skips denied paths")
    func wildcardReadSkipsDenied() async throws {
        let (handler, _, _) = makeTestHandler()
        let ctx = makeDeniedContext()

        // Wildcard read: endpointID = nil
        let request = ReadRequest(attributeRequests: [
            AttributePath(endpointID: nil, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff)
        ])

        let responses = try await handler.handleMessage(
            opcode: .readRequest,
            payload: request.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric,
            requestContext: ctx
        )

        let report = try ReportData.fromTLV(responses[0].1)
        // All reports silently dropped — no error statuses either
        let dataReports = report.attributeReports.filter { $0.attributeData != nil }
        let statusReports = report.attributeReports.filter { $0.attributeStatus?.status == .unsupportedAccess }
        #expect(dataReports.isEmpty)
        #expect(statusReports.isEmpty)
    }

    @Test("Write denied returns unsupportedAccess")
    func writeDenied() async throws {
        let (handler, _, _) = makeTestHandler()
        let ctx = makeViewOnlyContext()  // View privilege can't write

        let writeData = AttributeDataIB(
            dataVersion: DataVersion(rawValue: 0),
            path: AttributePath(endpointID: lightEndpoint, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff),
            data: .bool(true)
        )
        let request = WriteRequest(writeRequests: [writeData])

        let responses = try await handler.handleMessage(
            opcode: .writeRequest,
            payload: request.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric,
            requestContext: ctx
        )

        let writeResponse = try WriteResponse.fromTLV(responses[0].1)
        #expect(writeResponse.writeResponses.count == 1)
        #expect(writeResponse.writeResponses[0].status == .unsupportedAccess)
    }

    @Test("Write allowed with Operate privilege")
    func writeAllowedWithOperate() async throws {
        let (handler, store, _) = makeTestHandler()
        let ctx = IMRequestContext(
            checkerContext: ACLChecker.RequestContext(
                isPASE: false,
                subjectNodeID: 42,
                fabricIndex: testFabric
            ),
            acls: [
                AccessControlCluster.AccessControlEntry(
                    privilege: .operate,
                    authMode: .case,
                    subjects: [42],
                    fabricIndex: testFabric
                )
            ]
        )

        let writeData = AttributeDataIB(
            dataVersion: DataVersion(rawValue: 0),
            path: AttributePath(endpointID: lightEndpoint, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff),
            data: .bool(true)
        )
        let request = WriteRequest(writeRequests: [writeData])

        let responses = try await handler.handleMessage(
            opcode: .writeRequest,
            payload: request.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric,
            requestContext: ctx
        )

        let writeResponse = try WriteResponse.fromTLV(responses[0].1)
        #expect(writeResponse.writeResponses.count == 1)
        #expect(writeResponse.writeResponses[0].status == .success)

        let value = store.get(endpoint: lightEndpoint, cluster: .onOff, attribute: OnOffCluster.Attribute.onOff)
        #expect(value == .bool(true))
    }

    @Test("Invoke denied returns unsupportedAccess")
    func invokeDenied() async throws {
        let (handler, _, _) = makeTestHandler()
        let ctx = makeViewOnlyContext()  // View privilege can't invoke

        let cmd = CommandDataIB(
            commandPath: CommandPath(endpointID: lightEndpoint, clusterID: .onOff, commandID: OnOffCluster.Command.on)
        )
        let request = InvokeRequest(invokeRequests: [cmd])

        let responses = try await handler.handleMessage(
            opcode: .invokeRequest,
            payload: request.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric,
            requestContext: ctx
        )

        let invokeResponse = try InvokeResponse.fromTLV(responses[0].1)
        #expect(invokeResponse.invokeResponses.count == 1)
        #expect(invokeResponse.invokeResponses[0].status?.status == .unsupportedAccess)
    }

    @Test("PASE context bypasses all ACL checks")
    func paseBypassIM() async throws {
        let (handler, store, _) = makeTestHandler()
        let ctx = makePASEContext()

        // Should be able to write even with no ACLs
        let writeData = AttributeDataIB(
            dataVersion: DataVersion(rawValue: 0),
            path: AttributePath(endpointID: lightEndpoint, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff),
            data: .bool(true)
        )
        let request = WriteRequest(writeRequests: [writeData])

        let responses = try await handler.handleMessage(
            opcode: .writeRequest,
            payload: request.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric,
            requestContext: ctx
        )

        let writeResponse = try WriteResponse.fromTLV(responses[0].1)
        #expect(writeResponse.writeResponses[0].status == .success)

        let value = store.get(endpoint: lightEndpoint, cluster: .onOff, attribute: OnOffCluster.Attribute.onOff)
        #expect(value == .bool(true))
    }

    @Test("No request context means no enforcement (backward compat)")
    func noContextNoEnforcement() async throws {
        let (handler, store, _) = makeTestHandler()

        // Write without any ACL context — should succeed
        let writeData = AttributeDataIB(
            dataVersion: DataVersion(rawValue: 0),
            path: AttributePath(endpointID: lightEndpoint, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff),
            data: .bool(true)
        )
        let request = WriteRequest(writeRequests: [writeData])

        let responses = try await handler.handleMessage(
            opcode: .writeRequest,
            payload: request.tlvEncode(),
            sessionID: testSession,
            fabricIndex: testFabric
            // requestContext: nil (default)
        )

        let writeResponse = try WriteResponse.fromTLV(responses[0].1)
        #expect(writeResponse.writeResponses[0].status == .success)

        let value = store.get(endpoint: lightEndpoint, cluster: .onOff, attribute: OnOffCluster.Attribute.onOff)
        #expect(value == .bool(true))
    }

    // MARK: - Unknown Opcode

    @Test("Unknown opcode returns invalid action status")
    func unknownOpcodeReturnsError() async throws {
        let (handler, _, _) = makeTestHandler()

        // timedRequest is not handled
        let responses = try await handler.handleMessage(
            opcode: .timedRequest,
            payload: Data(),
            sessionID: testSession,
            fabricIndex: testFabric
        )

        #expect(responses.count == 1)
        #expect(responses[0].0 == .statusResponse)

        let status = try IMStatusResponse.fromTLV(responses[0].1)
        #expect(status.status == StatusIB.invalidAction.status)
    }
}
