// IMMessageTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
@testable import MatterProtocol
@testable import MatterTypes

@Suite("Interaction Model Paths")
struct IMPathTests {

    @Test("AttributePath TLV round-trip")
    func attributePathRoundTrip() throws {
        let path = AttributePath(
            endpointID: EndpointID(rawValue: 1),
            clusterID: ClusterID(rawValue: 0x0006),
            attributeID: AttributeID(rawValue: 0)
        )
        let element = path.toTLVElement()
        let decoded = try AttributePath.fromTLVElement(element)
        #expect(decoded == path)
    }

    @Test("AttributePath wildcard round-trip")
    func attributePathWildcard() throws {
        let path = AttributePath(clusterID: ClusterID(rawValue: 0x0006))
        let element = path.toTLVElement()
        let decoded = try AttributePath.fromTLVElement(element)
        #expect(decoded.endpointID == nil)
        #expect(decoded.clusterID == ClusterID(rawValue: 0x0006))
        #expect(decoded.attributeID == nil)
    }

    @Test("AttributePath with all fields")
    func attributePathAllFields() throws {
        let path = AttributePath(
            endpointID: EndpointID(rawValue: 2),
            clusterID: ClusterID(rawValue: 0x0008),
            attributeID: AttributeID(rawValue: 0),
            nodeID: NodeID(rawValue: 0x1234),
            listIndex: .index(5)
        )
        let element = path.toTLVElement()
        let decoded = try AttributePath.fromTLVElement(element)
        #expect(decoded == path)
        #expect(decoded.nodeID == NodeID(rawValue: 0x1234))
        #expect(decoded.listIndex == .index(5))
    }

    @Test("CommandPath TLV round-trip")
    func commandPathRoundTrip() throws {
        let path = CommandPath(
            endpointID: EndpointID(rawValue: 1),
            clusterID: ClusterID(rawValue: 0x0006),
            commandID: CommandID(rawValue: 0x02)
        )
        let element = path.toTLVElement()
        let decoded = try CommandPath.fromTLVElement(element)
        #expect(decoded == path)
    }

    @Test("EventPath TLV round-trip")
    func eventPathRoundTrip() throws {
        let path = EventPath(
            endpointID: EndpointID(rawValue: 1),
            clusterID: ClusterID(rawValue: 0x0006),
            eventID: EventID(rawValue: 0),
            isUrgent: true
        )
        let element = path.toTLVElement()
        let decoded = try EventPath.fromTLVElement(element)
        #expect(decoded == path)
        #expect(decoded.isUrgent == true)
    }

    @Test("CommandPath rejects non-list element")
    func commandPathRejectsNonList() throws {
        #expect(throws: IMError.self) {
            _ = try CommandPath.fromTLVElement(.unsignedInt(42))
        }
    }
}

@Suite("Interaction Model Messages")
struct IMMessageTests {

    // MARK: - Read Request

    @Test("ReadRequest TLV round-trip")
    func readRequestRoundTrip() throws {
        let req = ReadRequest(
            attributeRequests: [
                AttributePath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0006), attributeID: AttributeID(rawValue: 0)),
                AttributePath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0008), attributeID: AttributeID(rawValue: 0))
            ],
            isFabricFiltered: true
        )
        let data = req.tlvEncode()
        let decoded = try ReadRequest.fromTLV(data)
        #expect(decoded == req)
        #expect(decoded.attributeRequests.count == 2)
    }

    @Test("ReadRequest with events")
    func readRequestWithEvents() throws {
        let req = ReadRequest(
            eventRequests: [
                EventPath(endpointID: EndpointID(rawValue: 0), clusterID: ClusterID(rawValue: 0x0028))
            ],
            isFabricFiltered: false
        )
        let data = req.tlvEncode()
        let decoded = try ReadRequest.fromTLV(data)
        #expect(decoded.eventRequests.count == 1)
        #expect(decoded.isFabricFiltered == false)
    }

    @Test("ReadRequest empty")
    func readRequestEmpty() throws {
        let req = ReadRequest()
        let data = req.tlvEncode()
        let decoded = try ReadRequest.fromTLV(data)
        #expect(decoded.attributeRequests.isEmpty)
        #expect(decoded.eventRequests.isEmpty)
        #expect(decoded.isFabricFiltered == true)
    }

    // MARK: - Report Data

    @Test("ReportData with attribute data round-trip")
    func reportDataRoundTrip() throws {
        let report = ReportData(
            attributeReports: [
                AttributeReportIB(attributeData: AttributeDataIB(
                    dataVersion: DataVersion(rawValue: 1),
                    path: AttributePath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0006), attributeID: AttributeID(rawValue: 0)),
                    data: .bool(true)
                ))
            ]
        )
        let data = report.tlvEncode()
        let decoded = try ReportData.fromTLV(data)
        #expect(decoded.attributeReports.count == 1)
        #expect(decoded.attributeReports[0].attributeData?.data == .bool(true))
        #expect(decoded.moreChunkedMessages == false)
    }

    @Test("ReportData with attribute status")
    func reportDataWithStatus() throws {
        let report = ReportData(
            attributeReports: [
                AttributeReportIB(attributeStatus: AttributeStatusIB(
                    path: AttributePath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0006), attributeID: AttributeID(rawValue: 99)),
                    status: .unsupportedAttribute
                ))
            ]
        )
        let data = report.tlvEncode()
        let decoded = try ReportData.fromTLV(data)
        #expect(decoded.attributeReports[0].attributeStatus?.status == .unsupportedAttribute)
    }

    @Test("ReportData with subscription ID and chunking")
    func reportDataChunked() throws {
        let report = ReportData(
            subscriptionID: SubscriptionID(rawValue: 42),
            attributeReports: [],
            moreChunkedMessages: true,
            suppressResponse: true
        )
        let data = report.tlvEncode()
        let decoded = try ReportData.fromTLV(data)
        #expect(decoded.subscriptionID == SubscriptionID(rawValue: 42))
        #expect(decoded.moreChunkedMessages == true)
        #expect(decoded.suppressResponse == true)
    }

    // MARK: - Write Request / Response

    @Test("WriteRequest TLV round-trip")
    func writeRequestRoundTrip() throws {
        let req = WriteRequest(
            timedRequest: false,
            writeRequests: [
                AttributeDataIB(
                    dataVersion: DataVersion(rawValue: 5),
                    path: AttributePath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0006), attributeID: AttributeID(rawValue: 0)),
                    data: .bool(true)
                )
            ]
        )
        let data = req.tlvEncode()
        let decoded = try WriteRequest.fromTLV(data)
        #expect(decoded == req)
        #expect(decoded.writeRequests.count == 1)
    }

    @Test("WriteResponse TLV round-trip")
    func writeResponseRoundTrip() throws {
        let resp = WriteResponse(writeResponses: [
            AttributeStatusIB(
                path: AttributePath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0006), attributeID: AttributeID(rawValue: 0)),
                status: .success
            )
        ])
        let data = resp.tlvEncode()
        let decoded = try WriteResponse.fromTLV(data)
        #expect(decoded.writeResponses.count == 1)
        #expect(decoded.writeResponses[0].status == .success)
    }

    // MARK: - Invoke Request / Response

    @Test("InvokeRequest TLV round-trip")
    func invokeRequestRoundTrip() throws {
        let req = InvokeRequest(invokeRequests: [
            CommandDataIB(
                commandPath: CommandPath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0006), commandID: CommandID(rawValue: 0x02)),
                commandFields: .structure([
                    .init(tag: .contextSpecific(0), value: .unsignedInt(100))
                ])
            )
        ])
        let data = req.tlvEncode()
        let decoded = try InvokeRequest.fromTLV(data)
        #expect(decoded.invokeRequests.count == 1)
        #expect(decoded.invokeRequests[0].commandPath.commandID == CommandID(rawValue: 0x02))
        #expect(decoded.invokeRequests[0].commandFields != nil)
    }

    @Test("InvokeRequest without command fields")
    func invokeRequestNoFields() throws {
        let req = InvokeRequest(invokeRequests: [
            CommandDataIB(commandPath: CommandPath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0006), commandID: CommandID(rawValue: 0x00)))
        ])
        let data = req.tlvEncode()
        let decoded = try InvokeRequest.fromTLV(data)
        #expect(decoded.invokeRequests[0].commandFields == nil)
    }

    @Test("InvokeResponse with command data")
    func invokeResponseWithCommand() throws {
        let resp = InvokeResponse(invokeResponses: [
            InvokeResponseIB(command: CommandDataIB(
                commandPath: CommandPath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0006), commandID: CommandID(rawValue: 0x01)),
                commandFields: .structure([.init(tag: .contextSpecific(0), value: .bool(true))])
            ))
        ])
        let data = resp.tlvEncode()
        let decoded = try InvokeResponse.fromTLV(data)
        #expect(decoded.invokeResponses.count == 1)
        #expect(decoded.invokeResponses[0].command != nil)
        #expect(decoded.invokeResponses[0].status == nil)
    }

    @Test("InvokeResponse with status")
    func invokeResponseWithStatus() throws {
        let resp = InvokeResponse(invokeResponses: [
            InvokeResponseIB(status: CommandStatusIB(
                commandPath: CommandPath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0006), commandID: CommandID(rawValue: 0x02)),
                status: .success
            ))
        ])
        let data = resp.tlvEncode()
        let decoded = try InvokeResponse.fromTLV(data)
        #expect(decoded.invokeResponses[0].status?.status == .success)
        #expect(decoded.invokeResponses[0].command == nil)
    }

    // MARK: - Status Response

    @Test("IMStatusResponse TLV round-trip")
    func statusResponseRoundTrip() throws {
        let resp = IMStatusResponse(status: 0x00)
        let data = resp.tlvEncode()
        let decoded = try IMStatusResponse.fromTLV(data)
        #expect(decoded.status == 0x00)
    }

    @Test("StatusIB with cluster status")
    func statusIBClusterStatus() throws {
        let status = StatusIB(status: 0x01, clusterStatus: 0x42)
        let element = status.toTLVElement()
        let decoded = try StatusIB.fromTLVElement(element)
        #expect(decoded.status == 0x01)
        #expect(decoded.clusterStatus == 0x42)
    }

    // MARK: - Subscribe Request / Response

    @Test("SubscribeRequest TLV round-trip")
    func subscribeRequestRoundTrip() throws {
        let req = SubscribeRequest(
            keepSubscriptions: true,
            minIntervalFloor: 0,
            maxIntervalCeiling: 60,
            attributeRequests: [
                AttributePath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0006), attributeID: AttributeID(rawValue: 0)),
                AttributePath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0008), attributeID: AttributeID(rawValue: 0))
            ],
            eventRequests: [
                EventPath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0006), eventID: EventID(rawValue: 0))
            ],
            isFabricFiltered: false
        )
        let data = req.tlvEncode()
        let decoded = try SubscribeRequest.fromTLV(data)
        #expect(decoded == req)
        #expect(decoded.keepSubscriptions == true)
        #expect(decoded.minIntervalFloor == 0)
        #expect(decoded.maxIntervalCeiling == 60)
        #expect(decoded.attributeRequests.count == 2)
        #expect(decoded.eventRequests.count == 1)
        #expect(decoded.isFabricFiltered == false)
    }

    @Test("SubscribeResponse TLV round-trip")
    func subscribeResponseRoundTrip() throws {
        let resp = SubscribeResponse(
            subscriptionID: SubscriptionID(rawValue: 99),
            maxInterval: 120
        )
        let data = resp.tlvEncode()
        let decoded = try SubscribeResponse.fromTLV(data)
        #expect(decoded == resp)
        #expect(decoded.subscriptionID == SubscriptionID(rawValue: 99))
        #expect(decoded.maxInterval == 120)
    }

    @Test("SubscribeRequest with minimal fields")
    func subscribeRequestMinimal() throws {
        let req = SubscribeRequest(
            keepSubscriptions: false,
            minIntervalFloor: 10,
            maxIntervalCeiling: 300,
            attributeRequests: [
                AttributePath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0006), attributeID: AttributeID(rawValue: 0))
            ]
        )
        let data = req.tlvEncode()
        let decoded = try SubscribeRequest.fromTLV(data)
        #expect(decoded == req)
        #expect(decoded.keepSubscriptions == false)
        #expect(decoded.eventRequests.isEmpty)
        #expect(decoded.isFabricFiltered == true)
    }
}
