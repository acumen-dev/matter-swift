// IMClientTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
@testable import MatterProtocol

@Suite("IMClient invoke responses")
struct IMClientTests {

    private let path1 = CommandPath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0006), commandID: CommandID(rawValue: 0x02))
    private let path2 = CommandPath(endpointID: EndpointID(rawValue: 2), clusterID: ClusterID(rawValue: 0x0006), commandID: CommandID(rawValue: 0x02))

    private func encode(_ responses: [InvokeResponseIB]) -> Data {
        InvokeResponse(invokeResponses: responses).tlvEncode()
    }

    @Test("Every InvokeResponseIB is returned, in order")
    func allResponsesReturned() throws {
        let data = encode([
            InvokeResponseIB(status: CommandStatusIB(commandPath: path1, status: StatusIB(status: 0))),
            InvokeResponseIB(command: CommandDataIB(commandPath: path2, commandFields: .structure([]))),
        ])
        let responses = try IMClient.parseInvokeResponses(data)
        #expect(responses.count == 2)
        #expect(responses[0].status?.commandPath == path1)
        #expect(responses[1].command?.commandPath == path2)
    }

    @Test("The convenience parser throws when a later response failed, not only the first")
    func laterFailureThrows() {
        let data = encode([
            InvokeResponseIB(status: CommandStatusIB(commandPath: path1, status: StatusIB(status: 0))),
            InvokeResponseIB(status: CommandStatusIB(commandPath: path2, status: StatusIB(status: 0x85))),
        ])
        #expect(throws: IMError.commandStatus(path: path2, status: 0x85, clusterStatus: nil)) { try IMClient.parseInvokeResponse(data) }
    }

    @Test("SUCCESS carrying a cluster status is not an error")
    func successWithClusterStatus() throws {
        let data = encode([
            InvokeResponseIB(status: CommandStatusIB(commandPath: path1, status: StatusIB(status: 0, clusterStatus: 3))),
        ])
        #expect(try IMClient.parseInvokeResponse(data) == nil)
    }

    @Test("All-success responses return nil")
    func allSuccessReturnsNil() throws {
        let data = encode([
            InvokeResponseIB(status: CommandStatusIB(commandPath: path1, status: StatusIB(status: 0))),
            InvokeResponseIB(status: CommandStatusIB(commandPath: path2, status: StatusIB(status: 0))),
        ])
        #expect(try IMClient.parseInvokeResponse(data) == nil)
    }

    @Test("The convenience parser returns the first command's fields")
    func firstCommandFields() throws {
        let fields = TLVElement.structure([.init(tag: .contextSpecific(0), value: .unsignedInt(7))])
        let data = encode([
            InvokeResponseIB(status: CommandStatusIB(commandPath: path1, status: StatusIB(status: 0))),
            InvokeResponseIB(command: CommandDataIB(commandPath: path2, commandFields: fields)),
        ])
        #expect(try IMClient.parseInvokeResponse(data) == fields)
    }

    @Test("A TimedRequest carries the timeout in milliseconds")
    func timedRequestTimeout() throws {
        let data = IMClient.timedRequest(timeout: .milliseconds(1500))
        #expect(try TimedRequest.fromTLV(data).timeoutMs == 1500)
    }
}

@Suite("IMClient write responses")
struct IMClientWriteResponseTests {

    private let path1 = AttributePath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0006), attributeID: AttributeID(rawValue: 0x0000))
    private let path2 = AttributePath(endpointID: EndpointID(rawValue: 2), clusterID: ClusterID(rawValue: 0x0006), attributeID: AttributeID(rawValue: 0x0000))

    private func encode(_ statuses: [StatusIB]) -> Data {
        let paths = [path1, path2]
        return WriteResponse(writeResponses: statuses.enumerated().map {
            AttributeStatusIB(path: paths[$0.offset], status: $0.element)
        }).tlvEncode()
    }

    @Test("SUCCESS carrying a cluster status is success")
    func successWithClusterStatusIsSuccess() throws {
        let data = encode([StatusIB(status: 0, clusterStatus: 3)])
        #expect(try IMClient.parseWriteResponse(data) == true)
    }

    @Test("A failure alongside a SUCCESS is reported as failure")
    func mixedSuccessAndFailureIsFailure() throws {
        let data = encode([StatusIB(status: 0), StatusIB(status: 0x87)])
        #expect(try IMClient.parseWriteResponse(data) == false)
    }

    @Test("firstWriteFailure returns the first non-success status, nil when all succeed")
    func firstWriteFailure() throws {
        #expect(try IMClient.firstWriteFailure(encode([StatusIB(status: 0), StatusIB(status: 0, clusterStatus: 3)])) == nil)
        #expect(try IMClient.firstWriteFailure(encode([StatusIB(status: 0), StatusIB(status: 0x87)])) == 0x87)
        #expect(try IMClient.firstWriteFailure(encode([StatusIB(status: 0x88), StatusIB(status: 0x87)])) == 0x88)
    }

    // A real device refuses a write conditional on a stale data version
    // (connectedhomeip: "Write Version mismatch" → DataVersionMismatch), so
    // writes carry no DataVersion unless the caller asks for one.
    @Test("A write request is unconditional unless a data version is given")
    func writeIsUnconditionalByDefault() throws {
        let plain = try WriteRequest.fromTLV(IMClient.writeAttributeRequest(
            endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0006),
            attributeID: AttributeID(rawValue: 0x0000), value: .bool(true)
        ))
        #expect(plain.writeRequests.first?.dataVersion == nil)

        let conditional = try WriteRequest.fromTLV(IMClient.writeAttributeRequest(
            endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0006),
            attributeID: AttributeID(rawValue: 0x0000), dataVersion: DataVersion(rawValue: 7), value: .bool(true)
        ))
        #expect(conditional.writeRequests.first?.dataVersion == DataVersion(rawValue: 7))
    }
}

@Suite("IMClient typed status errors")
struct IMClientStatusErrorTests {

    private let attr = AttributePath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0006), attributeID: AttributeID(rawValue: 0x00FF))
    private let cmd = CommandPath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0006), commandID: CommandID(rawValue: 0x02))

    private func report(_ status: StatusIB) -> Data {
        ReportData(attributeReports: [AttributeReportIB(attributeStatus: AttributeStatusIB(path: attr, status: status))]).tlvEncode()
    }

    @Test("A read answered with UnsupportedAttribute throws a typed attributeStatus")
    func unsupportedAttribute() {
        #expect(throws: IMError.attributeStatus(path: attr, status: 0x86, clusterStatus: nil)) {
            try IMClient.parseReadResponse(report(StatusIB(status: 0x86)))
        }
    }

    @Test("A cluster-specific status is carried")
    func clusterStatusCarried() {
        #expect(throws: IMError.attributeStatus(path: attr, status: 0x01, clusterStatus: 0x42)) {
            try IMClient.parseReadResponse(report(StatusIB(status: 0x01, clusterStatus: 0x42)))
        }
    }

    @Test("A failed command throws a typed commandStatus")
    func commandStatus() {
        let data = InvokeResponse(invokeResponses: [
            InvokeResponseIB(status: CommandStatusIB(commandPath: cmd, status: StatusIB(status: 0xC6, clusterStatus: 7)))
        ]).tlvEncode()
        #expect(throws: IMError.commandStatus(path: cmd, status: 0xC6, clusterStatus: 7)) {
            try IMClient.parseInvokeResponse(data)
        }
    }

    @Test("Descriptions name the status, cluster status and path")
    func descriptions() {
        let a = IMError.attributeStatus(path: attr, status: 0x86, clusterStatus: nil)
        #expect(a.description == "Attribute error: status 0x86 (unsupportedAttribute) at endpoint 0x1 cluster 0x6 attribute 0xFF")
        #expect(a.statusCode == .unsupportedAttribute)
        let c = IMError.commandStatus(path: cmd, status: 0xC6, clusterStatus: 7)
        #expect(c.description == "Command error: status 0xC6 (needsTimedInteraction), cluster status 0x7 at endpoint 0x1 cluster 0x6 command 0x2")
    }
}
