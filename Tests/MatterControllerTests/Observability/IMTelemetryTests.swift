// IMTelemetryTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Tracing
import InMemoryTracing
import MatterTypes
import MatterProtocol
import MatterTestSupport
@testable import MatterController

@Suite("Controller IM telemetry", .timeLimit(.minutes(1)))
struct IMTelemetryTests {

    private let endpoint = EndpointID(rawValue: 1)
    private let windowCovering = ClusterID(rawValue: 0x0102)
    private let goToLift = CommandID(rawValue: 0x05)
    private let liftFields: TLVElement = .structure([.init(tag: .contextSpecific(0), value: .unsignedInt(5000))])

    /// A value no log line or span may show for a sensitive cluster, and its renderings.
    private static let secretValue: UInt64 = 0xDEADBEEF
    private static let secretRenderings = ["3735928559", "DEADBEEF", "deadbeef"]

    private func successResponse(cluster: ClusterID? = nil, command: CommandID? = nil) -> Data {
        InvokeResponse(invokeResponses: [InvokeResponseIB(status: CommandStatusIB(
            commandPath: CommandPath(endpointID: endpoint, clusterID: cluster ?? windowCovering, commandID: command ?? goToLift),
            status: StatusIB(status: 0)
        ))]).tlvEncode()
    }

    private func expectNoIMMetrics(_ telemetry: TestTelemetry, kind: IMRequestKind) {
        for outcome in IMRequestOutcome.allCases {
            #expect(telemetry.counter("matter_im_requests_total", [("kind", kind.rawValue), ("outcome", outcome.rawValue)]) == 0,
                    "no \(outcome.rawValue) outcome is counted")
        }
        #expect(telemetry.timerValues("matter_im_request_duration", [("kind", kind.rawValue)]).isEmpty)
    }

    @Test("An IM status response appears on the debug response line and on the invoke span")
    func statusOnLineAndSpan() async throws {
        let rig = try await makeControllerRig()
        var peer = TestPeer(link: rig.link)
        var seen = Set<UInt32>()
        let fields = liftFields, endpoint = endpoint, cluster = windowCovering, command = goToLift
        let call = Task {
            try await rig.controller.invokeCommand(nodeID: rig.node, endpointID: endpoint, clusterID: cluster, commandID: command, commandFields: fields)
        }
        let request = try await nextNewFrame(&peer, session: rig.peerSession, seen: &seen)
        #expect(request.exchangeHeader.protocolOpcode == InteractionModelOpcode.invokeRequest.rawValue)
        try await peer.send(ScriptedPeer.securedReply(
            to: request, session: rig.peerSession, protocolID: .interactionModel,
            opcode: InteractionModelOpcode.statusResponse.rawValue, payload: IMStatusResponse(status: 0x7E).tlvEncode()
        ))
        await #expect(throws: ControllerError.imStatus(0x7E)) { _ = try await call.value }

        let requestLine = try #require(rig.telemetry.logs.entries.first { $0.message.hasPrefix("IM invoke request") })
        #expect(requestLine.level == .debug)
        #expect(requestLine.subsystem == "im")
        #expect(requestLine.label == "test.controller")
        #expect(requestLine.metadata[MatterLogKey.node] == "0x42")
        #expect(requestLine.metadata[MatterLogKey.endpoint] == "0x1")
        #expect(requestLine.metadata[MatterLogKey.cluster] == "0x102")
        #expect(requestLine.metadata[MatterLogKey.command] == "0x5")
        #expect(requestLine.message.contains("5000"), "command fields are logged as decoded TLV")

        let responseLine = try #require(rig.telemetry.logs.entries.first { $0.message.hasPrefix("IM invoke response") })
        #expect(responseLine.message.hasPrefix("IM invoke response: im_status in "))
        #expect(responseLine.metadata[MatterLogKey.imStatus] == "0x7E")
        #expect(responseLine.metadata[MatterLogKey.latencyMs] != nil)

        let span = try #require(rig.telemetry.finishedSpans(named: "matter.im.invoke").first)
        #expect(span.attributes.get(MatterLogKey.imStatus) == .string("0x7E"))
        #expect(span.attributes.get(MatterLogKey.node) == .string("0x42"))
        #expect(span.attributes.get(MatterLogKey.cluster) == .string("0x102"))
        #expect(span.attributes.get(MatterLogKey.command) == .string("0x5"))
        #expect(span.status?.code == .error)
        let exchangeSpan = try #require(rig.telemetry.finishedSpans(named: "matter.exchange").first)
        #expect(exchangeSpan.parentSpanID == span.spanID)
        #expect(rig.telemetry.counter("matter_im_requests_total", [("kind", "invoke"), ("outcome", "im_status")]) == 1)
        #expect(rig.telemetry.timerValues("matter_im_request_duration", [("kind", "invoke")]).count == 1)
        await rig.controller.stop()
    }

    @Test("A parent ServiceContext parents the invoke span; success is logged, counted and timed")
    func parentContext() async throws {
        let rig = try await makeControllerRig()
        var peer = TestPeer(link: rig.link)
        var seen = Set<UInt32>()
        let parent = rig.telemetry.tracer.startSpan("acumen.matter.invoke")
        let parentContext = parent.context
        let endpoint = endpoint, cluster = windowCovering, command = goToLift
        let call = Task {
            try await rig.controller.invokeCommand(nodeID: rig.node, endpointID: endpoint, clusterID: cluster, commandID: command, context: parentContext)
        }
        let request = try await nextNewFrame(&peer, session: rig.peerSession, seen: &seen)
        try await peer.send(ScriptedPeer.securedReply(
            to: request, session: rig.peerSession, protocolID: .interactionModel,
            opcode: InteractionModelOpcode.invokeResponse.rawValue, payload: successResponse()
        ))
        #expect(try await call.value == nil)
        parent.end()

        let span = try #require(rig.telemetry.finishedSpans(named: "matter.im.invoke").first)
        #expect(span.parentSpanID == parent.spanID)
        #expect(span.traceID == parent.traceID)
        #expect(span.status?.code != .error)
        #expect(span.attributes.get(MatterLogKey.imStatus) == .string("0x0"))
        let responseLine = try #require(rig.telemetry.logs.entries.first { $0.message.hasPrefix("IM invoke response") })
        #expect(responseLine.message.hasPrefix("IM invoke response: success in "))
        #expect(rig.telemetry.counter("matter_im_requests_total", [("kind", "invoke"), ("outcome", "success")]) == 1)
        await rig.controller.stop()
    }

    @Test("A read logs its attribute path and response at debug and its value at trace")
    func readLogged() async throws {
        let rig = try await makeControllerRig()
        var peer = TestPeer(link: rig.link)
        var seen = Set<UInt32>()
        let path = AttributePath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0006), attributeID: AttributeID(rawValue: 0))
        let call = Task {
            try await rig.controller.readAttribute(nodeID: rig.node, endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0006), attributeID: AttributeID(rawValue: 0))
        }
        let request = try await nextNewFrame(&peer, session: rig.peerSession, seen: &seen)
        #expect(request.exchangeHeader.protocolOpcode == InteractionModelOpcode.readRequest.rawValue)
        try await peer.send(ScriptedPeer.securedReply(
            to: request, session: rig.peerSession, protocolID: .interactionModel,
            opcode: InteractionModelOpcode.reportData.rawValue,
            payload: ReportData(attributeReports: [AttributeReportIB(attributeData: AttributeDataIB(path: path, data: .bool(true)))]).tlvEncode()
        ))
        #expect(try await call.value == .bool(true))

        let requestLine = try #require(rig.telemetry.logs.entries.first { $0.message.hasPrefix("IM read request") })
        #expect(requestLine.metadata[MatterLogKey.attribute] == "0x0")
        #expect(requestLine.metadata[MatterLogKey.cluster] == "0x6")
        #expect(rig.telemetry.logs.entries.contains { $0.message.hasPrefix("IM read response: success") })
        #expect(rig.telemetry.logs.entries.contains { $0.level == .trace && $0.message.hasPrefix("IM read value: bool(true)") })
        let span = try #require(rig.telemetry.finishedSpans(named: "matter.im.read").first)
        #expect(span.attributes.get(MatterLogKey.attribute) == .string("0x0"))
        #expect(rig.telemetry.counter("matter_im_requests_total", [("kind", "read"), ("outcome", "success")]) == 1)
        await rig.controller.stop()
    }

    @Test("A timed invoke logs the timed-request step and counts kind timed")
    func timedInvokeLogged() async throws {
        let rig = try await makeControllerRig()
        var peer = TestPeer(link: rig.link)
        var seen = Set<UInt32>()
        let endpoint = endpoint, cluster = windowCovering, command = goToLift
        let call = Task {
            try await rig.controller.invokeCommand(nodeID: rig.node, endpointID: endpoint, clusterID: cluster, commandID: command, timedTimeout: .seconds(2))
        }
        let timed = try await nextNewFrame(&peer, session: rig.peerSession, seen: &seen)
        #expect(timed.exchangeHeader.protocolOpcode == InteractionModelOpcode.timedRequest.rawValue)
        try await peer.send(ScriptedPeer.securedReply(
            to: timed, session: rig.peerSession, protocolID: .interactionModel,
            opcode: InteractionModelOpcode.statusResponse.rawValue, payload: IMStatusResponse.success.tlvEncode()
        ))
        let invoke = try await nextNewFrame(&peer, session: rig.peerSession, seen: &seen)
        try await peer.send(ScriptedPeer.securedReply(
            to: invoke, session: rig.peerSession, protocolID: .interactionModel,
            opcode: InteractionModelOpcode.invokeResponse.rawValue, payload: successResponse()
        ))
        _ = try await call.value

        #expect(rig.telemetry.logs.entries.contains { $0.message == "Timed request: window 2000 ms" && $0.subsystem == "im" })
        #expect(rig.telemetry.logs.entries.contains { $0.message == "Timed request accepted" })
        #expect(rig.telemetry.counter("matter_im_requests_total", [("kind", "timed"), ("outcome", "success")]) == 1)
        let span = try #require(rig.telemetry.finishedSpans(named: "matter.im.invoke").first)
        #expect(span.attributes.get("matter.timed") == .bool(true))
        await rig.controller.stop()
    }

    @Test("A command the device refuses with a CommandStatusIB carries its IM status on the line and span")
    func commandRefusal() async throws {
        let rig = try await makeControllerRig()
        var peer = TestPeer(link: rig.link)
        var seen = Set<UInt32>()
        let endpoint = endpoint, cluster = windowCovering, command = goToLift
        let call = Task {
            try await rig.controller.invokeCommand(nodeID: rig.node, endpointID: endpoint, clusterID: cluster, commandID: command)
        }
        let request = try await nextNewFrame(&peer, session: rig.peerSession, seen: &seen)
        let commandPath = CommandPath(endpointID: endpoint, clusterID: cluster, commandID: command)
        try await peer.send(ScriptedPeer.securedReply(
            to: request, session: rig.peerSession, protocolID: .interactionModel,
            opcode: InteractionModelOpcode.invokeResponse.rawValue,
            payload: InvokeResponse(invokeResponses: [InvokeResponseIB(status: CommandStatusIB(
                commandPath: commandPath, status: StatusIB(status: 0x81)
            ))]).tlvEncode()
        ))
        await #expect(throws: IMError.commandStatus(path: commandPath, status: 0x81, clusterStatus: nil)) { _ = try await call.value }

        let responseLine = try #require(rig.telemetry.logs.entries.first { $0.message.hasPrefix("IM invoke response") })
        #expect(responseLine.message.hasPrefix("IM invoke response: im_status in "))
        #expect(responseLine.metadata[MatterLogKey.imStatus] == "0x81")
        let span = try #require(rig.telemetry.finishedSpans(named: "matter.im.invoke").first)
        #expect(span.attributes.get(MatterLogKey.imStatus) == .string("0x81"))
        #expect(span.status?.code == .error)
        #expect(rig.telemetry.counter("matter_im_requests_total", [("kind", "invoke"), ("outcome", "im_status")]) == 1)
        await rig.controller.stop()
    }

    // MARK: - Redaction

    @Test("Command fields of a sensitive cluster are redacted everywhere")
    func sensitiveInvokeRedacted() async throws {
        let rig = try await makeControllerRig()
        var peer = TestPeer(link: rig.link)
        var seen = Set<UInt32>()
        let operationalCredentials = ClusterID(rawValue: 0x003E)
        let addNOC = CommandID(rawValue: 0x06)
        let fields: TLVElement = .structure([.init(tag: .contextSpecific(0), value: .unsignedInt(Self.secretValue))])
        let endpoint = EndpointID(rawValue: 0)
        let call = Task {
            try await rig.controller.invokeCommand(nodeID: rig.node, endpointID: endpoint, clusterID: operationalCredentials, commandID: addNOC, commandFields: fields)
        }
        let request = try await nextNewFrame(&peer, session: rig.peerSession, seen: &seen)
        try await peer.send(ScriptedPeer.securedReply(
            to: request, session: rig.peerSession, protocolID: .interactionModel,
            opcode: InteractionModelOpcode.invokeResponse.rawValue,
            payload: successResponse(cluster: operationalCredentials, command: addNOC)
        ))
        _ = try await call.value

        let requestLine = try #require(rig.telemetry.logs.entries.first { $0.message.hasPrefix("IM invoke request") })
        #expect(requestLine.message == "IM invoke request: fields <redacted>")
        let text = rig.telemetry.allRecordedText()
        for rendering in Self.secretRenderings {
            #expect(!text.contains { $0.contains(rendering) }, "\(rendering) appears in a log line or span")
        }
        await rig.controller.stop()
    }

    @Test("Read and write values of sensitive clusters are redacted; a refused write counts im_status")
    func sensitiveReadAndWriteRedacted() async throws {
        let rig = try await makeControllerRig()
        var peer = TestPeer(link: rig.link)
        var seen = Set<UInt32>()
        let groupKeys = ClusterID(rawValue: 0x003F)
        let adminCommissioning = ClusterID(rawValue: 0x003C)
        let attribute = AttributeID(rawValue: 0)
        let endpoint = EndpointID(rawValue: 0)
        let secret: TLVElement = .unsignedInt(Self.secretValue)

        let read = Task {
            try await rig.controller.readAttribute(nodeID: rig.node, endpointID: endpoint, clusterID: groupKeys, attributeID: attribute)
        }
        let readRequest = try await nextNewFrame(&peer, session: rig.peerSession, seen: &seen)
        let readPath = AttributePath(endpointID: endpoint, clusterID: groupKeys, attributeID: attribute)
        try await peer.send(ScriptedPeer.securedReply(
            to: readRequest, session: rig.peerSession, protocolID: .interactionModel,
            opcode: InteractionModelOpcode.reportData.rawValue,
            payload: ReportData(attributeReports: [AttributeReportIB(attributeData: AttributeDataIB(path: readPath, data: secret))]).tlvEncode()
        ))
        #expect(try await read.value == secret)

        let write = Task {
            try await rig.controller.writeAttribute(nodeID: rig.node, endpointID: endpoint, clusterID: adminCommissioning, attributeID: attribute, value: secret)
        }
        let writeRequest = try await nextNewFrame(&peer, session: rig.peerSession, seen: &seen)
        let unsupportedWrite: UInt8 = 0x88
        try await peer.send(ScriptedPeer.securedReply(
            to: writeRequest, session: rig.peerSession, protocolID: .interactionModel,
            opcode: InteractionModelOpcode.writeResponse.rawValue,
            payload: WriteResponse(writeResponses: [AttributeStatusIB(
                path: AttributePath(endpointID: endpoint, clusterID: adminCommissioning, attributeID: attribute),
                status: StatusIB(status: unsupportedWrite)
            )]).tlvEncode()
        ))
        #expect(try await write.value == false)

        #expect(rig.telemetry.logs.entries.contains { $0.level == .trace && $0.message == "IM read value: <redacted>" })
        #expect(rig.telemetry.logs.entries.contains { $0.message == "IM write request: value <redacted>" })
        let text = rig.telemetry.allRecordedText()
        for rendering in Self.secretRenderings {
            #expect(!text.contains { $0.contains(rendering) }, "\(rendering) appears in a log line or span")
        }
        #expect(rig.telemetry.counter("matter_im_requests_total", [("kind", "write"), ("outcome", "im_status")]) == 1)
        let writeLine = try #require(rig.telemetry.logs.entries.first { $0.message.hasPrefix("IM write response") })
        #expect(writeLine.message.hasPrefix("IM write response: im_status in "))
        #expect(writeLine.metadata[MatterLogKey.imStatus] == "0x88")
        let span = try #require(rig.telemetry.finishedSpans(named: "matter.im.write").first)
        #expect(span.status?.code == .error)
        #expect(span.attributes.get(MatterLogKey.imStatus) == .string("0x88"))
        await rig.controller.stop()
    }

    @Test("IMFormat redacts the three sensitive clusters and renders paths in hex")
    func formatting() {
        let value: TLVElement = .unsignedInt(7)
        for cluster: UInt32 in [0x003C, 0x003E, 0x003F] {
            #expect(IMFormat.value(value, clusterID: ClusterID(rawValue: cluster)) == "<redacted>")
            #expect(IMFormat.value(nil, clusterID: ClusterID(rawValue: cluster)) == "<redacted>")
        }
        #expect(IMFormat.value(value, clusterID: ClusterID(rawValue: 0x0006)) == "unsignedInt(7)")
        #expect(IMFormat.value(nil, clusterID: ClusterID(rawValue: 0x0006)) == "none")

        let path = AttributePath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0102), attributeID: AttributeID(rawValue: 0x1A))
        #expect(IMFormat.path(path) == "0x1/0x102/0x1A")
        #expect(IMFormat.path(AttributePath(endpointID: nil, clusterID: ClusterID(rawValue: 6), attributeID: nil)) == "*/0x6/*")
        #expect(IMFormat.describe(AttributeReportIB(attributeData: AttributeDataIB(path: path, data: value))) == "0x1/0x102/0x1A")
        #expect(IMFormat.describe(AttributeReportIB(attributeStatus: AttributeStatusIB(path: path, status: StatusIB(status: 0x86))))
                == "0x1/0x102/0x1A status 0x86")
    }

    // MARK: - Outcomes

    @Test("Errors map to bounded outcomes; cancellation and stop are not counted")
    func outcomeMapping() {
        let node = NodeID(rawValue: 0x42)
        let commandPath = CommandPath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 6), commandID: CommandID(rawValue: 1))
        let cases: [(any Error, IMRequestOutcome?)] = [
            (ControllerError.imStatus(0x7E), .imStatus),
            (IMError.commandStatus(path: commandPath, status: 0x81, clusterStatus: nil), .imStatus),
            (ControllerError.timeout("no response"), .timeout),
            (MessagingError.unknownSession(10), .unreachable),
            (ControllerError.peerUnreachable(node), .unreachable),
            (MessagingError.sessionClosed, .unreachable),
            (ControllerError.transportError("send failed"), .error),
            (ControllerError.deviceNotFound, .error),
            (CancellationError(), nil),
            (MessagingError.stopped, nil),
        ]
        for (error, expected) in cases {
            #expect(IMRequestOutcome(recording: error, controllerStopped: false) == expected, "\(error)")
        }
        // After stop() the messenger's `stopped` reaches the caller mapped to a transport error.
        #expect(IMRequestOutcome(recording: ControllerError.transportError("stopped"), controllerStopped: true) == nil)
    }

    @Test("A silent peer counts outcome unreachable")
    func unreachableCounted() async throws {
        let rig = try await makeControllerRig(mrp: fastMRP)
        let endpoint = endpoint, cluster = windowCovering, command = goToLift
        await #expect(throws: ControllerError.peerUnreachable(rig.node)) {
            _ = try await rig.controller.invokeCommand(nodeID: rig.node, endpointID: endpoint, clusterID: cluster, commandID: command)
        }
        #expect(rig.telemetry.counter("matter_im_requests_total", [("kind", "invoke"), ("outcome", "unreachable")]) == 1)
        let span = try #require(rig.telemetry.finishedSpans(named: "matter.im.invoke").first)
        #expect(span.status?.code == .error)
        await rig.controller.stop()
    }

    @Test("A cancelled request is not counted and its span carries no error")
    func cancellationNotCounted() async throws {
        let rig = try await makeControllerRig()
        var peer = TestPeer(link: rig.link)
        var seen = Set<UInt32>()
        let endpoint = endpoint, cluster = windowCovering, command = goToLift
        let call = Task {
            try await rig.controller.invokeCommand(nodeID: rig.node, endpointID: endpoint, clusterID: cluster, commandID: command)
        }
        _ = try await nextNewFrame(&peer, session: rig.peerSession, seen: &seen)
        call.cancel()
        await #expect(throws: CancellationError.self) { _ = try await call.value }

        expectNoIMMetrics(rig.telemetry, kind: .invoke)
        let span = try #require(rig.telemetry.finishedSpans(named: "matter.im.invoke").first)
        #expect(span.status?.code != .error)
        let line = try #require(rig.telemetry.logs.entries.first { $0.message.hasPrefix("IM invoke response: cancelled in ") })
        #expect(line.message.hasSuffix(": CancellationError()"), "the aborted line keeps the error")
        await rig.controller.stop()
    }

    @Test("A request ended by stop() is not counted and its span carries no error")
    func stopNotCounted() async throws {
        let rig = try await makeControllerRig()
        var peer = TestPeer(link: rig.link)
        var seen = Set<UInt32>()
        let endpoint = endpoint, cluster = windowCovering, command = goToLift
        let call = Task {
            try await rig.controller.invokeCommand(nodeID: rig.node, endpointID: endpoint, clusterID: cluster, commandID: command)
        }
        _ = try await nextNewFrame(&peer, session: rig.peerSession, seen: &seen)
        await rig.controller.stop()
        await #expect(throws: (any Error).self) { _ = try await call.value }

        expectNoIMMetrics(rig.telemetry, kind: .invoke)
        let span = try #require(rig.telemetry.finishedSpans(named: "matter.im.invoke").first)
        #expect(span.status?.code != .error)
        let line = try #require(rig.telemetry.logs.entries.first { $0.message.hasPrefix("IM invoke response: stopped in ") })
        #expect(line.message.hasSuffix(": transportError(\"stopped\")"), "the aborted line keeps the error")
    }
}
