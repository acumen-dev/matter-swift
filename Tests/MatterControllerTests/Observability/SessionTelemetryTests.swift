// SessionTelemetryTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Tracing
import InMemoryTracing
import MatterTypes
import MatterProtocol
import MatterTestSupport
@testable import MatterController

@Suite("Controller session telemetry", .timeLimit(.minutes(1)))
struct SessionTelemetryTests {

    private func statusReport() -> Data {
        StatusReportMessage(generalStatus: .failure, protocolID: 0, protocolStatus: 0x0002).encode()
    }

    @Test("A refused PASE logs the failure with its duration, counts it and errors the matter.pase span; the passcode is never recorded")
    func paseRefused() async throws {
        let rig = try await makeControllerRig()
        var peer = TestPeer(link: rig.link)
        var seen = Set<UInt32>()
        let address = rig.link.b.address
        let commissioning = Task { try await rig.controller.commission(address: address, setupCode: 20202021) }
        let pbkdf = try await nextNewUnsecuredFrame(&peer, seen: &seen)
        #expect(pbkdf.exchangeHeader.protocolOpcode == SecureChannelOpcode.pbkdfParamRequest.rawValue)
        try await peer.send(ScriptedPeer.unsecuredReply(
            to: pbkdf, protocolID: .secureChannel, opcode: SecureChannelOpcode.statusReport.rawValue,
            payload: statusReport(), counter: 900
        ))
        do {
            _ = try await commissioning.value
            Issue.record("a refused PASE must throw")
        } catch let error as ControllerError {
            guard case .paseHandshakeFailed = error else { Issue.record("unexpected \(error)"); return }
        }

        let line = try #require(rig.telemetry.logs.entries.first { $0.message.hasPrefix("PASE failed after") })
        #expect(line.level == .info)
        #expect(line.subsystem == "pase")
        #expect(line.metadata[MatterLogKey.reason] == "refused")
        #expect(line.metadata[MatterLogKey.latencyMs] != nil)
        #expect(rig.telemetry.counter("matter_sessions_established_total", [("type", "pase"), ("outcome", "refused")]) == 1)
        let span = try #require(rig.telemetry.finishedSpans(named: "matter.pase").first)
        #expect(span.status?.code == .error)
        let exchange = try #require(rig.telemetry.finishedSpans(named: "matter.exchange").first)
        #expect(exchange.parentSpanID == span.spanID)
        #expect(!rig.telemetry.allRecordedText().contains { $0.contains("20202021") })
        await rig.controller.stop()
    }

    @Test("A CASE attempt refused at Sigma1 logs and counts the failure; case_duration records only successes")
    func caseRefused() async throws {
        let rig = try await makeControllerRig(installSession: false)
        var peer = TestPeer(link: rig.link)
        var seen = Set<UInt32>()
        let node = rig.node
        let establishing = Task { try await rig.controller.session(for: node) }
        let sigma1 = try await nextNewUnsecuredFrame(&peer, seen: &seen)
        #expect(sigma1.exchangeHeader.protocolOpcode == SecureChannelOpcode.caseSigma1.rawValue)
        try await peer.send(ScriptedPeer.unsecuredReply(
            to: sigma1, protocolID: .secureChannel, opcode: SecureChannelOpcode.statusReport.rawValue,
            payload: statusReport(), counter: 800
        ))
        do {
            _ = try await establishing.value
            Issue.record("a refused CASE must throw")
        } catch let error as ControllerError {
            guard case .caseSessionFailed = error else { Issue.record("unexpected \(error)"); return }
        }

        let line = try #require(rig.telemetry.logs.entries.first { $0.message.hasPrefix("CASE session failed after") })
        #expect(line.level == .info)
        #expect(line.subsystem == "case")
        #expect(line.metadata[MatterLogKey.node] == "0x42")
        #expect(line.metadata[MatterLogKey.reason] == "refused")
        #expect(rig.telemetry.counter("matter_sessions_established_total", [("type", "case"), ("outcome", "refused")]) == 1)
        #expect(rig.telemetry.timerValues("matter_case_duration").isEmpty)
        let span = try #require(rig.telemetry.finishedSpans(named: "matter.case").first)
        #expect(span.status?.code == .error)
        #expect(span.attributes.get(MatterLogKey.node) == .string("0x42"))
        await rig.controller.stop()
    }

    @Test("A successful CASE logs its session and duration, counts success, times case_duration once and ends the span without error")
    func caseEstablished() async throws {
        let (rig, deviceFabric) = try await makeCASEControllerRig()
        var peer = TestPeer(link: rig.link)
        var seen = Set<UInt32>()
        let node = rig.node
        let establishing = Task { try await rig.controller.session(for: node) }
        let sigma1 = try await nextNewUnsecuredFrame(&peer, seen: &seen)
        #expect(sigma1.exchangeHeader.protocolOpcode == SecureChannelOpcode.caseSigma1.rawValue)
        let (sigma2, _) = try CASEProtocolHandler(fabricInfo: deviceFabric).handleSigma1(payload: sigma1.payload, responderSessionID: 300)
        try await peer.send(ScriptedPeer.unsecuredReply(
            to: sigma1, protocolID: .secureChannel, opcode: SecureChannelOpcode.caseSigma2.rawValue,
            payload: sigma2, counter: 800
        ))
        let sigma3 = try await nextNewUnsecuredFrame(&peer, seen: &seen)
        #expect(sigma3.exchangeHeader.protocolOpcode == SecureChannelOpcode.caseSigma3.rawValue)
        try await peer.send(ScriptedPeer.unsecuredReply(
            to: sigma3, protocolID: .secureChannel, opcode: SecureChannelOpcode.statusReport.rawValue,
            payload: StatusReportMessage(generalStatus: .success, protocolID: 0, protocolStatus: 0).encode(), counter: 801
        ))
        let session = try await establishing.value
        let sessionID = MatterLogValue.hexString(session.localSessionID)

        let line = try #require(rig.telemetry.logs.entries.first { $0.message.hasPrefix("CASE session established in") })
        #expect(line.level == .info)
        #expect(line.subsystem == "case")
        #expect(line.metadata[MatterLogKey.node] == "0x42")
        #expect(line.metadata[MatterLogKey.session] == sessionID)
        #expect(line.metadata[MatterLogKey.latencyMs] != nil)
        #expect(line.metadata[MatterLogKey.reason] == nil)
        #expect(rig.telemetry.counter("matter_sessions_established_total", [("type", "case"), ("outcome", "success")]) == 1)
        #expect(rig.telemetry.timerValues("matter_case_duration").count == 1)
        let span = try #require(rig.telemetry.finishedSpans(named: "matter.case").first)
        #expect(span.attributes.get(MatterLogKey.session) == .string(sessionID))
        #expect(span.status?.code != .error)
        #expect(span.errors.isEmpty)
        #expect(await rig.controller.messenger.registeredSessionIDs.contains(session.localSessionID))
        await rig.controller.stop()
    }

    @Test("A caller's context parents the matter.case span, which parents the CASE exchange")
    func caseParentContext() async throws {
        let rig = try await makeControllerRig(installSession: false)
        var peer = TestPeer(link: rig.link)
        var seen = Set<UInt32>()
        let node = rig.node
        let parent = rig.telemetry.tracer.startSpan("test.parent")
        let parentContext = parent.context
        let establishing = Task { try await rig.controller.session(for: node, context: parentContext) }
        let sigma1 = try await nextNewUnsecuredFrame(&peer, seen: &seen)
        try await peer.send(ScriptedPeer.unsecuredReply(
            to: sigma1, protocolID: .secureChannel, opcode: SecureChannelOpcode.statusReport.rawValue,
            payload: statusReport(), counter: 800
        ))
        await #expect(throws: ControllerError.self) { _ = try await establishing.value }
        parent.end()

        let caseSpan = try #require(rig.telemetry.finishedSpans(named: "matter.case").first)
        #expect(caseSpan.parentSpanID == parent.spanID)
        #expect(caseSpan.traceID == parent.traceID)
        let exchanges = rig.telemetry.finishedSpans(named: "matter.exchange")
        #expect(!exchanges.isEmpty)
        for exchange in exchanges {
            #expect(exchange.parentSpanID == caseSpan.spanID)
        }
        await rig.controller.stop()
    }

    @Test("A CASE attempt ended by stop() is not counted and its span ends without error status")
    func caseStopped() async throws {
        let rig = try await makeControllerRig(installSession: false)
        var peer = TestPeer(link: rig.link)
        var seen = Set<UInt32>()
        let node = rig.node
        let establishing = Task { try await rig.controller.session(for: node) }
        let sigma1 = try await nextNewUnsecuredFrame(&peer, seen: &seen)
        #expect(sigma1.exchangeHeader.protocolOpcode == SecureChannelOpcode.caseSigma1.rawValue)
        await rig.controller.stop()
        await #expect(throws: (any Error).self) { _ = try await establishing.value }

        for outcome in SessionOutcome.allCases {
            #expect(rig.telemetry.counter("matter_sessions_established_total", [("type", "case"), ("outcome", outcome.rawValue)]) == 0,
                    "no \(outcome.rawValue) outcome is counted")
        }
        #expect(!rig.telemetry.logs.entries.contains { $0.message.hasPrefix("CASE session failed after") })
        let line = try #require(rig.telemetry.logs.entries.first { $0.message.hasPrefix("CASE session stopped after") })
        #expect(line.subsystem == "case")
        let span = try #require(rig.telemetry.finishedSpans(named: "matter.case").first)
        #expect(span.status?.code != .error)
        #expect(span.errors.isEmpty)
    }

    @Test("An unreachable node: the give-up, the IM outcome unreachable, and the session invalidation with its reason")
    func unreachableInvalidates() async throws {
        let rig = try await makeControllerRig(mrp: fastMRP)
        rig.link.setDropProbability(1, from: .a)
        let node = rig.node
        await #expect(throws: ControllerError.peerUnreachable(node)) {
            _ = try await rig.controller.invokeCommand(
                nodeID: node, endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0102), commandID: CommandID(rawValue: 0x05)
            )
        }

        let giveUp = try #require(rig.telemetry.logs.entries.first { $0.message.hasPrefix("Peer unreachable") })
        #expect(giveUp.subsystem == "mrp")
        #expect(giveUp.metadata[MatterLogKey.attempt] == "2")
        let invalidated = try #require(rig.telemetry.logs.entries.first { $0.message.hasPrefix("Session invalidated") })
        #expect(invalidated.level == .info)
        #expect(invalidated.subsystem == "session")
        #expect(invalidated.message == "Session invalidated: peer unreachable")
        #expect(invalidated.metadata[MatterLogKey.session] == "0xA")
        #expect(invalidated.metadata[MatterLogKey.reason] == "peer unreachable")
        #expect(rig.telemetry.counter("matter_im_requests_total", [("kind", "invoke"), ("outcome", "unreachable")]) == 1)
        #expect(rig.telemetry.counter("matter_mrp_give_ups_total") == 1)
        #expect(await rig.controller.messenger.registeredSessionIDs.isEmpty)
        await rig.controller.stop()
    }
}
