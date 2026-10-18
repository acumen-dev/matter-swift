// SubscriptionTelemetryTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Tracing
import InMemoryTracing
import MatterTypes
import MatterProtocol
import MatterTestSupport
@testable import MatterController

@Suite("ControllerSubscription telemetry", .timeLimit(.minutes(1)))
struct SubscriptionTelemetryTests {

    private let node = NodeID(rawValue: 0x42)
    private let onOff = AttributePath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0006), attributeID: AttributeID(rawValue: 0))
    private let id = SubscriptionID(rawValue: 7)

    private func makeSubscription(_ rig: Rig, telemetry: TestTelemetry, context: ServiceContext = .topLevel) -> ControllerSubscription {
        ControllerSubscription(
            nodeID: node,
            request: SubscriptionRequest(attributePaths: [onOff], minInterval: 1, maxInterval: 10),
            messenger: rig.messenger,
            client: SubscriptionClient(),
            sessionProvider: { 10 },
            livenessMargin: .seconds(5),
            operationTimeout: .seconds(30),
            logger: telemetry.logger(label: "test.subscription"),
            context: context
        )
    }

    /// The device side of one establishment: a two-chunk priming report, then SubscribeResponse.
    private func playEstablishment(_ peer: inout TestPeer, _ rig: Rig, maxInterval: UInt16 = 10) async throws {
        let request = try await peer.nextSecured(session: rig.peerSession)
        #expect(request.exchangeHeader.protocolOpcode == InteractionModelOpcode.subscribeRequest.rawValue)
        let chunk1 = ReportData(subscriptionID: id, attributeReports: [AttributeReportIB(attributeData: AttributeDataIB(path: onOff, data: .bool(false)))], moreChunkedMessages: true)
        try await peer.send(ScriptedPeer.securedReply(to: request, session: rig.peerSession, protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue, payload: chunk1.tlvEncode()))
        let status1 = try await peer.nextSecured(session: rig.peerSession)
        try await peer.send(ScriptedPeer.securedReply(to: status1, session: rig.peerSession, protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue, payload: ReportData(subscriptionID: id).tlvEncode()))
        let status2 = try await peer.nextSecured(session: rig.peerSession)
        try await peer.send(ScriptedPeer.securedReply(to: status2, session: rig.peerSession, protocolID: .interactionModel, opcode: InteractionModelOpcode.subscribeResponse.rawValue, payload: SubscribeResponse(subscriptionID: id, maxInterval: maxInterval).tlvEncode()))
    }

    @Test("Establishment: subscribe request and response at debug, established at info, each priming ReportData at debug; spans and events")
    func establishmentObserved() async throws {
        let telemetry = TestTelemetry()
        let rig = try await makeRig(telemetry: telemetry)
        var peer = TestPeer(link: rig.link)
        let parent = telemetry.tracer.startSpan("test.parent")
        let sub = makeSubscription(rig, telemetry: telemetry, context: parent.context)
        let started = Task { try await sub.start() }
        try await playEstablishment(&peer, rig)
        try await started.value

        let established = try #require(telemetry.logs.entries.first { $0.message.hasPrefix("Subscription established") })
        #expect(established.level == .info)
        #expect(established.subsystem == "subscription")
        #expect(established.label == "test.subscription")
        #expect(established.message == "Subscription established, max interval 10 s")
        #expect(established.metadata[MatterLogKey.subscription] == "0x7")
        #expect(established.metadata[MatterLogKey.node] == "0x42")
        #expect(telemetry.logs.entries.contains { $0.level == .debug && $0.message.hasPrefix("Subscribe request: 1 attribute path(s)") })
        #expect(telemetry.logs.entries.contains { $0.level == .debug && $0.message == "Subscribe response: max interval 10 s, 2 priming chunk(s)" })
        let reports = telemetry.logs.entries.filter { $0.message.hasPrefix("ReportData chunk") }
        #expect(reports.map(\.message) == [
            "ReportData chunk 1 (more follow): 1 attribute(s), 0 event(s) [0x1/0x6/0x0]",
            "ReportData chunk 2: 0 attribute(s), 0 event(s) []",
        ])
        #expect(telemetry.logs.entries.contains { $0.level == .trace && $0.message == "Report 0x1/0x6/0x0 = bool(false)" })

        let subscribeSpan = try #require(telemetry.finishedSpans(named: "matter.subscribe").first)
        #expect(subscribeSpan.parentSpanID == parent.spanID)
        let subscriptionSpan = try #require(telemetry.activeSpans(named: "matter.subscription").first)
        #expect(subscriptionSpan.parentSpanID == parent.spanID)
        #expect(subscriptionSpan.events.map(\.name) == ["report", "report"])
        let reportSpans = telemetry.finishedSpans(named: "matter.report")
        #expect(reportSpans.count == 2)
        #expect(reportSpans.first?.attributes.get(MatterLogKey.attribute) == .stringArray(["0x1/0x6/0x0"]))
        #expect(reportSpans.first?.parentSpanID == subscriptionSpan.spanID)

        await sub.cancel()
        #expect(telemetry.logs.entries.contains { $0.message == "Subscription closed" && $0.level == .info })
        #expect(telemetry.counter("matter_subscription_lost_total", [("reason", "closed")]) == 1)
        #expect(telemetry.finishedSpans(named: "matter.subscription").count == 1)
        await rig.messenger.stop()
    }

    @Test("A liveness expiry logs its reason at info, counts it and ends the subscription span; the re-subscribe is logged and counted")
    func livenessExpiry() async throws {
        let telemetry = TestTelemetry()
        let rig = try await makeRig(telemetry: telemetry)
        var peer = TestPeer(link: rig.link)
        let sub = makeSubscription(rig, telemetry: telemetry)
        let started = Task { try await sub.start() }
        try await playEstablishment(&peer, rig)
        try await started.value
        let ack = try await peer.nextSecured(session: rig.peerSession)
        #expect(ack.isStandaloneAck)
        var iterator = sub.events.makeAsyncIterator()
        _ = await iterator.next(); _ = await iterator.next(); _ = await iterator.next()

        #expect(await rig.clock.waitForSleeper(until: rig.clock.now + .seconds(15)))
        #expect(telemetry.logs.entries.contains { $0.level == .trace && $0.message.hasPrefix("Liveness deadline recomputed") })
        await rig.clock.advance(by: .seconds(15))
        guard case .lost(let reason)? = await iterator.next() else { Issue.record("expected .lost"); return }
        #expect(reason == "no report within 10 s + margin")

        let lost = try #require(telemetry.logs.entries.first { $0.message.hasPrefix("Subscription lost") })
        #expect(lost.level == .info)
        #expect(lost.message == "Subscription lost: no report within 10 s + margin")
        #expect(lost.metadata[MatterLogKey.reason] == "liveness")
        #expect(lost.metadata[MatterLogKey.subscription] == "0x7")
        #expect(telemetry.counter("matter_subscription_lost_total", [("reason", "liveness")]) == 1)
        let ended = try #require(telemetry.finishedSpans(named: "matter.subscription").first)
        #expect(ended.status?.code == .error)

        #expect(await rig.clock.waitForSleeper(until: rig.clock.now + .seconds(1)))
        let resubscribing = try #require(telemetry.logs.entries.first { $0.message.hasPrefix("Re-subscribing") })
        #expect(resubscribing.level == .info)
        #expect(resubscribing.metadata[MatterLogKey.attempt] == "1")
        await rig.clock.advance(by: .seconds(1), awaitingRearm: false)
        try await playEstablishment(&peer, rig)
        #expect(await iterator.next() == .established(id, negotiatedMaxInterval: 10))
        #expect(telemetry.counter("matter_resubscribes_total") == 1)
        #expect(rig.clock.quiescenceTimeouts == 0)
        await sub.cancel()
        await rig.messenger.stop()
    }

    @Test("A session gone under the subscription keeps the lost text unchanged; the cause is in matter.reason and the reason dimension")
    func sessionLoss() async throws {
        let telemetry = TestTelemetry()
        let rig = try await makeRig(telemetry: telemetry)
        var peer = TestPeer(link: rig.link)
        let sub = makeSubscription(rig, telemetry: telemetry)
        let started = Task { try await sub.start() }
        try await playEstablishment(&peer, rig)
        try await started.value
        var iterator = sub.events.makeAsyncIterator()
        _ = await iterator.next(); _ = await iterator.next(); _ = await iterator.next()

        #expect(await rig.clock.waitForSleeper(until: rig.clock.now + .seconds(15)))
        await rig.messenger.unregisterSession(localSessionID: 10)
        await rig.clock.advance(by: .seconds(15))
        guard case .lost(let reason)? = await iterator.next() else { Issue.record("expected .lost"); return }
        #expect(reason == "no report within 10 s + margin")

        let lost = try #require(telemetry.logs.entries.first { $0.message.hasPrefix("Subscription lost") })
        #expect(lost.message == "Subscription lost: no report within 10 s + margin")
        #expect(lost.metadata[MatterLogKey.reason] == "session")
        #expect(telemetry.counter("matter_subscription_lost_total", [("reason", "session")]) == 1)
        #expect(telemetry.counter("matter_subscription_lost_total", [("reason", "liveness")]) == 0)
        await sub.cancel()
        #expect(telemetry.counter("matter_subscription_lost_total", [("reason", "closed")]) == 0)
        await rig.messenger.stop()
    }

    @Test("Report values of Operational Credentials are redacted at trace; their paths still show")
    func sensitiveReportRedacted() async throws {
        let telemetry = TestTelemetry()
        let rig = try await makeRig(telemetry: telemetry)
        var peer = TestPeer(link: rig.link)
        let sub = makeSubscription(rig, telemetry: telemetry)
        let started = Task { try await sub.start() }
        let fabrics = AttributePath(endpointID: EndpointID(rawValue: 0), clusterID: ClusterID(rawValue: 0x003E), attributeID: AttributeID(rawValue: 1))
        let secret = TLVElement.unsignedInt(0xC0FFEE_5EC2E7)
        let request = try await peer.nextSecured(session: rig.peerSession)
        let chunk = ReportData(subscriptionID: id, attributeReports: [AttributeReportIB(attributeData: AttributeDataIB(path: fabrics, data: secret))])
        try await peer.send(ScriptedPeer.securedReply(to: request, session: rig.peerSession, protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue, payload: chunk.tlvEncode()))
        let status = try await peer.nextSecured(session: rig.peerSession)
        try await peer.send(ScriptedPeer.securedReply(to: status, session: rig.peerSession, protocolID: .interactionModel, opcode: InteractionModelOpcode.subscribeResponse.rawValue, payload: SubscribeResponse(subscriptionID: id, maxInterval: 10).tlvEncode()))
        try await started.value

        #expect(telemetry.logs.entries.contains { $0.level == .trace && $0.message == "Report 0x0/0x3E/0x1 = <redacted>" })
        #expect(telemetry.finishedSpans(named: "matter.report").first?.attributes.get(MatterLogKey.attribute) == .stringArray(["0x0/0x3E/0x1"]))
        let leaked = telemetry.allRecordedText().filter { $0.contains(String(describing: secret)) || $0.contains(String(0xC0FFEE_5EC2E7)) }
        #expect(leaked.isEmpty)
        await sub.cancel()
        await rig.messenger.stop()
    }

    @Test("An establishment cancelled mid-exchange counts no loss and leaves its subscribe span without error status")
    func cancelledEstablishment() async throws {
        let telemetry = TestTelemetry()
        let rig = try await makeRig(telemetry: telemetry)
        var peer = TestPeer(link: rig.link)
        let sub = makeSubscription(rig, telemetry: telemetry)
        let started = Task { try await sub.start() }
        let request = try await peer.nextSecured(session: rig.peerSession)
        await sub.cancel()
        let chunk = ReportData(subscriptionID: id, attributeReports: [AttributeReportIB(attributeData: AttributeDataIB(path: onOff, data: .bool(false)))])
        try await peer.send(ScriptedPeer.securedReply(to: request, session: rig.peerSession, protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue, payload: chunk.tlvEncode()))
        await #expect(throws: CancellationError.self) { try await started.value }

        let span = try #require(telemetry.finishedSpans(named: "matter.subscribe").first)
        #expect(span.status == nil)
        #expect(span.errors.isEmpty)
        #expect(!telemetry.logs.entries.contains { $0.message.hasPrefix("Subscription lost") || $0.message == "Subscription closed" })
        for reason in ["liveness", "resubscribe_failed", "session", "closed"] {
            #expect(telemetry.counter("matter_subscription_lost_total", [("reason", reason)]) == 0)
        }
        await rig.messenger.stop()
    }

    @Test("MatterController.subscribe hands the controller's logger and the caller's context to the subscription")
    func controllerSubscribe() async throws {
        let rig = try await makeControllerRig()
        var peer = TestPeer(link: rig.link)
        var seen = Set<UInt32>()
        let parent = rig.telemetry.tracer.startSpan("acumen.matter.subscribe")
        let parentContext = parent.context
        let request = SubscriptionRequest(attributePaths: [onOff], minInterval: 1, maxInterval: 10)
        let node = rig.node
        let call = Task { try await rig.controller.subscribe(nodeID: node, request, context: parentContext) }

        let subscribe = try await nextNewFrame(&peer, session: rig.peerSession, seen: &seen)
        #expect(subscribe.exchangeHeader.protocolOpcode == InteractionModelOpcode.subscribeRequest.rawValue)
        let priming = ReportData(subscriptionID: SubscriptionID(rawValue: 9), attributeReports: [AttributeReportIB(attributeData: AttributeDataIB(path: onOff, data: .bool(false)))])
        try await peer.send(ScriptedPeer.securedReply(to: subscribe, session: rig.peerSession, protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue, payload: priming.tlvEncode()))
        let status = try await nextNewFrame(&peer, session: rig.peerSession, seen: &seen)
        #expect(status.exchangeHeader.protocolOpcode == InteractionModelOpcode.statusResponse.rawValue)
        try await peer.send(ScriptedPeer.securedReply(to: status, session: rig.peerSession, protocolID: .interactionModel, opcode: InteractionModelOpcode.subscribeResponse.rawValue, payload: SubscribeResponse(subscriptionID: SubscriptionID(rawValue: 9), maxInterval: 30).tlvEncode()))
        let subscription = try await call.value

        let established = try await rig.telemetry.logs.first { $0.message.hasPrefix("Subscription established") }
        #expect(established.label == "test.controller")
        #expect(established.subsystem == "subscription")
        let subscribeSpan = try #require(rig.telemetry.finishedSpans(named: "matter.subscribe").first)
        #expect(subscribeSpan.parentSpanID == parent.spanID)
        await subscription.cancel()
        await rig.controller.stop()
    }
}
