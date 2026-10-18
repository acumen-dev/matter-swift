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

    /// The span IDs `span` links to.
    private func linkedSpanIDs(_ span: FinishedInMemorySpan) -> [String?] {
        span.links.map { $0.context.inMemorySpanContext?.spanID }
    }

    /// Establish, read the standalone ack of SubscribeResponse, and consume `.established` and
    /// the two priming reports.
    private func establishAndDrain(
        _ sub: ControllerSubscription, _ peer: inout TestPeer, _ rig: Rig
    ) async throws -> AsyncStream<SubscriptionEvent>.Iterator {
        let started = Task { try await sub.start() }
        try await playEstablishment(&peer, rig)
        try await started.value
        let ack = try await peer.nextSecured(session: rig.peerSession)
        #expect(ack.isStandaloneAck)
        var iterator = sub.events.makeAsyncIterator()
        _ = await iterator.next(); _ = await iterator.next(); _ = await iterator.next()
        return iterator
    }

    /// Expire the liveness deadline (10 s + 5 s margin) and return the `.lost` reason, then wait
    /// for the first re-subscribe backoff sleeper.
    private func expireLiveness(_ rig: Rig, _ iterator: inout AsyncStream<SubscriptionEvent>.Iterator) async -> String? {
        #expect(await rig.clock.waitForSleeper(until: rig.clock.now + .seconds(15)))
        await rig.clock.advance(by: .seconds(15))
        guard case .lost(let reason)? = await iterator.next() else { return nil }
        #expect(await rig.clock.waitForSleeper(until: rig.clock.now + .seconds(1)))
        return reason
    }

    @Test("Establishment: subscribe request and response at debug, established at info, each priming ReportData at debug; report spans are roots linked to the subscribe span")
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
        #expect(telemetry.tracer.activeSpans.allSatisfy { $0.operationName == "test.parent" }, "no long-lived span")
        let reportSpans = telemetry.finishedSpans(named: "matter.report")
        #expect(reportSpans.count == 2)
        #expect(reportSpans.first?.attributes.get(MatterLogKey.paths) == .stringArray(["0x1/0x6/0x0"]))
        #expect(reportSpans.first?.attributes.get(MatterLogKey.subscription) == .string("0x7"))
        #expect(reportSpans.first?.attributes.get(MatterLogKey.node) == .string("0x42"))
        for span in reportSpans {
            #expect(span.parentSpanID == nil)
            #expect(span.events.isEmpty)
            #expect(linkedSpanIDs(span) == [subscribeSpan.spanID])
        }
        #expect(telemetry.timerValues("matter_report_interval").isEmpty, "a priming report's second chunk records no interval")

        await sub.cancel()
        #expect(telemetry.logs.entries.contains { $0.message == "Subscription closed" && $0.level == .info })
        #expect(telemetry.counter("matter_subscription_lost_total", [("reason", "closed")]) == 1)
        let closed = try #require(telemetry.finishedSpans(named: "matter.subscription.lost").first)
        #expect(closed.status == nil)
        #expect(closed.parentSpanID == nil)
        #expect(closed.attributes.get(MatterLogKey.reason) == .string("closed"))
        #expect(closed.attributes.get(MatterLogKey.subscription) == .string("0x7"))
        #expect(linkedSpanIDs(closed) == [subscribeSpan.spanID])
        await rig.messenger.stop()
    }

    @Test("A liveness expiry is logged at info, counted and spanned before it is yielded; the re-subscribe is logged and counted, and its reports link to the new subscribe span")
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
        let firstSubscribe = try #require(telemetry.finishedSpans(named: "matter.subscribe").first)
        let ended = try #require(telemetry.finishedSpans(named: "matter.subscription.lost").first)
        #expect(ended.status?.code == .error)
        #expect(ended.parentSpanID == nil)
        #expect(ended.attributes.get(MatterLogKey.reason) == .string("liveness"))
        #expect(ended.attributes.get(MatterLogKey.subscription) == .string("0x7"))
        #expect(linkedSpanIDs(ended) == [firstSubscribe.spanID])

        #expect(await rig.clock.waitForSleeper(until: rig.clock.now + .seconds(1)))
        let resubscribing = try #require(telemetry.logs.entries.first { $0.message.hasPrefix("Re-subscribing") })
        #expect(resubscribing.level == .info)
        #expect(resubscribing.metadata[MatterLogKey.attempt] == "1")
        await rig.clock.advance(by: .seconds(1), awaitingRearm: false)
        try await playEstablishment(&peer, rig)
        #expect(await iterator.next() == .established(id, negotiatedMaxInterval: 10))
        guard case .report? = await iterator.next(), case .report? = await iterator.next() else { Issue.record("expected the priming reports"); return }
        #expect(telemetry.counter("matter_resubscribes_total") == 1)
        #expect(await eventually { telemetry.finishedSpans(named: "matter.subscribe").count == 2 })
        let secondSubscribe = try #require(telemetry.finishedSpans(named: "matter.subscribe").last)
        #expect(secondSubscribe.spanID != firstSubscribe.spanID)
        let reportSpans = telemetry.finishedSpans(named: "matter.report")
        #expect(reportSpans.count == 4)
        #expect(reportSpans.prefix(2).map(linkedSpanIDs) == [[firstSubscribe.spanID], [firstSubscribe.spanID]])
        #expect(reportSpans.suffix(2).map(linkedSpanIDs) == [[secondSubscribe.spanID], [secondSubscribe.spanID]])
        #expect(telemetry.timerValues("matter_report_interval").isEmpty, "a new subscription restarts the interval")
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
        let secretBytes = Data([0xC0, 0xFF, 0xEE, 0x5E, 0xC2, 0xE7, 0x11, 0x22])
        let secret = TLVElement.octetString(secretBytes)
        let request = try await peer.nextSecured(session: rig.peerSession)
        let chunk = ReportData(subscriptionID: id, attributeReports: [AttributeReportIB(attributeData: AttributeDataIB(path: fabrics, data: secret))])
        try await peer.send(ScriptedPeer.securedReply(to: request, session: rig.peerSession, protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue, payload: chunk.tlvEncode()))
        let status = try await peer.nextSecured(session: rig.peerSession)
        try await peer.send(ScriptedPeer.securedReply(to: status, session: rig.peerSession, protocolID: .interactionModel, opcode: InteractionModelOpcode.subscribeResponse.rawValue, payload: SubscribeResponse(subscriptionID: id, maxInterval: 10).tlvEncode()))
        try await started.value

        #expect(telemetry.logs.entries.contains { $0.level == .trace && $0.message == "Report 0x0/0x3E/0x1 = <redacted>" })
        #expect(telemetry.finishedSpans(named: "matter.report").first?.attributes.get(MatterLogKey.paths) == .stringArray(["0x0/0x3E/0x1"]))
        let forms = SecretForms.of(secretBytes) + [String(describing: secret)]
        let leaked = telemetry.allRecordedText().filter { text in forms.contains { text.contains($0) } }
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

    @Test("A report's first chunk records the interval since the last report's first chunk; later chunks do not")
    func reportInterval() async throws {
        let telemetry = TestTelemetry()
        let rig = try await makeRig(telemetry: telemetry)
        var peer = TestPeer(link: rig.link)
        let sub = makeSubscription(rig, telemetry: telemetry)
        var iterator = try await establishAndDrain(sub, &peer, rig)

        await rig.clock.advance(by: .seconds(3))
        let chunk1 = ReportData(subscriptionID: id, attributeReports: [AttributeReportIB(attributeData: AttributeDataIB(path: onOff, data: .bool(true)))], moreChunkedMessages: true)
        try await peer.send(ScriptedPeer.secured(session: rig.peerSession, exchangeID: 0x5000, initiator: true, protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue, payload: chunk1.tlvEncode()))
        var status = try await peer.nextSecured(session: rig.peerSession)
        while status.isStandaloneAck { status = try await peer.nextSecured(session: rig.peerSession) }
        #expect(status.exchangeHeader.protocolOpcode == InteractionModelOpcode.statusResponse.rawValue)
        await rig.clock.advance(by: .seconds(1))
        try await peer.send(ScriptedPeer.securedReply(to: status, session: rig.peerSession, protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue, payload: ReportData(subscriptionID: id).tlvEncode()))
        guard case .report? = await iterator.next(), case .report? = await iterator.next() else { Issue.record("expected both chunks"); return }

        #expect(telemetry.timerValues("matter_report_interval") == [3_000_000_000])
        await sub.cancel()
        await rig.messenger.stop()
    }

    @Test("A refused re-subscribe is logged, counted as resubscribe_failed and spanned with error status before it is yielded")
    func resubscribeFailed() async throws {
        let telemetry = TestTelemetry()
        let rig = try await makeRig(telemetry: telemetry)
        var peer = TestPeer(link: rig.link)
        let sub = makeSubscription(rig, telemetry: telemetry)
        var iterator = try await establishAndDrain(sub, &peer, rig)
        #expect(await expireLiveness(rig, &iterator) == "no report within 10 s + margin")

        await rig.clock.advance(by: .seconds(1), awaitingRearm: false)
        let request = try await peer.nextSecured(session: rig.peerSession)
        #expect(request.exchangeHeader.protocolOpcode == InteractionModelOpcode.subscribeRequest.rawValue)
        try await peer.send(ScriptedPeer.securedReply(to: request, session: rig.peerSession, protocolID: .interactionModel, opcode: InteractionModelOpcode.statusResponse.rawValue, payload: IMStatusResponse(status: 0x7D).tlvEncode()))
        guard case .lost(let reason)? = await iterator.next() else { Issue.record("expected .lost"); return }
        #expect(reason.hasPrefix("re-subscribe failed: "))

        let lost = try #require(telemetry.logs.entries.last { $0.message.hasPrefix("Subscription lost") })
        #expect(lost.level == .info)
        #expect(lost.message == "Subscription lost: \(reason)")
        #expect(lost.metadata[MatterLogKey.reason] == "resubscribe_failed")
        #expect(telemetry.counter("matter_subscription_lost_total", [("reason", "resubscribe_failed")]) == 1)
        #expect(telemetry.logs.entries.contains { $0.level == .debug && $0.message == "Subscribe refused" && $0.metadata[MatterLogKey.imStatus] == "0x7D" })
        let subscribes = telemetry.finishedSpans(named: "matter.subscribe")
        #expect(subscribes.count == 2)
        #expect(subscribes.last?.status?.code == .error)
        let failed = try #require(telemetry.finishedSpans(named: "matter.subscription.lost").last)
        #expect(failed.attributes.get(MatterLogKey.reason) == .string("resubscribe_failed"))
        #expect(failed.attributes.get(MatterLogKey.subscription) == .string("0x7"))
        #expect(failed.status?.code == .error)
        #expect(linkedSpanIDs(failed) == [subscribes.first?.spanID])
        await sub.cancel()
        await rig.messenger.stop()
    }

    @Test("A re-subscribe aborted by the messenger stopping still yields .lost, but is only logged at debug and not counted")
    func resubscribeAborted() async throws {
        let telemetry = TestTelemetry()
        let rig = try await makeRig(telemetry: telemetry)
        var peer = TestPeer(link: rig.link)
        let sub = makeSubscription(rig, telemetry: telemetry)
        var iterator = try await establishAndDrain(sub, &peer, rig)
        #expect(await expireLiveness(rig, &iterator) == "no report within 10 s + margin")

        await rig.messenger.stop()
        await rig.clock.advance(by: .seconds(1), awaitingRearm: false)
        guard case .lost(let reason)? = await iterator.next() else { Issue.record("expected .lost"); return }
        #expect(reason.hasPrefix("re-subscribe failed: "))

        #expect(telemetry.logs.entries.contains { $0.level == .debug && $0.message.hasPrefix("Re-subscribe aborted") })
        #expect(!telemetry.logs.entries.contains { $0.message == "Subscription lost: \(reason)" })
        #expect(telemetry.counter("matter_subscription_lost_total", [("reason", "resubscribe_failed")]) == 0)
        #expect(telemetry.finishedSpans(named: "matter.subscription.lost").count == 1, "the liveness loss only")
        let subscribes = telemetry.finishedSpans(named: "matter.subscribe")
        #expect(subscribes.count == 2)
        #expect(subscribes.last?.status == nil)
        #expect(subscribes.last?.errors.isEmpty == true)
        await sub.cancel()
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
