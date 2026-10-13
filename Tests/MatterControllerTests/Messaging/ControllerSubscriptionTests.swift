// ControllerSubscriptionTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterProtocol
import MatterTestSupport
@testable import MatterController

@Suite("ControllerSubscription", .timeLimit(.minutes(5)))
struct ControllerSubscriptionTests {

    private let node = NodeID(rawValue: 0x42)
    private let onOff = AttributePath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0006), attributeID: AttributeID(rawValue: 0))
    private let id = SubscriptionID(rawValue: 7)
    private let margin = Duration.seconds(5)

    private func makeSubscription(_ rig: Rig, client: SubscriptionClient = SubscriptionClient(), request: SubscriptionRequest? = nil) -> ControllerSubscription {
        ControllerSubscription(
            nodeID: node,
            request: request ?? SubscriptionRequest(attributePaths: [onOff], minInterval: 1, maxInterval: 10),
            messenger: rig.messenger,
            client: client,
            sessionProvider: { 10 },
            livenessMargin: margin,
            operationTimeout: .seconds(30)
        )
    }

    /// Play the device side of one establishment: answer SubscribeRequest with a
    /// two-chunk priming report, then SubscribeResponse. Returns the
    /// SubscribeRequest frame it received.
    private func playEstablishment(_ peer: inout TestPeer, _ rig: Rig, maxInterval: UInt16 = 10) async throws -> PeerFrame {
        let request = try await peer.nextSecured(session: rig.peerSession)
        #expect(request.exchangeHeader.protocolOpcode == InteractionModelOpcode.subscribeRequest.rawValue)
        let chunk1 = ReportData(subscriptionID: id, attributeReports: [AttributeReportIB(attributeData: AttributeDataIB(dataVersion: nil, path: onOff, data: .bool(false)))], moreChunkedMessages: true)
        try await peer.send(ScriptedPeer.securedReply(to: request, session: rig.peerSession, protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue, payload: chunk1.tlvEncode()))
        let status1 = try await peer.nextSecured(session: rig.peerSession)
        #expect(status1.exchangeHeader.protocolOpcode == InteractionModelOpcode.statusResponse.rawValue)
        try await peer.send(ScriptedPeer.securedReply(to: status1, session: rig.peerSession, protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue, payload: ReportData(subscriptionID: id).tlvEncode()))
        let status2 = try await peer.nextSecured(session: rig.peerSession)
        #expect(status2.exchangeHeader.protocolOpcode == InteractionModelOpcode.statusResponse.rawValue)
        try await peer.send(ScriptedPeer.securedReply(to: status2, session: rig.peerSession, protocolID: .interactionModel, opcode: InteractionModelOpcode.subscribeResponse.rawValue, payload: SubscribeResponse(subscriptionID: id, maxInterval: maxInterval).tlvEncode()))
        return request
    }

    /// Acknowledge the controller's StatusResponse so MRP does not retransmit it
    /// when the manual clock advances, and wait until the messenger has processed
    /// the ack (its retransmit timer is back at the idle horizon).
    private func ackStatus(_ status: PeerFrame, _ peer: TestPeer, _ rig: Rig) async throws {
        try await peer.send(ScriptedPeer.securedReply(to: status, session: rig.peerSession, protocolID: .secureChannel, opcode: SecureChannelOpcode.standaloneAck.rawValue, reliable: false))
        #expect(await rig.clock.waitForSleeper(until: rig.clock.now + ControllerMessenger.idleTimerHorizon))
    }

    /// Start a subscription and play its establishment; returns it with its event iterator
    /// positioned after the three establishment events.
    private func establish(_ rig: Rig, _ peer: inout TestPeer, client: SubscriptionClient = SubscriptionClient(), maxInterval: UInt16 = 10) async throws -> (ControllerSubscription, AsyncStream<SubscriptionEvent>.Iterator) {
        let sub = makeSubscription(rig, client: client)
        let started = Task { try await sub.start() }
        _ = try await playEstablishment(&peer, rig, maxInterval: maxInterval)
        try await started.value
        let ack = try await peer.nextSecured(session: rig.peerSession)   // ack of SubscribeResponse
        #expect(ack.isStandaloneAck)
        var iterator = sub.events.makeAsyncIterator()
        _ = await iterator.next(); _ = await iterator.next(); _ = await iterator.next()
        return (sub, iterator)
    }

    @Test("Establishment answers each priming chunk, then registers before the exchange closes")
    func establishment() async throws {
        let rig = try await makeRig()
        var peer = TestPeer(link: rig.link)
        let sub = makeSubscription(rig)
        let started = Task { try await sub.start() }
        _ = try await playEstablishment(&peer, rig)
        try await started.value
        #expect(await sub.currentSubscriptionID == id)

        var iterator = sub.events.makeAsyncIterator()
        #expect(await iterator.next() == .established(id, negotiatedMaxInterval: 10))
        guard case .report(let priming1)? = await iterator.next() else { Issue.record("expected priming chunk 1"); return }
        #expect(priming1.attributes.count == 1)
        guard case .report? = await iterator.next() else { Issue.record("expected priming chunk 2"); return }
        await sub.cancel(); await rig.messenger.stop()
    }

    @Test("A later report is delivered, keeps its events, and is answered with StatusResponse")
    func steadyStateReport() async throws {
        let rig = try await makeRig()
        var peer = TestPeer(link: rig.link)
        let sub = makeSubscription(rig)
        let started = Task { try await sub.start() }
        _ = try await playEstablishment(&peer, rig)
        try await started.value
        var iterator = sub.events.makeAsyncIterator()
        _ = await iterator.next(); _ = await iterator.next(); _ = await iterator.next()   // established + 2 priming chunks

        let lockOp = EventPath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0101), eventID: EventID(rawValue: 2))
        let report = ReportData(subscriptionID: id, eventReports: [EventReportIB(eventData: EventDataIB(path: lockOp, eventNumber: EventNumber(rawValue: 12), priority: .info, data: .structure([])))])
        try await peer.send(ScriptedPeer.secured(session: rig.peerSession, exchangeID: 0x5000, initiator: true, protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue, payload: report.tlvEncode()))
        // Closing the establishment exchange first acks SubscribeResponse with a standalone ack.
        var status = try await peer.nextSecured(session: rig.peerSession)
        if status.isStandaloneAck {
            #expect(status.exchangeHeader.exchangeID != 0x5000, "the ack is for the SubscribeResponse")
            status = try await peer.nextSecured(session: rig.peerSession)
        }
        #expect(status.exchangeHeader.protocolOpcode == InteractionModelOpcode.statusResponse.rawValue)
        #expect(status.exchangeHeader.exchangeID == 0x5000)
        guard case .report(let delivered)? = await iterator.next() else { Issue.record("expected the report"); return }
        #expect(delivered.events.count == 1)
        await sub.cancel(); await rig.messenger.stop()
    }

    @Test("A suppressResponse report is delivered without a StatusResponse")
    func suppressedReport() async throws {
        let rig = try await makeRig()
        var peer = TestPeer(link: rig.link)
        let sub = makeSubscription(rig)
        let started = Task { try await sub.start() }
        _ = try await playEstablishment(&peer, rig)
        try await started.value
        var iterator = sub.events.makeAsyncIterator()
        _ = await iterator.next(); _ = await iterator.next(); _ = await iterator.next()
        try await peer.send(ScriptedPeer.secured(session: rig.peerSession, exchangeID: 0x5001, initiator: true, protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue, payload: ReportData(subscriptionID: id, suppressResponse: true).tlvEncode()))
        guard case .report(let delivered)? = await iterator.next() else { Issue.record("expected the report"); return }
        #expect(delivered.suppressResponse)
        // A following ordinary report is answered; the first frame the peer reads
        // after that is its StatusResponse, so none was sent for 0x5001.
        try await peer.send(ScriptedPeer.secured(session: rig.peerSession, exchangeID: 0x5002, initiator: true, protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue, payload: ReportData(subscriptionID: id).tlvEncode()))
        var frame = try await peer.nextSecured(session: rig.peerSession)
        while frame.isStandaloneAck { frame = try await peer.nextSecured(session: rig.peerSession) }
        #expect(frame.exchangeHeader.exchangeID == 0x5002)
        #expect(frame.exchangeHeader.protocolOpcode == InteractionModelOpcode.statusResponse.rawValue)
        await sub.cancel(); await rig.messenger.stop()
    }

    @Test("A report is yielded on events before its StatusResponse is sent")
    func deliveryPrecedesStatusResponse() async throws {
        let rig = try await makeRig()
        var peer = TestPeer(link: rig.link)
        let sub = makeSubscription(rig)
        let started = Task { try await sub.start() }
        _ = try await playEstablishment(&peer, rig)
        try await started.value
        var iterator = sub.events.makeAsyncIterator()
        _ = await iterator.next(); _ = await iterator.next(); _ = await iterator.next()

        try await peer.send(ScriptedPeer.secured(session: rig.peerSession, exchangeID: 0x5004, initiator: true, protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue, payload: ReportData(subscriptionID: id).tlvEncode()))
        var frame = try await peer.nextSecured(session: rig.peerSession)
        while frame.isStandaloneAck { frame = try await peer.nextSecured(session: rig.peerSession) }
        #expect(frame.exchangeHeader.protocolOpcode == InteractionModelOpcode.statusResponse.rawValue)
        // The peer has read the StatusResponse, so the report is already buffered.
        // Cancelling finishes the stream; a buffered report still drains first,
        // and a missing one makes the stream end with nil.
        await sub.cancel()
        guard case .report? = await iterator.next() else { Issue.record("report was not delivered before the StatusResponse"); return }
        await rig.messenger.stop()
    }

    @Test("Cancel unregisters the handler and finishes the stream")
    func cancelFinishes() async throws {
        let rig = try await makeRig()
        var peer = TestPeer(link: rig.link)
        let client = SubscriptionClient()
        let sub = makeSubscription(rig, client: client)
        let started = Task { try await sub.start() }
        _ = try await playEstablishment(&peer, rig)
        try await started.value
        #expect(await client.count == 1)
        await sub.cancel()
        #expect(await client.count == 0)
        #expect(await rig.messenger.subscriptionHandlers.isEmpty)
        var count = 0
        for await _ in sub.events { count += 1 }
        #expect(count >= 1, "buffered events drain, then the stream finishes")
        #expect(await sub.currentSubscriptionID == nil)
        await rig.messenger.stop()
    }

    @Test("A report sent right after SubscribeResponse is delivered after the established event and priming reports")
    func reportImmediatelyAfterEstablishment() async throws {
        let rig = try await makeRig()
        var peer = TestPeer(link: rig.link)
        let sub = makeSubscription(rig)
        let started = Task { try await sub.start() }
        _ = try await playEstablishment(&peer, rig)
        // The controller's ack of SubscribeResponse goes out when it closes the
        // establishment exchange, after the route is registered. A device only
        // reports once that ack arrives; sending earlier would race the route.
        let ack = try await peer.nextSecured(session: rig.peerSession)
        #expect(ack.isStandaloneAck)
        try await peer.send(ScriptedPeer.secured(session: rig.peerSession, exchangeID: 0x5002, initiator: true, protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue, payload: ReportData(subscriptionID: id, suppressResponse: false).tlvEncode()))
        try await started.value

        var iterator = sub.events.makeAsyncIterator()
        #expect(await iterator.next() == .established(id, negotiatedMaxInterval: 10))
        guard case .report(let p1)? = await iterator.next() else { Issue.record("expected priming 1"); return }
        #expect(p1.attributes.count == 1)
        guard case .report(let p2)? = await iterator.next() else { Issue.record("expected priming 2"); return }
        #expect(p2.attributes.isEmpty)
        guard case .report? = await iterator.next() else { Issue.record("expected the later report"); return }
        let frame = try await peer.nextSecured(session: rig.peerSession)
        #expect(frame.exchangeHeader.exchangeID == 0x5002)
        #expect(frame.exchangeHeader.protocolOpcode == InteractionModelOpcode.statusResponse.rawValue)
        await sub.cancel(); await rig.messenger.stop()
    }

    @Test("Backoff doubles from 1 s and caps at 300 s")
    func backoffSequence() {
        let seconds = (0..<11).map { ControllerSubscription.backoff(attempt: $0) }
        #expect(seconds == [1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300].map { Duration.seconds($0) })
    }

    @Test("Silence past negotiated max interval + margin is declared lost; the re-subscribe asks only for new events")
    func livenessAndResubscribe() async throws {
        let rig = try await makeRig()
        var peer = TestPeer(link: rig.link)
        let lockOp = EventPath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0101), eventID: EventID(rawValue: 2))
        let sub = makeSubscription(rig, request: SubscriptionRequest(attributePaths: [onOff], eventPaths: [lockOp], minInterval: 1, maxInterval: 10))
        let started = Task { try await sub.start() }
        _ = try await playEstablishment(&peer, rig, maxInterval: 10)
        try await started.value
        var iterator = sub.events.makeAsyncIterator()
        _ = await iterator.next(); _ = await iterator.next(); _ = await iterator.next()

        // An event arrives: high-water mark 12.
        let report = ReportData(subscriptionID: id, eventReports: [EventReportIB(eventData: EventDataIB(path: lockOp, eventNumber: EventNumber(rawValue: 12), priority: .info, data: .structure([])))])
        try await peer.send(ScriptedPeer.secured(session: rig.peerSession, exchangeID: 0x5002, initiator: true, protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue, payload: report.tlvEncode()))
        var status = try await peer.nextSecured(session: rig.peerSession)
        if status.isStandaloneAck { status = try await peer.nextSecured(session: rig.peerSession) }
        #expect(status.exchangeHeader.protocolOpcode == InteractionModelOpcode.statusResponse.rawValue)
        try await ackStatus(status, peer, rig)
        _ = await iterator.next()

        // Just short of the deadline (10 s + 5 s margin): still alive.
        #expect(await rig.clock.waitForSleeper(until: rig.clock.now + .seconds(15)))
        await rig.clock.advance(by: .seconds(14))
        #expect(await sub.currentSubscriptionID == id)
        // At it: lost.
        await rig.clock.advance(by: .seconds(1))
        guard case .lost? = await iterator.next() else { Issue.record("expected .lost"); return }

        // First re-subscribe follows after backoff(0) = 1 s and carries eventMin 13.
        #expect(await rig.clock.waitForSleeper(until: rig.clock.now + .seconds(1)))
        await rig.clock.advance(by: .seconds(1))
        let resubscribe = try await playEstablishment(&peer, rig, maxInterval: 10)
        let decoded = try SubscribeRequest.fromTLV(resubscribe.payload)
        #expect(decoded.eventFilters.map(\.eventMin) == [EventNumber(rawValue: 13)])
        #expect(await iterator.next() == .established(id, negotiatedMaxInterval: 10))
        await sub.cancel(); await rig.messenger.stop()
    }

    @Test("A report before the deadline keeps the subscription alive")
    func reportExtendsLiveness() async throws {
        let rig = try await makeRig()
        var peer = TestPeer(link: rig.link)
        let sub = makeSubscription(rig)
        let started = Task { try await sub.start() }
        _ = try await playEstablishment(&peer, rig, maxInterval: 10)
        try await started.value
        var iterator = sub.events.makeAsyncIterator()
        _ = await iterator.next(); _ = await iterator.next(); _ = await iterator.next()

        #expect(await rig.clock.waitForSleeper(until: rig.clock.now + .seconds(15)))
        await rig.clock.advance(by: .seconds(12))
        try await peer.send(ScriptedPeer.secured(session: rig.peerSession, exchangeID: 0x5003, initiator: true, protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue, payload: ReportData(subscriptionID: id).tlvEncode()))
        var status = try await peer.nextSecured(session: rig.peerSession)
        if status.isStandaloneAck { status = try await peer.nextSecured(session: rig.peerSession) }
        try await ackStatus(status, peer, rig)
        _ = await iterator.next()
        await rig.clock.advance(by: .seconds(12))   // 24 s after establishment, 12 s after the report
        #expect(await sub.currentSubscriptionID == id, "the deadline moved with the report")
        await sub.cancel(); await rig.messenger.stop()
    }

    @Test("The liveness deadline uses the negotiated max interval, not the requested one")
    func negotiatedIntervalGovernsDeadline() async throws {
        let rig = try await makeRig()
        var peer = TestPeer(link: rig.link)
        var (sub, iterator) = try await establish(rig, &peer, maxInterval: 30)   // requested 10, granted 30
        #expect(await rig.clock.waitForSleeper(until: rig.clock.now + .seconds(35)))
        await rig.clock.advance(by: .seconds(34))
        #expect(await sub.currentSubscriptionID == id)
        await rig.clock.advance(by: .seconds(1))
        guard case .lost? = await iterator.next() else { Issue.record("expected .lost at 35 s"); return }
        await sub.cancel(); await rig.messenger.stop()
    }

    @Test("A failed re-subscribe yields .lost and the next attempt waits backoff(1) = 2 s")
    func failedResubscribeBacksOff() async throws {
        let rig = try await makeRig()
        var peer = TestPeer(link: rig.link)
        var (sub, iterator) = try await establish(rig, &peer)
        #expect(await rig.clock.waitForSleeper(until: rig.clock.now + .seconds(15)))
        await rig.clock.advance(by: .seconds(15))
        guard case .lost? = await iterator.next() else { Issue.record("expected .lost"); return }

        #expect(await rig.clock.waitForSleeper(until: rig.clock.now + .seconds(1)))
        await rig.clock.advance(by: .seconds(1))
        let request = try await peer.nextSecured(session: rig.peerSession)
        #expect(request.exchangeHeader.protocolOpcode == InteractionModelOpcode.subscribeRequest.rawValue)
        try await peer.send(ScriptedPeer.securedReply(to: request, session: rig.peerSession, protocolID: .interactionModel, opcode: InteractionModelOpcode.statusResponse.rawValue, payload: IMStatusResponse(status: 0x80).tlvEncode(), reliable: false))
        guard case .lost(let reason)? = await iterator.next() else { Issue.record("expected .lost for the failed attempt"); return }
        #expect(reason.contains("re-subscribe failed"))

        let sentAfterFailure = rig.link.sent(from: .a).count
        #expect(await rig.clock.waitForSleeper(until: rig.clock.now + .seconds(2)))
        await rig.clock.advance(by: .seconds(1))
        #expect(rig.link.sent(from: .a).count == sentAfterFailure, "backoff(1) is 2 s; nothing sent at 1 s")
        await rig.clock.advance(by: .seconds(1))
        let retry = try await playEstablishment(&peer, rig)
        #expect(retry.exchangeHeader.protocolOpcode == InteractionModelOpcode.subscribeRequest.rawValue)
        #expect(await iterator.next() == .established(id, negotiatedMaxInterval: 10))
        await sub.cancel(); await rig.messenger.stop()
    }

    @Test("Cancel during the backoff sleep stops everything: no further SubscribeRequest, no route, no client entry")
    func cancelDuringBackoff() async throws {
        let rig = try await makeRig()
        var peer = TestPeer(link: rig.link)
        let client = SubscriptionClient()
        var (sub, iterator) = try await establish(rig, &peer, client: client)
        #expect(await rig.clock.waitForSleeper(until: rig.clock.now + .seconds(15)))
        await rig.clock.advance(by: .seconds(15))
        guard case .lost? = await iterator.next() else { Issue.record("expected .lost"); return }
        #expect(await rig.clock.waitForSleeper(until: rig.clock.now + .seconds(1)))

        await sub.cancel()
        let sentAtCancel = rig.link.sent(from: .a).count
        await rig.clock.advance(by: .seconds(600))
        #expect(rig.link.sent(from: .a).count == sentAtCancel, "no SubscribeRequest after cancel")
        #expect(await iterator.next() == nil, "the stream finished")
        #expect(await rig.messenger.subscriptionHandlers.isEmpty)
        #expect(await client.count == 0)
        #expect(await sub.currentSubscriptionID == nil)
        await rig.messenger.stop()
    }

    @Test("A failed establishment reports the session it used, and the next attempt asks for a session again")
    func failureHookAndFreshSession() async throws {
        let rig = try await makeRig()
        let used = LockedValue<[UInt16]>([])
        let failed = LockedValue<[UInt16]>([])
        let next = LockedValue<[UInt16]>([999, 998])
        let sub = ControllerSubscription(
            nodeID: node,
            request: SubscriptionRequest(attributePaths: [onOff], minInterval: 1, maxInterval: 10),
            messenger: rig.messenger,
            client: SubscriptionClient(),
            sessionProvider: { next.withLock { ids in let id = ids.removeFirst(); used.withLock { $0.append(id) }; return id } },
            livenessMargin: margin,
            operationTimeout: .seconds(30),
            onEstablishFailure: { sessionID, _ in failed.withLock { $0.append(sessionID) } }
        )
        await #expect(throws: (any Error).self) { try await sub.start() }
        await #expect(throws: (any Error).self) { try await sub.start() }
        #expect(used.value == [999, 998], "the provider is consulted afresh on every attempt")
        #expect(failed.value == [999, 998])
        await sub.cancel(); await rig.messenger.stop()
    }

    @Test("A cancelled establishment does not report a failure")
    func cancellationIsNotAFailure() async throws {
        let rig = try await makeRig()
        let failed = LockedValue(0)
        let box = LockedValue<ControllerSubscription?>(nil)
        let sub = ControllerSubscription(
            nodeID: node,
            request: SubscriptionRequest(attributePaths: [onOff], minInterval: 1, maxInterval: 10),
            messenger: rig.messenger,
            client: SubscriptionClient(),
            sessionProvider: { await box.value?.cancel(); return 10 },
            livenessMargin: margin,
            operationTimeout: .seconds(30),
            onEstablishFailure: { _, _ in failed.withLock { $0 += 1 } }
        )
        box.withLock { $0 = sub }
        await #expect(throws: CancellationError.self) { try await sub.start() }
        #expect(failed.value == 0)
        #expect(await sub.isCancelled)
        await rig.messenger.stop()
    }
}
