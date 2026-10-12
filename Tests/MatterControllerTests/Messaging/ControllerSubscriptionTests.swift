// ControllerSubscriptionTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterProtocol
import MatterTestSupport
@testable import MatterController

@Suite("ControllerSubscription")
struct ControllerSubscriptionTests {

    private let node = NodeID(rawValue: 0x42)
    private let onOff = AttributePath(endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0006), attributeID: AttributeID(rawValue: 0))
    private let id = SubscriptionID(rawValue: 7)
    private let margin = Duration.seconds(5)

    private func makeSubscription(_ rig: Rig, request: SubscriptionRequest? = nil) -> ControllerSubscription {
        ControllerSubscription(
            nodeID: node,
            request: request ?? SubscriptionRequest(attributePaths: [onOff], minInterval: 1, maxInterval: 10),
            messenger: rig.messenger,
            client: SubscriptionClient(),
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
        while status.isStandaloneAck { status = try await peer.nextSecured(session: rig.peerSession) }
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
        let sentBefore = rig.link.sent(from: .a).count
        try await peer.send(ScriptedPeer.secured(session: rig.peerSession, exchangeID: 0x5001, initiator: true, protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue, payload: ReportData(subscriptionID: id, suppressResponse: true).tlvEncode()))
        guard case .report(let delivered)? = await iterator.next() else { Issue.record("expected the report"); return }
        #expect(delivered.suppressResponse)
        let statusSent = rig.link.sent(from: .a).dropFirst(sentBefore).compactMap { try? ScriptedPeer.decodeSecured($0, session: rig.peerSession) }
            .contains { $0.exchangeHeader.protocolOpcode == InteractionModelOpcode.statusResponse.rawValue }
        #expect(!statusSent)
        await sub.cancel(); await rig.messenger.stop()
    }

    @Test("Cancel unregisters the handler and finishes the stream")
    func cancelFinishes() async throws {
        let rig = try await makeRig()
        var peer = TestPeer(link: rig.link)
        let sub = makeSubscription(rig)
        let started = Task { try await sub.start() }
        _ = try await playEstablishment(&peer, rig)
        try await started.value
        await sub.cancel()
        var count = 0
        for await _ in sub.events { count += 1 }
        #expect(count >= 1, "buffered events drain, then the stream finishes")
        #expect(await sub.currentSubscriptionID == nil)
        await rig.messenger.stop()
    }
}
