// TelemetryPlumbingTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Logging
import MetricsTestKit
import MatterTypes
import MatterProtocol
import MatterTransport
import MatterTestSupport
@testable import MatterController

@Suite("Telemetry plumbing", .timeLimit(.minutes(1)))
struct TelemetryPlumbingTests {

    @Test("The controller's logger reaches its messenger and subscriptions, label unchanged, tagged by subsystem")
    func injectedLoggerReachesComponents() async throws {
        let rig = try await makeControllerRig()
        var peer = TestPeer(link: rig.link)
        let messenger = await rig.controller.messenger
        #expect(messenger.logger.label == "test.controller")
        #expect(messenger.logger[metadataKey: MatterLogKey.subsystem] == "messenger")
        #expect(messenger.mrpLogger[metadataKey: MatterLogKey.subsystem] == "mrp")

        let subscription = ControllerSubscription(
            nodeID: rig.node, request: SubscriptionRequest(maxInterval: 10), messenger: messenger,
            client: SubscriptionClient(), sessionProvider: { 10 }, livenessMargin: .seconds(5),
            operationTimeout: .seconds(30), logger: rig.telemetry.logger(label: "test.controller")
        )
        #expect(subscription.logger.label == "test.controller")
        #expect(subscription.logger[metadataKey: MatterLogKey.subsystem] == "subscription")

        // A line the messenger writes: a frame for an unknown session (77), then a round trip
        // on session 10, so the earlier datagram has been processed.
        let stranger = ScriptedPeer.mirroredSessions(controllerSessionID: 77, peerSessionID: 78).peer
        try await peer.send(ScriptedPeer.secured(
            session: stranger, exchangeID: 0x0700, initiator: true,
            protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue
        ))
        async let reply = rig.controller.imRequest(sessionID: 10, opcode: .invokeRequest, payload: Data([0x15, 0x18]))
        let request = try await peer.nextSecured(session: rig.peerSession)
        try await peer.send(ScriptedPeer.securedReply(
            to: request, session: rig.peerSession, protocolID: .interactionModel,
            opcode: InteractionModelOpcode.statusResponse.rawValue, payload: IMStatusResponse(status: 0x7E).tlvEncode()
        ))
        do {
            _ = try await reply
            Issue.record("a StatusResponse reply must throw")
        } catch {
            #expect(error as? ControllerError == .imStatus(0x7E))
        }

        let line = try #require(rig.telemetry.logs.entries.first { $0.message.hasPrefix("Dropping message for unknown session") })
        #expect(line.label == "test.controller")
        #expect(line.subsystem == "messenger")
        await rig.controller.stop()
    }

    @Test("SecureMessageCodec logs an oversized frame through the logger it is given")
    func codecUsesInjectedLogger() throws {
        let telemetry = TestTelemetry()
        let (session, _) = ScriptedPeer.mirroredSessions(controllerSessionID: 1, peerSessionID: 2)
        _ = try SecureMessageCodec.encode(
            exchangeHeader: ExchangeHeader(
                flags: ExchangeFlags(initiator: true, reliableDelivery: true),
                protocolOpcode: InteractionModelOpcode.invokeRequest.rawValue,
                exchangeID: 1,
                protocolID: MatterProtocolID.interactionModel.rawValue
            ),
            payload: Data(count: MatterMessage.maxUDPPayloadSize),
            session: session,
            sourceNodeID: NodeID(rawValue: 1),
            logger: telemetry.logger(label: "test.codec")
        )
        let entry = try #require(telemetry.logs.entries.first)
        #expect(entry.label == "test.codec")
        #expect(entry.level == .error)
        #expect(entry.message.contains("exceeds max UDP payload"))
        #expect(entry.metadata[MatterLogKey.session] == "0x1")
    }

    @Test("Metrics are created once, named with the prefix, with bounded dimensions only")
    func metricNames() {
        let metrics = TestMetrics()
        _ = ControllerMetrics(prefix: "acme", factory: metrics)
        #expect(Set(metrics.counters.map(\.label)) == [
            "acme_controller_messages_total", "acme_mrp_retransmits_total", "acme_mrp_give_ups_total",
            "acme_exchange_timeouts_total", "acme_im_requests_total", "acme_sessions_established_total",
            "acme_subscription_lost_total", "acme_resubscribes_total",
        ])
        #expect(Set(metrics.timers.map(\.label)) == ["acme_im_request_duration", "acme_case_duration", "acme_report_interval"])
        let dimensionNames = Set(
            metrics.counters.flatMap { $0.dimensions.map { $0.0 } } + metrics.timers.flatMap { $0.dimensions.map { $0.0 } }
        )
        #expect(dimensionNames == ["direction", "protocol", "kind", "outcome", "type", "reason"])
        #expect(metrics.counters.filter { $0.label == "acme_im_requests_total" }.count == 20)
        #expect(metrics.counters.filter { $0.label == "acme_controller_messages_total" }.count == 12)
    }

    @Test("A controller's metrics default to the matter prefix and its configured factory")
    func defaultPrefix() async throws {
        let rig = try await makeControllerRig()
        #expect(rig.telemetry.metrics.counters.contains { $0.label == "matter_mrp_retransmits_total" })
        #expect(rig.configuration.metricsLabelPrefix == "matter")
        await rig.controller.stop()
    }
}
