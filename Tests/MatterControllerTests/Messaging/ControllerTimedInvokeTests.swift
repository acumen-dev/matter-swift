// ControllerTimedInvokeTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterProtocol
import MatterTestSupport
@testable import MatterController

@Suite("Controller timed invoke", .timeLimit(.minutes(5)))
struct ControllerTimedInvokeTests {

    /// Same construction as ControllerIMStatusTests: a controller on link.a
    /// with mirrored PASE sessions 10 (controller) / 20 (peer) registered.
    private func makeController() async throws -> (MatterController, FaultInjectingLink, SecureSession) {
        let link = FaultInjectingLink(seed: 3)
        let controller = try MatterController(
            transport: link.a,
            discovery: MockDiscovery(),
            configuration: .init(fabricID: FabricID(rawValue: 1))
        )
        let (controllerSession, peerSession) = ScriptedPeer.mirroredSessions(controllerSessionID: 10, peerSessionID: 20)
        try await controller.messenger.registerSession(controllerSession, peerAddress: link.b.address)
        return (controller, link, peerSession)
    }

    /// The next frame the controller has not sent before. Under load the real
    /// clock can starve the test long enough for MRP to retransmit an
    /// unacknowledged request (same message counter); that is correct
    /// controller behaviour, so the scripted peer skips repeats and bare acks.
    private func nextNew(_ peer: inout TestPeer, session: SecureSession, seen: inout Set<UInt32>) async throws -> PeerFrame {
        while true {
            let frame = try await peer.nextSecured(session: session)
            if frame.isStandaloneAck { continue }
            if seen.insert(frame.counter).inserted { return frame }
        }
    }

    @Test("TimedRequest and the timed InvokeRequest share one exchange")
    func sameExchange() async throws {
        let (controller, link, peerSession) = try await makeController()
        var peer = TestPeer(link: link)
        var seen = Set<UInt32>()
        let payload = IMClient.invokeCommandRequest(
            endpointID: EndpointID(rawValue: 0), clusterID: ClusterID(rawValue: 0x003C),
            commandID: CommandID(rawValue: 0x01),
            commandFields: .structure([.init(tag: .contextSpecific(0), value: .unsignedInt(180))]),
            timedRequest: true
        )
        let call = Task { try await controller.timedInvoke(sessionID: 10, timeout: .seconds(2), payload: payload) }

        let timed = try await nextNew(&peer, session: peerSession, seen: &seen)
        #expect(timed.exchangeHeader.protocolOpcode == InteractionModelOpcode.timedRequest.rawValue)
        #expect(try TimedRequest.fromTLV(timed.payload).timeoutMs == 2000)
        try await peer.send(ScriptedPeer.securedReply(
            to: timed, session: peerSession, protocolID: .interactionModel,
            opcode: InteractionModelOpcode.statusResponse.rawValue, payload: IMStatusResponse.success.tlvEncode()
        ))

        let invoke = try await nextNew(&peer, session: peerSession, seen: &seen)
        #expect(invoke.exchangeHeader.protocolOpcode == InteractionModelOpcode.invokeRequest.rawValue)
        #expect(invoke.exchangeHeader.exchangeID == timed.exchangeHeader.exchangeID, "the device's timed window is per exchange")
        #expect(try InvokeRequest.fromTLV(invoke.payload).timedRequest)
        try await peer.send(ScriptedPeer.securedReply(
            to: invoke, session: peerSession, protocolID: .interactionModel,
            opcode: InteractionModelOpcode.invokeResponse.rawValue,
            payload: InvokeResponse(invokeResponses: []).tlvEncode()
        ))

        let response = try await call.value
        #expect(response.opcode == InteractionModelOpcode.invokeResponse.rawValue)
        await controller.stop()
    }

    @Test("A refused TimedRequest fails the call and the invoke is never sent")
    func refusedTimedRequest() async throws {
        let (controller, link, peerSession) = try await makeController()
        var peer = TestPeer(link: link)
        var seen = Set<UInt32>()
        let call = Task {
            try await controller.timedInvoke(sessionID: 10, timeout: .seconds(1), payload: IMClient.invokeCommandRequest(
                endpointID: EndpointID(rawValue: 1), clusterID: ClusterID(rawValue: 0x0101), commandID: CommandID(rawValue: 0x00), timedRequest: true
            ))
        }
        let timed = try await nextNew(&peer, session: peerSession, seen: &seen)
        try await peer.send(ScriptedPeer.securedReply(
            to: timed, session: peerSession, protocolID: .interactionModel,
            opcode: InteractionModelOpcode.statusResponse.rawValue, payload: IMStatusResponse(status: 0x9C).tlvEncode()
        ))
        await #expect(throws: ControllerError.imStatus(0x9C)) { try await call.value }
        let sentAfter = link.sent(from: .a).compactMap { try? ScriptedPeer.decodeSecured($0, session: peerSession) }
        #expect(!sentAfter.contains { $0.exchangeHeader.protocolOpcode == InteractionModelOpcode.invokeRequest.rawValue })
        await controller.stop()
    }
}
