// ControllerIMStatusTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterProtocol
import MatterTransport
import MatterTestSupport
@testable import MatterController

@Suite("Controller IM StatusResponse", .timeLimit(.minutes(1)))
struct ControllerIMStatusTests {

    @Test("A StatusResponse in place of the reply surfaces as imStatus with its code")
    func statusResponseIsTyped() async throws {
        let link = FaultInjectingLink(seed: 3)
        var peer = TestPeer(link: link)
        let controller = try MatterController(
            transport: link.a,
            discovery: MockDiscovery(),
            configuration: .init(fabricID: FabricID(rawValue: 1))
        )
        let (controllerSession, peerSession) = ScriptedPeer.mirroredSessions(controllerSessionID: 10, peerSessionID: 20)
        await controller.messenger.registerSession(controllerSession, peerAddress: link.b.address)

        do {
            async let reply = controller.imRequest(
                sessionID: 10,
                opcode: .invokeRequest,
                payload: Data([0x15, 0x18])
            )
            let request = try await peer.nextSecured(session: peerSession)
            #expect(request.exchangeHeader.protocolOpcode == InteractionModelOpcode.invokeRequest.rawValue)

            let unsupportedAccess: UInt8 = 0x7E
            try await peer.send(ScriptedPeer.securedReply(
                to: request, session: peerSession,
                protocolID: .interactionModel,
                opcode: InteractionModelOpcode.statusResponse.rawValue,
                payload: IMStatusResponse(status: unsupportedAccess).tlvEncode()
            ))

            do {
                _ = try await reply
                Issue.record("a StatusResponse reply must throw")
            } catch {
                #expect(error as? ControllerError == .imStatus(unsupportedAccess))
            }
        } catch {
            await controller.stop()
            throw error
        }
        await controller.stop()
    }
}
