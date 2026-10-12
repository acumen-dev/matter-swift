// ControllerIMClientTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterModel
import MatterProtocol
import MatterDevice
import MatterController
import MatterTestSupport

@Suite("Controller IM client against the device server", .serialized, .timeLimit(.minutes(3)))
struct ControllerIMClientTests {

    private static let commissioningTimeout = TLVElement.structure([
        .init(tag: .contextSpecific(0), value: .unsignedInt(180))
    ])

    @Test("A timed-only command is refused without TimedRequest and accepted with it")
    func timedInvoke() async throws {
        let link = FaultInjectingLink(seed: 11)
        let (server, _) = try await startServer(on: link, toggles: LockedValue(0))
        let controller = try makeController(on: link, maxRetransmissions: 4)
        do {
            let device = try await controller.commission(address: link.b.address, setupCode: passcode, mrp: fast)

            // The device answers with an InvokeResponse carrying the command
            // status NeedsTimedInteraction (0xC6 = 198), not a top-level
            // StatusResponse, so it surfaces as IMError.invalidStatus.
            await #expect(throws: IMError.invalidStatus("Command error: status 198")) {
                _ = try await controller.invokeCommand(
                    nodeID: device.nodeID, endpointID: EndpointID(rawValue: 0),
                    clusterID: .adminCommissioning, commandID: CommandID(rawValue: 0x01),
                    commandFields: Self.commissioningTimeout
                )
            }

            let fields = try await controller.invokeCommand(
                nodeID: device.nodeID, endpointID: EndpointID(rawValue: 0),
                clusterID: .adminCommissioning, commandID: CommandID(rawValue: 0x01),
                commandFields: Self.commissioningTimeout,
                timedTimeout: .seconds(2)
            )
            #expect(fields == nil)
        } catch {
            await controller.stop(); await server.stop()
            throw error
        }
        await controller.stop(); await server.stop()
    }
}
