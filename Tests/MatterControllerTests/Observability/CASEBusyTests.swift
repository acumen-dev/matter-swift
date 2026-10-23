// CASEBusyTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterProtocol
import MatterTestSupport
@testable import MatterController

@Suite("CASE busy StatusReport", .timeLimit(.minutes(1)))
struct CASEBusyTests {

    private func busyReport(waitMs: UInt16?) -> Data {
        let data = waitMs.map { Data([UInt8($0 & 0xFF), UInt8($0 >> 8)]) }
        return StatusReportMessage(generalStatus: .busy, protocolID: 0, protocolStatus: 4, protocolData: data).encode()
    }

    @Test("A busy Sigma1 waits the stated time before a fresh Sigma1, then establishes")
    func waitsThenEstablishes() async throws {
        let clock = ManualClock()
        let (rig, fabric) = try await makeCASEControllerRig(retryClock: clock)
        var peer = TestPeer(link: rig.link)
        var seen = Set<UInt32>()
        let node = rig.node
        let establishing = Task { try await rig.controller.session(for: node) }
        let first = try await nextNewUnsecuredFrame(&peer, seen: &seen)
        #expect(first.exchangeHeader.protocolOpcode == SecureChannelOpcode.caseSigma1.rawValue)
        try await peer.send(ScriptedPeer.unsecuredReply(
            to: first, protocolID: .secureChannel, opcode: SecureChannelOpcode.statusReport.rawValue,
            payload: busyReport(waitMs: 2000), counter: 700
        ))
        try await clock.awaitSleepers(atLeast: 1)
        #expect(clock.nextSleeperDeadline == clock.now + .seconds(2))
        #expect(rig.telemetry.counter("matter_case_busy_waits_total") == 1)
        let log = try #require(rig.telemetry.logs.entries.first { $0.message.contains("busy") })
        #expect(log.level == .info)
        #expect(log.metadata[MatterLogKey.node] == "0x42")

        // Nothing new has been sent while the controller waits.
        let outbound = { rig.telemetry.counter("matter_controller_messages_total", [("direction", "out"), ("protocol", "secure_channel")]) }
        try await Task.sleep(for: .milliseconds(100))
        let sentWhileWaiting = outbound()
        try await Task.sleep(for: .milliseconds(200))
        #expect(outbound() == sentWhileWaiting, "no frame leaves while the controller waits out the busy time")

        await clock.advance(by: .seconds(2), awaitingRearm: false)
        let sigma1 = try await nextNewUnsecuredFrame(&peer, seen: &seen)
        #expect(sigma1.exchangeHeader.protocolOpcode == SecureChannelOpcode.caseSigma1.rawValue)
        let (sigma2, _) = try CASEProtocolHandler(fabricInfo: fabric.deviceFabric).handleSigma1(payload: sigma1.payload, responderSessionID: 300)
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
        #expect(await rig.controller.messenger.registeredSessionIDs.contains(session.localSessionID))
        #expect(rig.telemetry.counter("matter_case_busy_waits_total") == 1)
        await rig.controller.stop()
    }

    @Test("A busy wait longer than the operation timeout fails at once, with no second Sigma1")
    func waitBeyondTimeoutFails() async throws {
        let clock = ManualClock()
        let (rig, _) = try await makeCASEControllerRig(operationTimeout: .seconds(30), retryClock: clock)
        var peer = TestPeer(link: rig.link)
        var seen = Set<UInt32>()
        let node = rig.node
        let establishing = Task { try await rig.controller.session(for: node) }
        let first = try await nextNewUnsecuredFrame(&peer, seen: &seen)
        try await peer.send(ScriptedPeer.unsecuredReply(
            to: first, protocolID: .secureChannel, opcode: SecureChannelOpcode.statusReport.rawValue,
            payload: busyReport(waitMs: 0xFFFF), counter: 700
        ))
        let error = await #expect(throws: ControllerError.self) { _ = try await establishing.value }
        guard case .caseSessionFailed(let message)? = error else { Issue.record("unexpected \(String(describing: error))"); return }
        #expect(message.contains("busy"))
        #expect(clock.sleeperCount == 0)
        let sent = rig.telemetry.counter("matter_controller_messages_total", [("direction", "out"), ("protocol", "secure_channel")])
        try await Task.sleep(for: .milliseconds(200))
        #expect(rig.telemetry.counter("matter_controller_messages_total", [("direction", "out"), ("protocol", "secure_channel")]) == sent)
        #expect(rig.telemetry.counter("matter_case_busy_waits_total") == 0)
        await rig.controller.stop()
    }

    @Test("Three busy answers give up")
    func threeBusyGiveUp() async throws {
        let clock = ManualClock()
        let (rig, _) = try await makeCASEControllerRig(retryClock: clock)
        var peer = TestPeer(link: rig.link)
        var seen = Set<UInt32>()
        let node = rig.node
        let establishing = Task { try await rig.controller.session(for: node) }
        for attempt in 0..<3 {
            let sigma1 = try await nextNewUnsecuredFrame(&peer, seen: &seen)
            #expect(sigma1.exchangeHeader.protocolOpcode == SecureChannelOpcode.caseSigma1.rawValue)
            try await peer.send(ScriptedPeer.unsecuredReply(
                to: sigma1, protocolID: .secureChannel, opcode: SecureChannelOpcode.statusReport.rawValue,
                payload: busyReport(waitMs: 0), counter: UInt32(700 + attempt)
            ))
        }
        let error = await #expect(throws: ControllerError.self) { _ = try await establishing.value }
        guard case .caseSessionFailed(let message)? = error else { Issue.record("unexpected \(String(describing: error))"); return }
        #expect(message.contains("after 3 attempts"))
        await rig.controller.stop()
    }
}
