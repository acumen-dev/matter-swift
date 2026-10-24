// CASEBusyTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterProtocol
import MatterTransport
import MatterTestSupport
@testable import MatterController

/// The waits here are event-driven and a failed establishment ends them at once (see
/// `failFast`), so the limit is only a hang guard: five minutes, as for the branch's other
/// path suites, because on a loaded 2-CPU host a minute measures the host, not the code.
@Suite("CASE busy StatusReport", .timeLimit(.minutes(5)))
struct CASEBusyTests {

    /// An operation timeout no loaded host reaches, for the tests its value does not decide.
    static let patientTimeout: Duration = .seconds(600)

    private func busyReport(waitMs: UInt16?) -> Data {
        let data = waitMs.map { Data([UInt8($0 & 0xFF), UInt8($0 >> 8)]) }
        return StatusReportMessage(generalStatus: .busy, protocolID: 0, protocolStatus: 4, protocolData: data).encode()
    }

    @Test("A busy Sigma1 waits the stated time before a fresh Sigma1, then establishes")
    func waitsThenEstablishes() async throws {
        let clock = ManualClock()
        let (rig, fabric) = try await makeCASEControllerRig(operationTimeout: Self.patientTimeout, retryClock: clock, mrp: slowMRP)
        var peer = TestPeer(link: rig.link)
        var seen = Set<UInt32>()
        let node = rig.node
        let establishing = Task { try await rig.controller.session(for: node) }
        let watch = failFast(on: establishing, closing: rig.link)
        defer { watch.cancel() }
        let first = try await nextNewUnsecuredFrame(&peer, seen: &seen)
        #expect(first.exchangeHeader.protocolOpcode == SecureChannelOpcode.caseSigma1.rawValue)
        try await peer.send(ScriptedPeer.unsecuredReply(
            to: first, protocolID: .secureChannel, opcode: SecureChannelOpcode.statusReport.rawValue,
            payload: busyReport(waitMs: 2000), counter: 700
        ))
        try #require(await clock.waitForSleepers(1), "the controller never slept on the busy wait")
        #expect(clock.nextSleeperDeadline == clock.now + .seconds(2))
        #expect(rig.telemetry.counter("matter_case_busy_waits_total") == 1)
        let log = try #require(rig.telemetry.logs.entries.first { $0.message.contains("busy") })
        #expect(log.level == .info)
        #expect(log.metadata[MatterLogKey.node] == "0x42")

        // One millisecond short of the stated wait the controller is still asleep on the same deadline.
        let deadline = try #require(clock.nextSleeperDeadline)
        await clock.advance(by: .milliseconds(1999), awaitingRearm: false)
        #expect(clock.sleeperCount == 1)
        #expect(clock.nextSleeperDeadline == deadline)
        await clock.advance(by: .milliseconds(1), awaitingRearm: false)
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
        // 30 s, not patient: the 65.5 s wait must exceed it. The real-time margin left is the
        // first Sigma1's answer arriving within 30 s.
        let (rig, _) = try await makeCASEControllerRig(operationTimeout: .seconds(30), retryClock: clock, mrp: slowMRP)
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
        // It failed without ever sleeping, so it cannot have gone on to send a second Sigma1.
        #expect(clock.sleeperCount == 0)
        #expect(rig.telemetry.counter("matter_case_busy_waits_total") == 0)
        await rig.controller.stop()
    }

    @Test("Four busy answers give up after three waited retries")
    func fourBusyGiveUp() async throws {
        let clock = ManualClock()
        let (rig, _) = try await makeCASEControllerRig(operationTimeout: Self.patientTimeout, retryClock: clock, mrp: slowMRP)
        var peer = TestPeer(link: rig.link)
        var seen = Set<UInt32>()
        let node = rig.node
        let establishing = Task { try await rig.controller.session(for: node) }
        let watch = failFast(on: establishing, closing: rig.link)
        for attempt in 0..<4 {
            if attempt == 3 { watch.cancel() }                // the fourth answer ends it
            let sigma1 = try await nextNewUnsecuredFrame(&peer, seen: &seen)
            #expect(sigma1.exchangeHeader.protocolOpcode == SecureChannelOpcode.caseSigma1.rawValue)
            try await peer.send(ScriptedPeer.unsecuredReply(
                to: sigma1, protocolID: .secureChannel, opcode: SecureChannelOpcode.statusReport.rawValue,
                payload: busyReport(waitMs: 0), counter: UInt32(700 + attempt)
            ))
        }
        let error = await #expect(throws: ControllerError.self) { _ = try await establishing.value }
        guard case .caseSessionFailed(let message)? = error else { Issue.record("unexpected \(String(describing: error))"); return }
        #expect(message.contains("after 4 attempts"))
        #expect(rig.telemetry.counter("matter_case_busy_waits_total") == 3)
        await rig.controller.stop()
    }

    @Test("A busy report without a wait is a 0 ms wait, logged at debug")
    func missingWaitIsZero() async throws {
        for data in [nil, Data([0x05])] as [Data?] {
            let clock = ManualClock()
            let (rig, _) = try await makeCASEControllerRig(operationTimeout: Self.patientTimeout, retryClock: clock, mrp: slowMRP)
            var peer = TestPeer(link: rig.link)
            var seen = Set<UInt32>()
            let node = rig.node
            let establishing = Task { try await rig.controller.session(for: node) }
            let watch = failFast(on: establishing, closing: rig.link)
            let first = try await nextNewUnsecuredFrame(&peer, seen: &seen)
            let report = StatusReportMessage(generalStatus: .busy, protocolID: 0, protocolStatus: 4, protocolData: data).encode()
            try await peer.send(ScriptedPeer.unsecuredReply(
                to: first, protocolID: .secureChannel, opcode: SecureChannelOpcode.statusReport.rawValue,
                payload: report, counter: 700
            ))
            let second = try await nextNewUnsecuredFrame(&peer, seen: &seen)
            #expect(second.exchangeHeader.protocolOpcode == SecureChannelOpcode.caseSigma1.rawValue)
            #expect(rig.telemetry.counter("matter_case_busy_waits_total") == 1)
            let log = try #require(rig.telemetry.logs.entries.first { $0.message.contains("without a minimum wait") })
            #expect(log.level == .debug)
            #expect(log.metadata[MatterLogKey.node] == "0x42")
            #expect(rig.telemetry.logs.entries.contains { $0.message.hasPrefix("Node busy; retrying CASE in 0 ms") })
            watch.cancel()
            establishing.cancel()
            await rig.controller.stop()
        }
    }

    @Test("A busy status in another protocol is not a busy answer")
    func otherProtocolIsNotBusy() async throws {
        let clock = ManualClock()
        let (rig, _) = try await makeCASEControllerRig(operationTimeout: Self.patientTimeout, retryClock: clock, mrp: slowMRP)
        var peer = TestPeer(link: rig.link)
        var seen = Set<UInt32>()
        let node = rig.node
        let establishing = Task { try await rig.controller.session(for: node) }
        let first = try await nextNewUnsecuredFrame(&peer, seen: &seen)
        try await peer.send(ScriptedPeer.unsecuredReply(
            to: first, protocolID: .secureChannel, opcode: SecureChannelOpcode.statusReport.rawValue,
            payload: StatusReportMessage(generalStatus: .busy, protocolID: 1, protocolStatus: 4, protocolData: Data([0, 1])).encode(),
            counter: 700
        ))
        let error = await #expect(throws: ControllerError.self) { _ = try await establishing.value }
        guard case .caseSessionFailed? = error else { Issue.record("unexpected \(String(describing: error))"); return }
        #expect(clock.sleeperCount == 0)
        #expect(rig.telemetry.counter("matter_case_busy_waits_total") == 0)
        await rig.controller.stop()
    }

    @Test("The busy budget is shared by the first attempt and the post-refresh attempt")
    func budgetSharedAcrossRefresh() async throws {
        let clock = ManualClock()
        let moved = MatterAddress(host: "10.0.0.2", port: 5540)
        let stale = MatterAddress(host: "10.0.0.9", port: 5540)
        let discovery = InMemoryDiscovery { _ in moved }
        let fabric = try makeTestFabric()
        let endpoint = LockedValue<MultiInterfaceEndpoint?>(nil)
        // A single-interface fake that reaches both addresses until the test says otherwise:
        // the retry is made to find no route (nothing answered, at once) instead of waiting
        // out a real-clock MRP give-up, so no answer here races retransmission.
        let rig = try await makeControllerRig(
            mrp: slowMRP, discovery: discovery, installSession: false, deviceAddress: stale,
            fabricManager: fabric.manager,
            transport: { link, logger in
                let fake = MultiInterfaceEndpoint(
                    wrapping: link.a,
                    interfaces: [.init(
                        snapshot: InterfaceSnapshot(name: "en0", index: 7, isUp: true, addresses: ["fd48::a"]),
                        reachable: [moved.host, stale.host]
                    )],
                    routeTable: "en0",
                    logger: logger
                )
                endpoint.withLock { $0 = fake }
                return fake
            },
            operationTimeout: .seconds(30), retryClock: clock
        )
        let fake = try #require(endpoint.withLock { $0 })
        let name = OperationalInstanceName(
            compressedFabricID: await rig.controller.compressedFabricIDForTesting, nodeID: rig.node.rawValue
        ).instanceName
        try await discovery.advertise(service: MatterServiceRecord(name: name, serviceType: .operational, host: "10.0.0.2", port: 5540))
        var peer = TestPeer(link: rig.link)
        var seen = Set<UInt32>()
        let node = rig.node
        let establishing = Task { try await rig.controller.session(for: node) }
        let watch = failFast(on: establishing, closing: rig.link)

        // First attempt: busy for 1 s, waited out.
        let first = try await nextNewUnsecuredFrame(&peer, seen: &seen)
        try await peer.send(ScriptedPeer.unsecuredReply(
            to: first, protocolID: .secureChannel, opcode: SecureChannelOpcode.statusReport.rawValue,
            payload: busyReport(waitMs: 1000), counter: 700
        ), from: stale)
        try #require(await clock.waitForSleepers(1), "the controller never slept on the busy wait")

        // The retry finds no route to the stale address (nothing answered), the address is
        // re-resolved, and the post-refresh attempt is answered busy again: 29.5 s would fit
        // a fresh 30 s budget but not what is left of the shared one.
        fake.setReachable("en0", [moved.host])
        await clock.advance(by: .seconds(1), awaitingRearm: false)
        let refreshed = try await nextNewUnsecuredFrame(&peer, seen: &seen)
        #expect(refreshed.exchangeHeader.protocolOpcode == SecureChannelOpcode.caseSigma1.rawValue)
        let sigma1Destinations = fake.sends.filter {
            (try? ScriptedPeer.decodeUnsecured($0.data).exchangeHeader.protocolOpcode) == SecureChannelOpcode.caseSigma1.rawValue
        }.map(\.to)
        #expect(sigma1Destinations == [stale, moved], "one Sigma1 left for the stale address (the retry found no route), one for the re-resolved one")
        watch.cancel()
        try await peer.send(ScriptedPeer.unsecuredReply(
            to: refreshed, protocolID: .secureChannel, opcode: SecureChannelOpcode.statusReport.rawValue,
            payload: busyReport(waitMs: 29_500), counter: 701
        ))
        let error = await #expect(throws: ControllerError.self) { _ = try await establishing.value }
        guard case .caseSessionFailed(let message)? = error else { Issue.record("unexpected \(String(describing: error))"); return }
        #expect(message.contains("asked to wait 29500 ms"))
        #expect(rig.telemetry.counter("matter_case_busy_waits_total") == 1)
        #expect(clock.sleeperCount == 0)
        await rig.controller.stop()
    }
}
