// DiscoveryTelemetryTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Tracing
import InMemoryTracing
import MatterTypes
import MatterProtocol
import MatterTransport
import MatterTestSupport
@testable import MatterController

@Suite("Controller discovery telemetry", .timeLimit(.minutes(1)))
struct DiscoveryTelemetryTests {

    private func advertise(_ discovery: InMemoryDiscovery, rig: ControllerRig, host: String) async throws {
        let name = OperationalInstanceName(
            compressedFabricID: await rig.controller.compressedFabricIDForTesting, nodeID: rig.node.rawValue
        ).instanceName
        try await discovery.advertise(service: MatterServiceRecord(name: name, serviceType: .operational, host: host, port: 5540))
    }

    @Test("discoverDevice: resolve start and result at debug, inside a matter.resolve span")
    func resolveObserved() async throws {
        let resolved = MatterAddress(host: "10.0.0.2", port: 5540)
        let discovery = InMemoryDiscovery { _ in resolved }
        let rig = try await makeControllerRig(discovery: discovery)
        try await advertise(discovery, rig: rig, host: "10.0.0.2")

        let found = try await rig.controller.discoverDevice(nodeID: rig.node)
        #expect(found.address == resolved)

        let start = try #require(rig.telemetry.logs.entries.first { $0.message.hasPrefix("mDNS resolve start") })
        #expect(start.level == .debug)
        #expect(start.subsystem == "discovery")
        #expect(start.metadata[MatterLogKey.node] == "0x42")
        let result = try #require(rig.telemetry.logs.entries.first { $0.message.hasPrefix("mDNS resolve result") })
        #expect(result.message.hasPrefix("mDNS resolve result: 10.0.0.2:5540"))
        let span = try #require(rig.telemetry.finishedSpans(named: "matter.resolve").first)
        #expect(span.attributes.get(MatterLogKey.node) == .string("0x42"))
        let instance = OperationalInstanceName(
            compressedFabricID: await rig.controller.compressedFabricIDForTesting, nodeID: rig.node.rawValue
        ).instanceName
        #expect(span.attributes.get(MatterLogKey.instance) == .string(instance))
        #expect(span.status?.code != .error)
        await rig.controller.stop()
    }

    @Test("A node that moved: CASE gets no answer, the re-resolve finds it elsewhere, and the change is logged old → new at info")
    func addressChange() async throws {
        let moved = MatterAddress(host: "10.0.0.2", port: 5540)
        let stale = MatterAddress(host: "10.0.0.9", port: 5540)
        let discovery = InMemoryDiscovery { _ in moved }
        let rig = try await makeControllerRig(mrp: fastMRP, discovery: discovery, installSession: false, deviceAddress: stale)
        try await advertise(discovery, rig: rig, host: "10.0.0.2")
        rig.link.setInterceptor { _, _ in .drop }        // nothing answers, at either address
        let node = rig.node

        await #expect(throws: ControllerError.peerUnreachable(node)) { _ = try await rig.controller.session(for: node) }

        let changed = try #require(rig.telemetry.logs.entries.first { $0.message.hasPrefix("Operational address changed") })
        #expect(changed.level == .info)
        #expect(changed.subsystem == "discovery")
        #expect(changed.message == "Operational address changed: 10.0.0.9:5540 → 10.0.0.2:5540")
        #expect(changed.metadata[MatterLogKey.node] == "0x42")
        #expect(rig.telemetry.logs.entries.filter { $0.message.hasPrefix("Peer unreachable") }.count == 2)
        #expect(rig.telemetry.counter("matter_sessions_established_total", [("type", "case"), ("outcome", "unreachable")]) == 1)
        let caseSpan = try #require(rig.telemetry.finishedSpans(named: "matter.case").first)
        let resolveSpan = try #require(rig.telemetry.finishedSpans(named: "matter.resolve").first)
        #expect(resolveSpan.parentSpanID == caseSpan.spanID)
        #expect(await rig.controller.device(for: node)?.operationalAddress == moved)
        await rig.controller.stop()
    }

    @Test("MatterLogValue.address brackets an IPv6 host once, whether or not it arrived bracketed")
    func addressBrackets() {
        #expect(MatterLogValue.address(MatterAddress(host: "fd00::1", port: 5540)) == "[fd00::1]:5540")
        #expect(MatterLogValue.address(MatterAddress(host: "[fd00::1]", port: 5540)) == "[fd00::1]:5540")
        #expect(MatterLogValue.address(MatterAddress(host: "10.0.0.2", port: 5540)) == "10.0.0.2:5540")
    }
}
