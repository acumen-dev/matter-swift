// MultiInterfaceEndpointTests.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Testing
import MatterTestSupport
@testable import MatterTransport

private let peer = MatterAddress(host: "fd48::99", port: 5540)

private struct Rig {
    let capture = LogCapture()
    let link = FaultInjectingLink(seed: 1)
    let endpoint: MultiInterfaceEndpoint

    init(en0Reaches: Set<String> = ["fd48::99"], en1Reaches: Set<String> = ["fd48::99"], routeTable: String? = "en0") {
        endpoint = MultiInterfaceEndpoint(
            wrapping: link.a,
            interfaces: [
                .init(snapshot: InterfaceSnapshot(name: "en0", index: 7, isUp: true, addresses: ["fd48::a"]), reachable: en0Reaches),
                .init(snapshot: InterfaceSnapshot(name: "en1", index: 15, isUp: true, addresses: ["fd48::b"]), reachable: en1Reaches),
            ],
            routeTable: routeTable,
            logger: capture.logger(label: "test"))
    }
}

private let en0Path = MatterPath(interfaceIndex: 7, interfaceName: "en0", localAddress: "fd48::a")
private let en1Path = MatterPath(interfaceIndex: 15, interfaceName: "en1", localAddress: "fd48::b")

@Suite("MultiInterfaceEndpoint")
struct MultiInterfaceEndpointTests {
    @Test("A pinned send to a host the interface does not reach throws pathUnavailable")
    func pinnedUnreachable() async {
        let rig = Rig(en1Reaches: [])
        await #expect(throws: TransportPathError.pathUnavailable(en1Path, errno: EHOSTUNREACH)) {
            _ = try await rig.endpoint.send(Data([1]), to: peer, via: en1Path)
        }
        #expect(rig.endpoint.sends.isEmpty)
    }

    @Test("A pinned send by a down interface throws pathUnavailable")
    func pinnedDown() async {
        let rig = Rig()
        rig.endpoint.setInterface("en1", up: false)
        await #expect(throws: TransportPathError.pathUnavailable(en1Path, errno: EHOSTUNREACH)) {
            _ = try await rig.endpoint.send(Data([1]), to: peer, via: en1Path)
        }
    }

    @Test("A pinned send is recorded with its path and reports no selection")
    func pinnedRecorded() async throws {
        let rig = Rig()
        let result = try await rig.endpoint.send(Data([1]), to: peer, via: en1Path)
        #expect(result == MatterSendResult(path: en1Path, selection: nil))
        #expect(rig.endpoint.sends.map(\.path) == [en1Path])
        #expect(rig.link.sent(from: .a).count == 1)
    }

    @Test("Reachability is by canonicalised host, ignoring the port")
    func canonicalHost() async throws {
        let rig = Rig(en0Reaches: ["FD48:0:0:0:0:0:0:99"])
        let result = try await rig.endpoint.send(Data([1]), to: MatterAddress(host: "[fd48::99]", port: 1234), via: en0Path)
        #expect(result?.path == en0Path)
    }

    @Test("setArrival makes receiveDatagrams report that interface")
    func arrival() async throws {
        let rig = Rig()
        rig.endpoint.setArrival("en1")
        let stream = rig.endpoint.receiveDatagrams()
        try await rig.link.b.send(Data([9]), to: rig.link.a.address)
        var iterator = stream.makeAsyncIterator()
        let datagram = try #require(await iterator.next())
        #expect(datagram.path == en1Path)
        #expect(datagram.data == Data([9]))
        #expect(datagram.sender == rig.link.b.address)

        rig.endpoint.setArrival("en0")
        try await rig.link.b.send(Data([10]), to: rig.link.a.address)
        #expect(try #require(await iterator.next()).path == en0Path)
    }

    @Test("receiveDatagrams returns one stream: a second call's consumer does not end it")
    func sharedStream() async throws {
        let rig = Rig()
        do {
            var first = rig.endpoint.receiveDatagrams().makeAsyncIterator()
            try await rig.link.b.send(Data([1]), to: rig.link.a.address)
            _ = await first.next()
        }
        var second = rig.endpoint.receiveDatagrams().makeAsyncIterator()
        try await rig.link.b.send(Data([2]), to: rig.link.a.address)
        #expect(await second.next()?.data == Data([2]))
    }

    @Test("receive() yields (data, sender)")
    func legacyReceive() async throws {
        let rig = Rig()
        var it = rig.endpoint.receive().makeAsyncIterator()
        try await rig.link.b.send(Data([3]), to: rig.link.a.address)
        let (data, sender) = try #require(await it.next())
        #expect(data == Data([3]))
        #expect(sender == rig.link.b.address)
    }

    @Test("A policy naming a missing interface logs a warning")
    func missingWarns() async {
        let rig = Rig()
        await rig.endpoint.setInterfacePolicy(InterfacePolicy(preferred: ["en9"]))
        let warnings = rig.capture.entries(where: { $0.level == .warning })
        #expect(warnings.map(\.message) == ["Interface en9 named in the Matter interface policy is missing"])
        #expect(rig.endpoint.policy == InterfacePolicy(preferred: ["en9"]))
    }

    @Test("A preferred interface that goes down warns once and recovery logs info")
    func downAndRecovery() async throws {
        let rig = Rig()
        await rig.endpoint.setInterfacePolicy(InterfacePolicy(preferred: ["en1"]))
        rig.endpoint.setInterface("en1", up: false)
        _ = try await rig.endpoint.send(Data([1]), to: peer, via: nil)
        _ = try await rig.endpoint.send(Data([1]), to: peer, via: nil)
        #expect(rig.capture.entries(where: { $0.level == .warning }).map(\.message)
            == ["Interface en1 named in the Matter interface policy is down"])
        rig.endpoint.setInterface("en1", up: true)
        _ = try await rig.endpoint.send(Data([1]), to: peer, via: nil)
        #expect(rig.capture.entries(where: { $0.message == "Interface en1 named in the Matter interface policy is available again" }).count == 1)
    }

    @Test("Preferred order decides on first contact")
    func preferredOrder() async throws {
        let rig = Rig()
        await rig.endpoint.setInterfacePolicy(InterfacePolicy(preferred: ["en1", "en0"]))
        let result = try await rig.endpoint.send(Data([1]), to: peer, via: nil)
        #expect(result == MatterSendResult(path: en1Path, selection: .preferred))
        #expect(rig.endpoint.sends.map(\.path) == [en1Path])
    }

    @Test("Automatic policy uses the route table's interface")
    func routeTable() async throws {
        let rig = Rig(routeTable: "en1")
        let result = try await rig.endpoint.send(Data([1]), to: peer, via: nil)
        #expect(result == MatterSendResult(path: en1Path, selection: .routeTable))
    }

    @Test("Falls through when the preferred interface cannot reach the host, and says so")
    func fallthroughLogged() async throws {
        let rig = Rig(en1Reaches: [])
        await rig.endpoint.setInterfacePolicy(InterfacePolicy(preferred: ["en1"]))
        let result = try await rig.endpoint.send(Data([1]), to: peer, via: nil)
        #expect(result == MatterSendResult(path: en0Path, selection: .fallthrough))
        let info = rig.capture.entries(where: { $0.level == .info }).map(\.message)
        #expect(info == ["Path to fd48::99: en1 preferred, no route; using en0 (fd48::a)"])
    }

    @Test("An excluded interface is never chosen")
    func excluded() async throws {
        let rig = Rig(routeTable: "en0")
        await rig.endpoint.setInterfacePolicy(InterfacePolicy(excluded: ["en0"]))
        let result = try await rig.endpoint.send(Data([1]), to: peer, via: nil)
        #expect(result?.path == en1Path)

        rig.endpoint.setReachable("en1", [])
        await #expect(throws: TransportPathError.noAllowedRoute(peer: peer)) {
            _ = try await rig.endpoint.send(Data([1]), to: peer, via: nil)
        }
    }
}
