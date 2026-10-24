// PathSelectorTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
@testable import MatterTransport

private let en0 = InterfaceSnapshot(name: "en0", index: 7, isUp: true, addresses: ["fd48::a"])
private let en1 = InterfaceSnapshot(name: "en1", index: 15, isUp: true, addresses: ["fd48::b"])
private func routes(_ map: [String: String], table: String?) -> (InterfaceSnapshot?) -> (index: UInt32, source: String)? {
    { iface in
        guard let iface else {
            guard let table, let s = map[table] else { return nil }
            return (table == "en0" ? 7 : 15, s)
        }
        return map[iface.name].map { (iface.index, $0) }
    }
}

@Suite("PathSelector")
struct PathSelectorTests {
    @Test("Automatic uses the route table's choice")
    func automatic() {
        let s = PathSelector(policy: .automatic).select(interfaces: [en0, en1], route: routes(["en0": "fd48::a"], table: "en0"))
        #expect(s.path == MatterPath(interfaceIndex: 7, interfaceName: "en0", localAddress: "fd48::a"))
        #expect(s.outcome == .routeTable)
    }

    @Test("The first preferred interface with a route wins")
    func preferred() {
        let s = PathSelector(policy: .init(preferred: ["en1", "en0"]))
            .select(interfaces: [en0, en1], route: routes(["en0": "fd48::a", "en1": "fd48::b"], table: "en0"))
        #expect(s.path?.interfaceName == "en1")
        #expect(s.outcome == .preferred)
    }

    @Test("A preferred interface with no route falls through, and says why")
    func fallsThrough() {
        let s = PathSelector(policy: .init(preferred: ["en1", "en0"]))
            .select(interfaces: [en0, en1], route: routes(["en0": "fd48::a"], table: "en0"))
        #expect(s.path?.interfaceName == "en0")
        #expect(s.outcome == .`fallthrough`)
        #expect(s.skipped.map(\.name) == ["en1"])
        #expect(s.skipped.first?.reason == .noRoute)
    }

    @Test("An excluded interface is never chosen, even as the route table's choice")
    func excluded() {
        let s = PathSelector(policy: .init(excluded: ["en0"]))
            .select(interfaces: [en0, en1], route: routes(["en0": "fd48::a", "en1": "fd48::b"], table: "en0"))
        #expect(s.path?.interfaceName == "en1")
        let none = PathSelector(policy: .init(excluded: ["en0"]))
            .select(interfaces: [en0, en1], route: routes(["en0": "fd48::a"], table: "en0"))
        #expect(none.path == nil)
    }

    @Test("Missing and down preferred interfaces are skipped with their reason")
    func missingAndDown() {
        var down1 = en1; down1.isUp = false
        let s = PathSelector(policy: .init(preferred: ["en9", "en1", "en0"]))
            .select(interfaces: [en0, down1], route: routes(["en0": "fd48::a", "en1": "fd48::b"], table: "en0"))
        #expect(s.path?.interfaceName == "en0")
        #expect(s.skipped.map(\.reason) == [.missing, .down])
    }

    @Test("The monitor reports each named interface's problem once, and its recovery")
    func monitor() {
        var m = InterfacePolicyMonitor(policy: .init(preferred: ["en1"], excluded: ["en9"]))
        var down1 = en1; down1.isUp = false
        #expect(m.update([en0, down1]).map(\.name).sorted() == ["en1", "en9"])
        #expect(m.update([en0, down1]).isEmpty)
        let recovered = m.update([en0, en1])
        #expect(recovered.count == 1 && recovered[0].name == "en1" && recovered[0].problem == nil)
    }
}
