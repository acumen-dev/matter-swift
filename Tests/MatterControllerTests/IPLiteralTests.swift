// IPLiteralTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import MatterTransport

/// One address, one text: the controller keys exchanges by host string, and
/// the transports report a sender in `inet_ntop`'s canonical form.
@Suite("MatterAddress IP literals")
struct IPLiteralTests {

    @Test(
        "ipLiteral returns the canonical form of an IP literal",
        arguments: [
            ("[fd00:0:0:0:0:0:0:5]", "fd00::5"),
            ("FD00::0005", "fd00::5"),
            ("0:0:0:0:0:0:0:1", "::1"),
            ("[::1]", "::1"),
            ("fd00::5", "fd00::5"),
            ("192.0.2.10", "192.0.2.10"),
            ("127.0.0.1", "127.0.0.1"),
        ]
    )
    func canonicalLiteral(host: String, expected: String) {
        #expect(MatterAddress.ipLiteral(host) == expected)
    }

    @Test(
        "ipLiteral rejects a host name, an IPv6 zone and anything not a literal",
        arguments: ["fe80::1%en0", "[fe80::1%en0]", "fe80::1%", "device.local", "", "[]", "192.0.2", "fd00::5]"]
    )
    func notALiteral(host: String) {
        #expect(MatterAddress.ipLiteral(host) == nil)
    }

    @Test("withIPLiteralHost keeps the port and canonicalises the host")
    func withIPLiteralHost() {
        #expect(MatterAddress(host: "[FD00:0:0:0:0:0:0:5]", port: 5540).withIPLiteralHost
            == MatterAddress(host: "fd00::5", port: 5540))
        #expect(MatterAddress(host: "fe80::1%en0", port: 5540).withIPLiteralHost == nil)
    }

    @Test(
        "canonicalised: an IP literal in canonical form, its zone kept; anything else unchanged",
        arguments: [
            ("[fd00:0:0:0:0:0:0:5]", "fd00::5"),
            ("0:0:0:0:0:0:0:1", "::1"),
            ("192.0.2.10", "192.0.2.10"),
            ("FE80::0001%en0", "fe80::1%en0"),
            ("device.local", "device.local"),
            ("[device.local]", "[device.local]"),
        ]
    )
    func canonicalised(host: String, expected: String) {
        #expect(MatterAddress(host: host, port: 5540).canonicalised == MatterAddress(host: expected, port: 5540))
    }
}
