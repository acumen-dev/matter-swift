// AppleUDPTransportTests.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(Network)
import Testing
import Foundation
import MatterApple
import MatterTransport

// Network tests are serialized: they bind real sockets and using SO_REUSEPORT
// means fixed-port tests can share a socket with a concurrent test, causing
// the expected packet to be delivered to the wrong consumer. Waits for a
// datagram have no deadline of their own: the time limit is the hang guard.
@Suite("AppleUDPTransport", .serialized, .timeLimit(.minutes(1)))
struct AppleUDPTransportTests {

    /// The first datagram `transport` receives (no deadline: the suite's
    /// time limit cancels the wait, and nil is returned).
    private static func firstDatagram(_ transport: AppleUDPTransport) async -> (Data, MatterAddress)? {
        for await datagram in transport.receive() { return datagram }
        return nil
    }

    @Test("Bind to ephemeral port and close")
    func bindAndClose() async throws {
        let transport = AppleUDPTransport()
        try await transport.bind(port: 0)
        await transport.close()
    }

    @Test("IPv6 loopback send and receive (::1)")
    func ipv6LoopbackLoopbackSendReceive() async throws {
        let receiver = AppleUDPTransport()
        try await receiver.bind(port: 0)                          // ephemeral
        let receiverPort = await receiver.boundPort() ?? 5541

        let sender = AppleUDPTransport()
        try await sender.bind(port: 0)

        let testData = Data([0x01, 0x02, 0x03, 0x04])
        // AppleUDPTransport is IPv6-only — use ::1 for loopback
        let address = MatterAddress(host: "::1", port: receiverPort)

        try await sender.send(testData, to: address)

        let received = await Self.firstDatagram(receiver)?.0

        await receiver.close()
        await sender.close()

        #expect(received == testData)
    }

    @Test("A bracketed IPv6 host (\"[::1]\", the URL-host form discovery returns) is sent to")
    func bracketedIPv6Send() async throws {
        let receiver = AppleUDPTransport()
        try await receiver.bind(port: 0)
        let receiverPort = try #require(await receiver.boundPort())

        let sender = AppleUDPTransport()
        try await sender.bind(port: 0)

        let testData = Data([0x5B, 0x3A, 0x3A, 0x31, 0x5D])
        try await sender.send(testData, to: MatterAddress(host: "[::1]", port: receiverPort))

        let received = await Self.firstDatagram(receiver)?.0

        await receiver.close()
        await sender.close()

        #expect(received == testData)
    }

    @Test("IPv6 loopback send and receive")
    func ipv6LoopbackSendReceive() async throws {
        let receiver = AppleUDPTransport()
        try await receiver.bind(port: 0)                          // ephemeral
        let receiverPort = await receiver.boundPort() ?? 5542

        let sender = AppleUDPTransport()
        try await sender.bind(port: 0)

        let testData = Data([0xAA, 0xBB, 0xCC, 0xDD])
        // Native IPv6 loopback
        let address = MatterAddress(host: "::1", port: receiverPort)

        try await sender.send(testData, to: address)

        let received = await Self.firstDatagram(receiver)

        await receiver.close()
        await sender.close()

        #expect(received?.0 == testData)
        // Sender address should be presented as ::1 (not IPv4-mapped)
        #expect(received?.1.host == "::1")
    }

    @Test("Close finishes receive stream")
    func closeFinishesStream() async throws {
        let transport = AppleUDPTransport()
        try await transport.bind(port: 0)

        let stream = transport.receive()
        await transport.close()

        var count = 0
        for await _ in stream {
            count += 1
        }
        #expect(count == 0)
    }

    @Test("Invalid host throws invalidAddress error")
    func invalidHostThrows() async throws {
        let transport = AppleUDPTransport()
        try await transport.bind(port: 0)
        defer { Task { await transport.close() } }

        await #expect(throws: (any Error).self) {
            try await transport.send(Data([0x01]), to: MatterAddress(host: "not-an-ip", port: 1234))
        }
    }
}
#endif
