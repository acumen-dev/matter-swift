// AppleUDPTransportTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterApple
import MatterTransport

@Suite("AppleUDPTransport")
struct AppleUDPTransportTests {

    @Test("Bind to ephemeral port and close")
    func bindAndClose() async throws {
        let transport = AppleUDPTransport()
        try await transport.bind(port: 0)
        await transport.close()
    }

    @Test("IPv4 loopback send and receive via IPv4-mapped socket")
    func ipv4LoopbackSendReceive() async throws {
        let receiver = AppleUDPTransport()
        try await receiver.bind(port: 5541)

        let sender = AppleUDPTransport()
        try await sender.bind(port: 0)

        let testData = Data([0x01, 0x02, 0x03, 0x04])
        // IPv4 address — transport converts to ::ffff:127.0.0.1 internally
        let address = MatterAddress(host: "127.0.0.1", port: 5541)

        try await sender.send(testData, to: address)

        let stream = receiver.receive()
        let received = await withTaskGroup(of: Data?.self) { group in
            group.addTask {
                for await (data, _) in stream { return data }
                return nil
            }
            group.addTask {
                try? await Task.sleep(for: .seconds(2))
                return nil
            }
            let result = await group.next()!
            group.cancelAll()
            return result
        }

        await receiver.close()
        await sender.close()

        #expect(received == testData)
    }

    @Test("IPv6 loopback send and receive")
    func ipv6LoopbackSendReceive() async throws {
        let receiver = AppleUDPTransport()
        try await receiver.bind(port: 5542)

        let sender = AppleUDPTransport()
        try await sender.bind(port: 0)

        let testData = Data([0xAA, 0xBB, 0xCC, 0xDD])
        // Native IPv6 loopback
        let address = MatterAddress(host: "::1", port: 5542)

        try await sender.send(testData, to: address)

        let stream = receiver.receive()
        let received = await withTaskGroup(of: (Data, MatterAddress)?.self) { group in
            group.addTask {
                for await pair in stream { return pair }
                return nil
            }
            group.addTask {
                try? await Task.sleep(for: .seconds(2))
                return nil
            }
            let result = await group.next()!
            group.cancelAll()
            return result
        }

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
