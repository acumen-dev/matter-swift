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

    @Test("Loopback send and receive")
    func loopbackSendReceive() async throws {
        // Bind receiver on known port
        let receiver = AppleUDPTransport()
        try await receiver.bind(port: 5541)

        // Bind sender on ephemeral port
        let sender = AppleUDPTransport()
        try await sender.bind(port: 0)

        let testData = Data([0x01, 0x02, 0x03, 0x04])
        let address = MatterAddress(host: "127.0.0.1", port: 5541)

        // Send from sender to receiver
        try await sender.send(testData, to: address)

        // Listen for data on receiver
        let stream = receiver.receive()
        let received = await withTaskGroup(of: Data?.self) { group in
            group.addTask {
                for await (data, _) in stream {
                    return data
                }
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

        // Clean up
        await receiver.close()
        await sender.close()

        #expect(received == testData)
    }

    @Test("Close finishes receive stream")
    func closeFinishesStream() async throws {
        let transport = AppleUDPTransport()
        try await transport.bind(port: 0)

        let stream = transport.receive()
        await transport.close()

        // Stream should finish after close
        var count = 0
        for await _ in stream {
            count += 1
        }
        #expect(count == 0)
    }
}
