// POSIXUDPSocketCoreTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Logging
import MatterTransport
import MatterTestSupport
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

#if canImport(Darwin) || canImport(Glibc)

fileprivate let loopbackName: String = {
    #if canImport(Darwin)
    "lo0"
    #else
    "lo"
    #endif
}()

fileprivate let loopbackIndex = UInt32(if_nametoindex(loopbackName))

/// Network tests bind real sockets; serialised so no two share a port. Waits
/// for a datagram have no deadline of their own: the time limit is the hang guard.
@Suite("POSIXUDPSocketCore", .serialized, .timeLimit(.minutes(2)))
struct POSIXUDPSocketCoreTests {

    private static func bound(_ logger: Logger = Logger(label: "test.udp")) throws -> POSIXUDPSocketCore {
        let core = POSIXUDPSocketCore(logger: logger)
        try core.bind(port: 0)
        return core
    }

    /// The first datagram `core` receives (nil when the stream ends first).
    private static func firstDatagram(_ core: POSIXUDPSocketCore) async -> MatterDatagram? {
        for await datagram in core.datagrams { return datagram }
        return nil
    }

    @Test(
        "A selected send returns the path and leaves from the bound port",
        .enabled(if: IPv6Loopback.isAvailable, "this host has no IPv6 loopback")
    )
    func selectedSend() async throws {
        let rx = try Self.bound()
        let tx = try Self.bound()
        defer { rx.close(); tx.close() }
        let rxPort = try #require(rx.boundPort)

        let result = try tx.send(Data([1, 2, 3]), to: MatterAddress(host: "::1", port: rxPort), via: nil)
        #expect(result.path.interfaceName == loopbackName)
        #expect(result.path.interfaceIndex == loopbackIndex)
        #expect(result.path.localAddress == "::1")
        #expect(result.selection == .routeTable)

        let datagram = try #require(await Self.firstDatagram(rx))
        #expect(datagram.data == Data([1, 2, 3]))
        #expect(datagram.sender.port == tx.boundPort)
        #expect(datagram.path?.localAddress == "::1")
        #expect(datagram.path?.interfaceName == loopbackName)
    }

    @Test(
        "A pinned send uses the pinned path",
        .enabled(if: IPv6Loopback.isAvailable, "this host has no IPv6 loopback")
    )
    func pinnedSend() async throws {
        let rx = try Self.bound()
        let tx = try Self.bound()
        defer { rx.close(); tx.close() }
        let peer = MatterAddress(host: "::1", port: try #require(rx.boundPort))

        let first = try tx.send(Data([1]), to: peer, via: nil)
        _ = await Self.firstDatagram(rx)

        let pinned = try tx.send(Data([2]), to: peer, via: first.path)
        #expect(pinned.path == first.path)
        #expect(pinned.selection == nil)

        let datagram = try #require(await Self.firstDatagram(rx))
        #expect(datagram.data == Data([2]))
        #expect(datagram.sender.port == tx.boundPort)
        #expect(datagram.path?.localAddress == "::1")
    }

    @Test(
        "A pinned path with an address not on the host fails as pathUnavailable",
        .enabled(if: IPv6Loopback.isAvailable, "this host has no IPv6 loopback")
    )
    func pinnedPathUnavailable() async throws {
        let rx = try Self.bound()
        let tx = try Self.bound()
        defer { rx.close(); tx.close() }
        let path = MatterPath(interfaceIndex: loopbackIndex, interfaceName: loopbackName, localAddress: "fd00:dead::1")

        #expect(throws: TransportPathError.pathUnavailable(path, errno: EADDRNOTAVAIL)) {
            try tx.send(Data([1]), to: MatterAddress(host: "::1", port: try #require(rx.boundPort)), via: path)
        }
    }

    @Test(
        "Excluding loopback leaves no route to ::1",
        .enabled(if: IPv6Loopback.isAvailable, "this host has no IPv6 loopback")
    )
    func excludedLoopback() async throws {
        let rx = try Self.bound()
        let tx = try Self.bound()
        defer { rx.close(); tx.close() }
        tx.setPolicy(InterfacePolicy(excluded: [loopbackName]))
        let peer = MatterAddress(host: "::1", port: try #require(rx.boundPort))

        #expect(throws: TransportPathError.noAllowedRoute(peer: peer)) {
            try tx.send(Data([1]), to: peer, via: nil)
        }
    }

    @Test("A named interface that does not exist is logged at warning on apply")
    func missingInterfaceWarns() throws {
        let capture = LogCapture()
        let core = try Self.bound(capture.logger(label: "test.udp"))
        defer { core.close() }

        core.setPolicy(InterfacePolicy(preferred: ["nosuch0"]))

        let warnings = capture.entries(where: { $0.level == .warning })
        #expect(warnings.count == 1)
        #expect(warnings.first?.message.contains("nosuch0") == true)
        #expect(warnings.first?.message.contains("missing") == true)
    }

    @Test("Closing wakes both blocked receive threads and finishes the stream")
    func closeEndsReceiveThreads() async throws {
        let capture = LogCapture()
        let core = try Self.bound(capture.logger(label: "test.udp"))
        // Let both threads block in recvmsg before closing.
        try await Task.sleep(for: .milliseconds(100))

        core.close()

        for name in ["matter.udp.recv6", "matter.udp.recv4"] {
            _ = try await capture.first { $0.message.contains("UDP receive loop ended") && $0.message.contains(name) }
        }
        #expect(await Self.firstDatagram(core) == nil)
    }

    @Test(
        "IPv4 and IPv6 share one port when bound to 0",
        .enabled(if: IPv6Loopback.isAvailable, "this host has no IPv6 loopback")
    )
    func sharedPort() async throws {
        let rx6 = try Self.bound()
        let rx4 = try Self.bound()
        let tx = try Self.bound()
        defer { rx6.close(); rx4.close(); tx.close() }
        let txPort = try #require(tx.boundPort)

        _ = try tx.send(Data([6]), to: MatterAddress(host: "::1", port: try #require(rx6.boundPort)), via: nil)
        _ = try tx.send(Data([4]), to: MatterAddress(host: "127.0.0.1", port: try #require(rx4.boundPort)), via: nil)

        let v6 = try #require(await Self.firstDatagram(rx6))
        let v4 = try #require(await Self.firstDatagram(rx4))
        #expect(v6.sender.port == txPort)
        #expect(v4.sender.port == txPort)
        #expect(v4.sender.host == "127.0.0.1")
        #expect(v4.path?.localAddress == "127.0.0.1")
    }
}

#endif
