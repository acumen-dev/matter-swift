// IPv6LoopbackCommissioningTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterModel
import MatterProtocol
import MatterTransport
import MatterController
import MatterDevice
import MatterTestSupport
#if os(Linux)
import MatterLinux
#else
import MatterApple
#endif

/// Controller ↔ MatterDeviceServer over the platform UDP transport on the IPv6
/// loopback. The platform transports report a datagram's sender in
/// `inet_ntop`'s canonical form (`"::1"`); the controller is handed the same
/// address in another text, as discovery on Linux used to produce it. Every
/// reply used to be dropped as a message for a closed exchange.
@Suite(
    "Commissioning over the IPv6 loopback",
    .serialized,
    .timeLimit(.minutes(3)),
    .enabled(if: IPv6Loopback.isAvailable, "this host has no IPv6 loopback")
)
struct IPv6LoopbackCommissioningTests {

    static func makeTransport() -> any MatterUDPTransport {
        #if os(Linux)
        LinuxUDPTransport()
        #else
        AppleUDPTransport()
        #endif
    }

    static func boundPort(_ transport: any MatterUDPTransport) async -> UInt16? {
        #if os(Linux)
        await (transport as? LinuxUDPTransport)?.boundPort()
        #else
        await (transport as? AppleUDPTransport)?.boundPort()
        #endif
    }

    @Test(
        "commission(address:) given the loopback in non-canonical text completes PASE, CASE and an IM read",
        arguments: ["0:0:0:0:0:0:0:1", "[0:0:0:0:0:0:0:1]", "0000::0001"]
    )
    func commissionOverNonCanonicalLoopback(host: String) async throws {
        let bridge = MatterBridge()
        let light = bridge.addDimmableLight(name: "Loopback Light")
        let deviceTransport = Self.makeTransport()
        let server = MatterDeviceServer(
            bridge: bridge,
            transport: deviceTransport,
            discovery: FaultyLinkDiscovery(),
            config: .init(
                discriminator: 3840,
                passcode: passcode,
                port: 0,
                salt: Data(repeating: 0xAB, count: 32),
                iterations: 1000
            )
        )
        try await server.start()
        let controllerTransport = Self.makeTransport()
        var started: MatterController?

        do {
            try await controllerTransport.bind(port: 0)
            // `patient` with 2 retransmissions: a silent device exhausts after
            // ≈ 28–36 s, a hang guard, never waited on by a passing run.
            let controller = try MatterController(
                transport: controllerTransport,
                discovery: FaultyLinkDiscovery(),
                configuration: .init(fabricID: FabricID(rawValue: 1), mrp: MRPConfig(maxRetransmissions: 2))
            )
            started = controller
            let port = try #require(await Self.boundPort(deviceTransport))
            let device = try await controller.commission(address: MatterAddress(host: host, port: port), setupCode: passcode, mrp: patient)
            #expect(device.operationalAddress == MatterAddress(host: "::1", port: port))

            let onOff = try await controller.readAttribute(
                nodeID: device.nodeID, endpointID: light.endpointID,
                clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff
            )
            #expect(onOff.boolValue == false)
        } catch {
            await started?.stop(); await server.stop(); await controllerTransport.close()
            throw error
        }
        await started?.stop(); await server.stop(); await controllerTransport.close()
    }
}
