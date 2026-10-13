// DeviceLinkFixtures.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel
import MatterProtocol
import MatterTransport
import MatterController
import MatterDevice
import MatterTestSupport

// Shared rig for suites that drive a MatterController against a
// MatterDeviceServer over a FaultInjectingLink.

let passcode: UInt32 = 20202021

/// Short intervals keep lossy runs quick (values are illustrative, not
/// spec). With 4 retransmissions a silent peer exhausts after ≈ 3.5–4.3 s,
/// comfortably above a debug build's handshake processing time, even
/// under linux/amd64 emulation.
let fast = MRPParameters(
    sessionIdleInterval: .milliseconds(200),
    sessionActiveInterval: .milliseconds(200),
    sessionActiveThreshold: .milliseconds(4000)
)

/// `discovery` is where the device advertises; share one `InMemoryDiscovery`
/// with the controller so it can find the device. The default advertises nowhere.
func startServer(
    on link: FaultInjectingLink,
    toggles: LockedValue<Int>,
    discovery: any MatterDiscovery = FaultyLinkDiscovery()
) async throws -> (MatterDeviceServer, BridgedEndpoint) {
    let bridge = MatterBridge()
    let light = bridge.addDimmableLight(name: "Faulty Light", onOffChanged: { _ in
        toggles.withLock { $0 += 1 }
    })
    let server = MatterDeviceServer(
        bridge: bridge,
        transport: link.b,
        discovery: discovery,
        config: .init(
            discriminator: 3840,
            passcode: passcode,
            port: 5540,
            salt: Data(repeating: 0xAB, count: 32),
            iterations: 1000
        )
    )
    try await server.start()
    return (server, light)
}

func makeController(
    on link: FaultInjectingLink,
    maxRetransmissions: Int,
    discovery: any MatterDiscovery = FaultyLinkDiscovery(),
    store: (any MatterControllerStore)? = nil
) throws -> MatterController {
    try MatterController(
        transport: link.a,
        discovery: discovery,
        configuration: .init(
            fabricID: FabricID(rawValue: 1),
            mrp: MRPConfig(maxRetransmissions: maxRetransmissions)
        ),
        store: store
    )
}

/// Discovery is not exercised: the link carries addresses directly.
struct FaultyLinkDiscovery: MatterDiscovery {
    func advertise(service: MatterServiceRecord) async throws {}
    func browse(serviceType: ServiceType) -> AsyncStream<MatterServiceRecord> {
        AsyncStream { $0.finish() }
    }
    func resolve(_ record: MatterServiceRecord) async throws -> MatterAddress {
        throw FaultyLinkDiscoveryError.notAvailable
    }
    func stopAdvertising() async {}
}

enum FaultyLinkDiscoveryError: Error {
    case notAvailable
}
