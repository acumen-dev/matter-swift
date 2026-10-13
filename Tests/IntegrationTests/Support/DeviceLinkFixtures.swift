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
/// spec). A silent peer then exhausts in seconds, which is what a phase
/// testing silence wants, but not enough for the PASE handshake: commission
/// with `patient`, or give `fast` `handshakeRetransmissions`.
let fast = MRPParameters(
    sessionIdleInterval: .milliseconds(200),
    sessionActiveInterval: .milliseconds(200),
    sessionActiveThreshold: .milliseconds(4000)
)

/// Commissioning timing for suites that are not testing loss during the
/// handshake. The device acks Pake1 only once its Pake2 is computed, and a
/// debug build's SPAKE2+ takes seconds (measured: 1.6 s idle, about 3 s
/// under a full parallel `swift test`), so `fast`'s 1.1–4.3 s exhaustion
/// budget was a wall-clock margin. Here the budget is a hang guard: with 2
/// retransmissions a silent peer exhausts after ≈ 20–25 s (longer with
/// more), and a passing run, which loses nothing on the link, never waits
/// on it. Phases that need a
/// silent device to give up quickly switch to `fast` with
/// `setMRPParameters(_:for:)` once commissioned.
let patient = MRPParameters(
    sessionIdleInterval: .seconds(5),
    sessionActiveInterval: .seconds(5),
    sessionActiveThreshold: .milliseconds(4000)
)

/// Retransmissions that make `fast`'s exhaustion budget a hang guard over the
/// handshake (≈ 16–20 s: the sum of nine backed-off 220 ms intervals), for
/// suites that need `fast` during commissioning itself because they drop
/// the device's replies there. 10 (the lossy suites' value) also qualifies.
let handshakeRetransmissions = 8

/// `discovery` is where the device advertises; share one `InMemoryDiscovery`
/// with the controller so it can find the device. The default advertises nowhere.
/// `transport` replaces the device's endpoint (default `link.b`), e.g. to
/// wrap it.
func startServer(
    on link: FaultInjectingLink,
    toggles: LockedValue<Int>,
    discovery: any MatterDiscovery = FaultyLinkDiscovery(),
    transport: (any MatterUDPTransport)? = nil
) async throws -> (MatterDeviceServer, BridgedEndpoint) {
    let bridge = MatterBridge()
    let light = bridge.addDimmableLight(name: "Faulty Light", onOffChanged: { _ in
        toggles.withLock { $0 += 1 }
    })
    let server = MatterDeviceServer(
        bridge: bridge,
        transport: transport ?? link.b,
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
