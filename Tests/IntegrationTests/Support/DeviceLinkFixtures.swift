// DeviceLinkFixtures.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterCrypto
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
/// budget was a wall-clock margin. Here the budget is a hang guard: a
/// silent peer exhausts after ≈ 28.4–35.5 s with 2 retransmissions, or
/// ≈ 87–109 s with 4 (`MRPConfig.retransmissionInterval`, summed over every
/// transmission), and a passing run, which loses nothing on the link, never
/// waits on it. Phases that need a
/// silent device to give up quickly switch to `fast` with
/// `setMRPParameters(_:for:)` once commissioned.
let patient = MRPParameters(
    sessionIdleInterval: .seconds(5),
    sessionActiveInterval: .seconds(5),
    sessionActiveThreshold: .milliseconds(4000)
)

/// Retransmissions that make `fast`'s exhaustion budget a hang guard over the
/// handshake (≈ 24.8–31.0 s: the sum of nine backed-off 220 ms intervals), for
/// suites that need `fast` during commissioning itself because they drop
/// the device's replies there. 10 (the lossy suites' value) also qualifies.
let handshakeRetransmissions = 8

/// The attestation identity every link-harness device presents, and the trust store that
/// trusts exactly it. One set per test process: the suites share it so a controller made by
/// ``makeController(on:maxRetransmissions:discovery:store:discoveryClock:trustStore:)`` trusts
/// a device from ``startServer(on:toggles:discovery:transport:credentials:)`` without either
/// relying on the controller's production default.
enum LinkAttestation {
    private static let generated: Result<DeviceAttestationCredentials, any Error> = Result {
        try DeviceAttestationCredentials.testCredentials()
    }
    private static let store: Result<AttestationTrustStore, any Error> = Result {
        try TestAttestation.trustStore(for: generated.get())
    }

    static func credentials() throws -> DeviceAttestationCredentials { try generated.get() }
    static func trustStore() throws -> AttestationTrustStore { try store.get() }
}

/// `discovery` is where the device advertises; share one `InMemoryDiscovery`
/// with the controller so it can find the device. The default advertises nowhere.
/// `transport` replaces the device's endpoint (default `link.b`), e.g. to
/// wrap it. `credentials` is the attestation identity the device presents
/// (default: ``LinkAttestation/credentials()``).
func startServer(
    on link: FaultInjectingLink,
    toggles: LockedValue<Int>,
    discovery: any MatterDiscovery = FaultyLinkDiscovery(),
    transport: (any MatterUDPTransport)? = nil,
    credentials: DeviceAttestationCredentials? = nil
) async throws -> (MatterDeviceServer, BridgedEndpoint) {
    let bridge = MatterBridge()
    bridge.commissioningState.attestationCredentials = try credentials ?? LinkAttestation.credentials()
    let light = bridge.addDimmableLight(name: "Faulty Light", uniqueID: "faulty-light", onOffChanged: { _ in
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

/// A controller on the link's `a` side. Its discovery deadlines (search,
/// per-record resolve, address refresh) run on `discoveryClock`, by default
/// one that never moves: in-memory discovery answers at once, so a deadline
/// could only ever fall because a loaded host was slow to schedule the
/// answer. MRP and the operation timeouts stay on the real clock.
/// `trustStore` is the attestation trust store (default:
/// ``LinkAttestation/trustStore()``, which trusts the harness device).
func makeController(
    on link: FaultInjectingLink,
    maxRetransmissions: Int,
    discovery: any MatterDiscovery = FaultyLinkDiscovery(),
    store: (any MatterControllerStore)? = nil,
    discoveryClock: any MRPClock = ManualClock(),
    trustStore: AttestationTrustStore? = nil
) throws -> MatterController {
    try MatterController(
        transport: link.a,
        discovery: discovery,
        configuration: .init(
            fabricID: FabricID(rawValue: 1),
            mrp: MRPConfig(maxRetransmissions: maxRetransmissions),
            discoveryClock: discoveryClock,
            attestationTrustStore: try trustStore ?? LinkAttestation.trustStore()
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
