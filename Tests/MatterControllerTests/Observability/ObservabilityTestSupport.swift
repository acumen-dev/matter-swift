// ObservabilityTestSupport.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import MatterCrypto
import Logging
import MatterTypes
import MatterProtocol
import MatterTransport
import MatterTestSupport
@testable import MatterController

/// SII/SAI 5 ms, one retransmission: a silent peer exhausts MRP in about 20 ms of real time.
let fastMRP = MRPConfig(
    peer: MRPParameters(sessionIdleInterval: .milliseconds(5), sessionActiveInterval: .milliseconds(5)),
    maxRetransmissions: 1
)

/// A controller on `link.a` with test telemetry injected (logger label `test.controller`),
/// mirrored sessions 10 (controller) / 20 (peer), and node 0x42 known at `link.b` (or
/// `deviceAddress`), with session 10 as its operational session unless `installSession` is false.
struct ControllerRig {
    let telemetry: TestTelemetry
    let link: FaultInjectingLink
    let configuration: MatterController.Configuration
    let controller: MatterController
    let controllerSession: SecureSession
    let peerSession: SecureSession
    let node: NodeID
}

func makeControllerRig(
    mrp: MRPConfig = .default,
    discovery: any MatterDiscovery = MockDiscovery(),
    installSession: Bool = true,
    deviceAddress: MatterAddress? = nil,
    fabricManager: FabricManager? = nil
) async throws -> ControllerRig {
    let telemetry = TestTelemetry()
    let link = FaultInjectingLink(seed: 11)
    let configuration = MatterController.Configuration(
        fabricID: FabricID(rawValue: 1),
        mrp: mrp,
        metricsFactory: telemetry.metrics,
        tracer: telemetry.tracer
    )
    let logger = telemetry.logger(label: "test.controller")
    let controller: MatterController
    if let fabricManager {
        controller = try MatterController(
            transport: link.a,
            discovery: discovery,
            configuration: configuration,
            stored: StoredControllerState(
                identity: fabricManager.toStoredIdentity(), devices: [], nextNodeID: await fabricManager.nextNodeID
            ),
            logger: logger
        )
    } else {
        controller = try MatterController(
            transport: link.a,
            discovery: discovery,
            configuration: configuration,
            logger: logger
        )
    }
    let (controllerSession, peerSession) = ScriptedPeer.mirroredSessions(controllerSessionID: 10, peerSessionID: 20)
    let node = NodeID(rawValue: 0x42)
    try await controller.installForTesting(
        device: CommissionedDevice(nodeID: node, fabricIndex: FabricIndex(rawValue: 1)),
        session: installSession ? controllerSession : nil,
        address: deviceAddress ?? link.b.address
    )
    return ControllerRig(
        telemetry: telemetry, link: link, configuration: configuration, controller: controller,
        controllerSession: controllerSession, peerSession: peerSession, node: node
    )
}

/// The next secured frame the controller has not sent before. On the real clock MRP may
/// retransmit an unacknowledged request (same counter); bare acks and repeats are skipped.
func nextNewFrame(_ peer: inout TestPeer, session: SecureSession, seen: inout Set<UInt32>) async throws -> PeerFrame {
    while true {
        let frame = try await peer.nextSecured(session: session)
        if frame.isStandaloneAck { continue }
        if seen.insert(frame.counter).inserted { return frame }
    }
}

/// As ``nextNewFrame(_:session:seen:)`` for unsecured (handshake) frames.
func nextNewUnsecuredFrame(_ peer: inout TestPeer, seen: inout Set<UInt32>) async throws -> PeerFrame {
    while true {
        let frame = try await peer.next()
        if frame.isStandaloneAck { continue }
        if seen.insert(frame.counter).inserted { return frame }
    }
}

/// A fabric the test knows: its root key, the controller's `FabricManager` on it, and node
/// 0x42's device-side `FabricInfo` (NOC signed by the same root, same IPK).
struct TestFabric {
    let rootKey: P256.Signing.PrivateKey
    let manager: FabricManager
    let deviceFabric: FabricInfo
}

func makeTestFabric() throws -> TestFabric {
    let rootKey = P256.Signing.PrivateKey()
    let fabricID = FabricID(rawValue: 1)
    let manager = try FabricManager(
        rootKey: rootKey, fabricID: fabricID, controllerNodeID: NodeID(rawValue: 1), vendorID: .test
    )
    let node = NodeID(rawValue: 0x42)
    let rcac = manager.controllerFabricInfo.rcac
    let deviceKey = P256.Signing.PrivateKey()
    let deviceNOC = try MatterCertificate.generateNOC(
        signerKey: rootKey, issuerDN: rcac.subject, nodePublicKey: deviceKey.publicKey, nodeID: node, fabricID: fabricID
    )
    let deviceFabric = FabricInfo(
        fabricIndex: FabricIndex(rawValue: 1),
        fabricID: fabricID,
        nodeID: node,
        rcac: rcac,
        noc: deviceNOC,
        operationalKey: deviceKey,
        ipkEpochKey: manager.ipkEpochKey
    )
    return TestFabric(rootKey: rootKey, manager: manager, deviceFabric: deviceFabric)
}

/// A rig whose controller is on a ``TestFabric``, with no session installed: a
/// `CASEProtocolHandler(fabricInfo: fabric.deviceFabric)` answers the controller's Sigma1 for real.
func makeCASEControllerRig() async throws -> (rig: ControllerRig, fabric: TestFabric) {
    let fabric = try makeTestFabric()
    let rig = try await makeControllerRig(installSession: false, fabricManager: fabric.manager)
    return (rig, fabric)
}
