// ControllerSessionTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
@testable import MatterController
@testable import MatterCrypto
@testable import MatterProtocol
import MatterTypes

@Suite("ControllerSession")
struct ControllerSessionTests {

    /// Create a controller-side FabricManager and a device-side FabricInfo
    /// sharing the same fabric (same root CA).
    private func setupFabricPair() throws -> (
        controllerManager: FabricManager,
        deviceFabricInfo: FabricInfo,
        rootKey: P256.Signing.PrivateKey
    ) {
        let rootKey = P256.Signing.PrivateKey()
        let fabricID = FabricID(rawValue: 1)

        let controllerManager = try FabricManager(
            rootKey: rootKey,
            fabricID: fabricID,
            controllerNodeID: NodeID(rawValue: 1),
            vendorID: .test
        )

        // Create a device-side fabric info with the same root CA
        let deviceKey = P256.Signing.PrivateKey()
        let rcac = try MatterCertificate.generateRCAC(
            key: rootKey,
            fabricID: fabricID
        )
        let deviceNOC = try MatterCertificate.generateNOC(
            signerKey: rootKey,
            issuerDN: rcac.subject,
            nodePublicKey: deviceKey.publicKey,
            nodeID: NodeID(rawValue: 2),
            fabricID: fabricID
        )

        let deviceFabricInfo = FabricInfo(
            fabricIndex: FabricIndex(rawValue: 1),
            fabricID: fabricID,
            nodeID: NodeID(rawValue: 2),
            rcac: rcac,
            noc: deviceNOC,
            operationalKey: deviceKey
        )

        return (controllerManager, deviceFabricInfo, rootKey)
    }

    @Test("Sigma1 is produced")
    func sigma1Produced() async throws {
        let (mgr, _, _) = try setupFabricPair()
        let cs = ControllerSession(fabricManager: mgr)

        let (sigma1, ctx) = cs.createSigma1(
            peerNodeID: NodeID(rawValue: 2),
            initiatorSessionID: 42
        )

        #expect(sigma1.count > 0)
        #expect(ctx.peerNodeID.rawValue == 2)
    }

    @Test("Full CASE round-trip through ControllerSession")
    func fullCASERoundTrip() async throws {
        let (mgr, deviceFabricInfo, _) = try setupFabricPair()
        let cs = ControllerSession(fabricManager: mgr)
        let controllerFabricInfo = mgr.controllerFabricInfo

        // Controller creates Sigma1
        let (sigma1Data, csCtx) = cs.createSigma1(
            peerNodeID: NodeID(rawValue: 2),
            initiatorSessionID: 42
        )

        // Device handles Sigma1 → produces Sigma2
        let deviceHandler = CASEProtocolHandler(
            fabricInfo: deviceFabricInfo
        )
        let (sigma2Data, deviceCtx) = try deviceHandler.handleSigma1(
            payload: sigma1Data,
            responderSessionID: 100
        )

        // Controller handles Sigma2 → produces Sigma3 + session
        let (sigma3Data, session) = try cs.handleSigma2(
            sigma2Data: sigma2Data,
            context: csCtx,
            localSessionID: 42
        )

        // Verify session
        #expect(session.localSessionID == 42)
        #expect(session.peerSessionID == 100)
        #expect(session.establishment == .case)
        #expect(session.encryptKey != nil)
        #expect(session.decryptKey != nil)

        // Device handles Sigma3 to complete handshake
        let deviceSession = try deviceHandler.handleSigma3(
            payload: sigma3Data,
            context: deviceCtx,
            initiatorRCAC: controllerFabricInfo.rcac,
            localSessionID: 100
        )
        #expect(deviceSession.localSessionID == 100)
        #expect(deviceSession.peerSessionID == 42)

        // Keys should be complementary (controller I2R = device I2R decryptKey)
        let ctrlEncrypt = session.encryptKey!.withUnsafeBytes { Data($0) }
        let deviceDecrypt = deviceSession.decryptKey!.withUnsafeBytes { Data($0) }
        #expect(ctrlEncrypt == deviceDecrypt)
    }

    @Test("Session has correct fabric index")
    func sessionFabricIndex() async throws {
        let (mgr, deviceFabricInfo, _) = try setupFabricPair()
        let cs = ControllerSession(fabricManager: mgr)
        let controllerFabricInfo = mgr.controllerFabricInfo

        let (sigma1Data, csCtx) = cs.createSigma1(
            peerNodeID: NodeID(rawValue: 2),
            initiatorSessionID: 10
        )

        let deviceHandler = CASEProtocolHandler(fabricInfo: deviceFabricInfo)
        let (sigma2Data, _) = try deviceHandler.handleSigma1(
            payload: sigma1Data,
            responderSessionID: 20
        )

        let (_, session) = try cs.handleSigma2(
            sigma2Data: sigma2Data,
            context: csCtx,
            localSessionID: 10
        )

        #expect(session.fabricIndex == controllerFabricInfo.fabricIndex)
    }
}
