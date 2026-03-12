// CASESessionTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
@testable import MatterCrypto
import MatterTypes

@Suite("CASE Session")
struct CASESessionTests {

    // MARK: - Full Round-Trip

    @Test("Full CASE round-trip produces matching session keys")
    func fullRoundTrip() throws {
        // Setup: two nodes in the same fabric
        let rootKey = P256.Signing.PrivateKey()
        let fabricID = FabricID(rawValue: 1)

        let initiatorNodeKey = P256.Signing.PrivateKey()
        let responderNodeKey = P256.Signing.PrivateKey()

        let rcac = try MatterCertificate.generateRCAC(
            key: rootKey, fabricID: fabricID
        )

        let initiatorNOC = try MatterCertificate.generateNOC(
            signerKey: rootKey, issuerDN: rcac.subject,
            nodePublicKey: initiatorNodeKey.publicKey,
            nodeID: NodeID(rawValue: 1), fabricID: fabricID
        )

        let responderNOC = try MatterCertificate.generateNOC(
            signerKey: rootKey, issuerDN: rcac.subject,
            nodePublicKey: responderNodeKey.publicKey,
            nodeID: NodeID(rawValue: 2), fabricID: fabricID
        )

        let initiatorFabric = FabricInfo(
            fabricIndex: FabricIndex(rawValue: 1),
            fabricID: fabricID,
            nodeID: NodeID(rawValue: 1),
            rcac: rcac, noc: initiatorNOC,
            operationalKey: initiatorNodeKey
        )

        let responderFabric = FabricInfo(
            fabricIndex: FabricIndex(rawValue: 1),
            fabricID: fabricID,
            nodeID: NodeID(rawValue: 2),
            rcac: rcac, noc: responderNOC,
            operationalKey: responderNodeKey
        )

        // Step 1: Initiator creates Sigma1
        let (initiatorCtx, sigma1Data) = CASESession.initiatorStep1(
            fabricInfo: initiatorFabric,
            peerNodeID: NodeID(rawValue: 2),
            peerFabricID: fabricID,
            peerRootPublicKey: rootKey.publicKey,
            initiatorSessionID: 100
        )

        // Step 2: Responder processes Sigma1, creates Sigma2
        let (responderCtx, sigma2Data) = try CASESession.responderStep1(
            sigma1Data: sigma1Data,
            fabricInfo: responderFabric,
            responderSessionID: 200
        )

        // Step 3: Initiator processes Sigma2, creates Sigma3
        let (sigma3Data, initiatorKeys, peerSessionID) = try CASESession.initiatorStep2(
            context: initiatorCtx,
            sigma2Data: sigma2Data,
            responderRCAC: rcac
        )

        // Step 4: Responder processes Sigma3, derives session keys
        let responderKeys = try CASESession.responderStep2(
            context: responderCtx,
            sigma3Data: sigma3Data,
            initiatorRCAC: rcac
        )

        // Verify session IDs
        #expect(peerSessionID == 200)

        // Verify both sides derived matching keys
        // I2R key on initiator == I2R key on responder
        let i2r_initiator = initiatorKeys.i2rKey.withUnsafeBytes { Data($0) }
        let i2r_responder = responderKeys.i2rKey.withUnsafeBytes { Data($0) }
        #expect(i2r_initiator == i2r_responder)

        let r2i_initiator = initiatorKeys.r2iKey.withUnsafeBytes { Data($0) }
        let r2i_responder = responderKeys.r2iKey.withUnsafeBytes { Data($0) }
        #expect(r2i_initiator == r2i_responder)

        let att_initiator = initiatorKeys.attestationKey.withUnsafeBytes { Data($0) }
        let att_responder = responderKeys.attestationKey.withUnsafeBytes { Data($0) }
        #expect(att_initiator == att_responder)
    }

    // MARK: - Wrong Fabric Rejection

    @Test("CASE rejects wrong fabric (destination ID mismatch)")
    func wrongFabricRejected() throws {
        // Setup: two different fabrics
        let rootKey2 = P256.Signing.PrivateKey()

        let (initiatorFabric, _) = try FabricInfo.generateTestFabric(
            fabricID: FabricID(rawValue: 1),
            nodeID: NodeID(rawValue: 1)
        )

        let (responderFabric, _) = try FabricInfo.generateTestFabric(
            fabricID: FabricID(rawValue: 2),
            nodeID: NodeID(rawValue: 2)
        )

        // Initiator targets responder's node but with wrong fabric root key
        let (_, sigma1Data) = CASESession.initiatorStep1(
            fabricInfo: initiatorFabric,
            peerNodeID: NodeID(rawValue: 2),
            peerFabricID: FabricID(rawValue: 2),
            peerRootPublicKey: rootKey2.publicKey, // wrong root key for responder's fabric
            initiatorSessionID: 100
        )

        // Responder should reject because destination ID won't match
        #expect(throws: CASEError.self) {
            _ = try CASESession.responderStep1(
                sigma1Data: sigma1Data,
                fabricInfo: responderFabric,
                responderSessionID: 200
            )
        }
    }

    // MARK: - Tampered Sigma2 Rejection

    @Test("CASE rejects tampered Sigma2 signature")
    func tamperedSigma2Rejected() throws {
        let rootKey = P256.Signing.PrivateKey()
        let fabricID = FabricID(rawValue: 1)

        let initiatorNodeKey = P256.Signing.PrivateKey()
        let responderNodeKey = P256.Signing.PrivateKey()

        let rcac = try MatterCertificate.generateRCAC(key: rootKey, fabricID: fabricID)

        let initiatorNOC = try MatterCertificate.generateNOC(
            signerKey: rootKey, issuerDN: rcac.subject,
            nodePublicKey: initiatorNodeKey.publicKey,
            nodeID: NodeID(rawValue: 1), fabricID: fabricID
        )
        let responderNOC = try MatterCertificate.generateNOC(
            signerKey: rootKey, issuerDN: rcac.subject,
            nodePublicKey: responderNodeKey.publicKey,
            nodeID: NodeID(rawValue: 2), fabricID: fabricID
        )

        let initiatorFabric = FabricInfo(
            fabricIndex: FabricIndex(rawValue: 1), fabricID: fabricID,
            nodeID: NodeID(rawValue: 1), rcac: rcac, noc: initiatorNOC,
            operationalKey: initiatorNodeKey
        )
        let responderFabric = FabricInfo(
            fabricIndex: FabricIndex(rawValue: 1), fabricID: fabricID,
            nodeID: NodeID(rawValue: 2), rcac: rcac, noc: responderNOC,
            operationalKey: responderNodeKey
        )

        let (initiatorCtx, sigma1Data) = CASESession.initiatorStep1(
            fabricInfo: initiatorFabric,
            peerNodeID: NodeID(rawValue: 2),
            peerFabricID: fabricID,
            peerRootPublicKey: rootKey.publicKey,
            initiatorSessionID: 100
        )

        let (_, sigma2Data) = try CASESession.responderStep1(
            sigma1Data: sigma1Data,
            fabricInfo: responderFabric,
            responderSessionID: 200
        )

        // Tamper with sigma2 by flipping a byte in the encrypted payload
        var tampered = sigma2Data
        if tampered.count > 20 {
            tampered[tampered.count - 20] ^= 0xFF
        }

        // Initiator should reject (decryption or signature verification will fail)
        #expect(throws: Error.self) {
            _ = try CASESession.initiatorStep2(
                context: initiatorCtx,
                sigma2Data: tampered,
                responderRCAC: rcac
            )
        }
    }

    // MARK: - Cross-Encryption Test

    @Test("Session keys can encrypt/decrypt between parties")
    func sessionKeysWorkForEncryption() throws {
        let rootKey = P256.Signing.PrivateKey()
        let fabricID = FabricID(rawValue: 1)

        let (initiatorFabric, _) = try makeTestFabricPair(
            rootKey: rootKey, fabricID: fabricID,
            nodeID: NodeID(rawValue: 1)
        )
        let (responderFabric, _) = try makeTestFabricPair(
            rootKey: rootKey, fabricID: fabricID,
            nodeID: NodeID(rawValue: 2)
        )

        let rcac = initiatorFabric.rcac

        // Full handshake
        let (iCtx, s1) = CASESession.initiatorStep1(
            fabricInfo: initiatorFabric,
            peerNodeID: NodeID(rawValue: 2),
            peerFabricID: fabricID,
            peerRootPublicKey: rootKey.publicKey,
            initiatorSessionID: 1
        )
        let (rCtx, s2) = try CASESession.responderStep1(
            sigma1Data: s1, fabricInfo: responderFabric, responderSessionID: 2
        )
        let (s3, iKeys, _) = try CASESession.initiatorStep2(
            context: iCtx, sigma2Data: s2, responderRCAC: rcac
        )
        let rKeys = try CASESession.responderStep2(
            context: rCtx, sigma3Data: s3, initiatorRCAC: rcac
        )

        // Test: initiator encrypts with I2R key, responder decrypts with I2R key
        let nonce = MessageEncryption.buildNonce(
            securityFlags: 0, messageCounter: 1, sourceNodeID: 1
        )
        let plaintext = Data("Hello from initiator".utf8)

        let encrypted = try MessageEncryption.encrypt(
            plaintext: plaintext,
            key: iKeys.encryptKey(isInitiator: true),
            nonce: nonce,
            aad: Data()
        )

        let decrypted = try MessageEncryption.decrypt(
            ciphertextWithMIC: encrypted,
            key: rKeys.decryptKey(isInitiator: false),
            nonce: nonce,
            aad: Data()
        )

        #expect(decrypted == plaintext)
    }

    // MARK: - Helpers

    /// Create a FabricInfo using a shared root key (both nodes in same fabric).
    private func makeTestFabricPair(
        rootKey: P256.Signing.PrivateKey,
        fabricID: FabricID,
        nodeID: NodeID
    ) throws -> (FabricInfo, P256.Signing.PrivateKey) {
        let nodeKey = P256.Signing.PrivateKey()
        let rcac = try MatterCertificate.generateRCAC(key: rootKey, fabricID: fabricID)
        let noc = try MatterCertificate.generateNOC(
            signerKey: rootKey, issuerDN: rcac.subject,
            nodePublicKey: nodeKey.publicKey,
            nodeID: nodeID, fabricID: fabricID
        )
        let fabric = FabricInfo(
            fabricIndex: FabricIndex(rawValue: 1),
            fabricID: fabricID, nodeID: nodeID,
            rcac: rcac, noc: noc, operationalKey: nodeKey
        )
        return (fabric, nodeKey)
    }
}
