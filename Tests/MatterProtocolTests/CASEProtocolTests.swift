// CASEProtocolTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
@testable import MatterProtocol
@testable import MatterCrypto
@testable import MatterTypes

@Suite("CASE Protocol Handler")
struct CASEProtocolHandlerTests {

    @Test("Full CASE handshake via protocol handler produces working sessions")
    func fullHandshake() throws {
        // Setup: two fabrics sharing the same root CA
        let rootKey = P256.Signing.PrivateKey()
        let fabricID = FabricID(rawValue: 1)

        // Generate initiator fabric
        let initiatorKey = P256.Signing.PrivateKey()
        let initiatorNodeID = NodeID(rawValue: 0x1111)
        let initiatorRCAC = try MatterCertificate.generateRCAC(
            key: rootKey, rcacID: 1, fabricID: fabricID
        )
        let initiatorNOC = try MatterCertificate.generateNOC(
            signerKey: rootKey, issuerDN: initiatorRCAC.subject,
            nodePublicKey: initiatorKey.publicKey, nodeID: initiatorNodeID, fabricID: fabricID
        )
        let initiatorFabric = FabricInfo(
            fabricIndex: FabricIndex(rawValue: 1), fabricID: fabricID,
            nodeID: initiatorNodeID, rcac: initiatorRCAC, icac: nil,
            noc: initiatorNOC, operationalKey: initiatorKey
        )

        // Generate responder fabric
        let responderKey = P256.Signing.PrivateKey()
        let responderNodeID = NodeID(rawValue: 0x2222)
        let responderRCAC = try MatterCertificate.generateRCAC(
            key: rootKey, rcacID: 1, fabricID: fabricID
        )
        let responderNOC = try MatterCertificate.generateNOC(
            signerKey: rootKey, issuerDN: responderRCAC.subject,
            nodePublicKey: responderKey.publicKey, nodeID: responderNodeID, fabricID: fabricID
        )
        let responderFabric = FabricInfo(
            fabricIndex: FabricIndex(rawValue: 2), fabricID: fabricID,
            nodeID: responderNodeID, rcac: responderRCAC, icac: nil,
            noc: responderNOC, operationalKey: responderKey
        )

        let ipk = Data(repeating: 0, count: 16)

        // Create handlers
        let initiatorHandler = CASEProtocolHandler(fabricInfo: initiatorFabric, ipkEpochKey: ipk)
        let responderHandler = CASEProtocolHandler(fabricInfo: responderFabric, ipkEpochKey: ipk)

        // Step 1: Initiator creates Sigma1
        let (sigma1Data, initCtx) = initiatorHandler.createSigma1(
            peerNodeID: responderNodeID,
            peerFabricID: fabricID,
            peerRootPublicKey: rootKey.publicKey,
            initiatorSessionID: 100
        )
        #expect(sigma1Data.count > 0)

        // Step 2: Responder handles Sigma1 → produces Sigma2
        let (sigma2Data, respCtx) = try responderHandler.handleSigma1(
            payload: sigma1Data,
            responderSessionID: 200
        )
        #expect(sigma2Data.count > 0)

        // Step 3: Initiator handles Sigma2 → produces Sigma3 + session
        let (sigma3Data, initiatorSession) = try initiatorHandler.handleSigma2(
            payload: sigma2Data,
            context: initCtx,
            responderRCAC: responderRCAC,
            localSessionID: 100
        )
        #expect(sigma3Data.count > 0)

        // Step 4: Responder handles Sigma3 → produces session
        let responderSession = try responderHandler.handleSigma3(
            payload: sigma3Data,
            context: respCtx,
            initiatorRCAC: initiatorRCAC,
            localSessionID: 200
        )

        // Verify sessions have matching keys (cross-encryption)
        #expect(initiatorSession.encryptKey != nil)
        #expect(responderSession.encryptKey != nil)
        #expect(initiatorSession.establishment == .case)
        #expect(responderSession.establishment == .case)
        #expect(initiatorSession.fabricIndex == FabricIndex(rawValue: 1))
        #expect(responderSession.fabricIndex == FabricIndex(rawValue: 2))

        // Cross-encrypt: initiator encrypts, responder decrypts
        let testPayload = Data("Hello CASE!".utf8)
        let nonce = Data(repeating: 0x42, count: 13)
        let aad = Data()

        let encrypted = try MessageEncryption.encrypt(
            plaintext: testPayload, key: initiatorSession.encryptKey!, nonce: nonce, aad: aad
        )
        let decrypted = try MessageEncryption.decrypt(
            ciphertextWithMIC: encrypted, key: responderSession.decryptKey!, nonce: nonce, aad: aad
        )
        #expect(decrypted == testPayload)

        // And the reverse direction
        let encrypted2 = try MessageEncryption.encrypt(
            plaintext: testPayload, key: responderSession.encryptKey!, nonce: nonce, aad: aad
        )
        let decrypted2 = try MessageEncryption.decrypt(
            ciphertextWithMIC: encrypted2, key: initiatorSession.decryptKey!, nonce: nonce, aad: aad
        )
        #expect(decrypted2 == testPayload)
    }

    @Test("Exchange header helper builds correct headers")
    func exchangeHeaders() {
        let sigma1Header = CASEProtocolHandler.exchangeHeader(
            opcode: .caseSigma1, exchangeID: 42, isInitiator: true
        )
        #expect(sigma1Header.protocolOpcode == SecureChannelOpcode.caseSigma1.rawValue)
        #expect(sigma1Header.protocolID == MatterProtocolID.secureChannel.rawValue)
        #expect(sigma1Header.exchangeID == 42)
        #expect(sigma1Header.flags.initiator == true)
        #expect(sigma1Header.flags.reliableDelivery == true)

        let sigma2Header = CASEProtocolHandler.exchangeHeader(
            opcode: .caseSigma2, exchangeID: 42, isInitiator: false
        )
        #expect(sigma2Header.protocolOpcode == SecureChannelOpcode.caseSigma2.rawValue)
        #expect(sigma2Header.flags.initiator == false)
    }

    @Test("End-to-end: CASE → encrypt IM ReadRequest → decrypt → parse")
    func caseToIMEndToEnd() throws {
        // Setup shared root
        let rootKey = P256.Signing.PrivateKey()
        let fabricID = FabricID(rawValue: 1)
        let ipk = Data(repeating: 0, count: 16)

        // Initiator (controller)
        let ctrlKey = P256.Signing.PrivateKey()
        let ctrlNodeID = NodeID(rawValue: 0xAAAA)
        let ctrlRCAC = try MatterCertificate.generateRCAC(key: rootKey, rcacID: 1, fabricID: fabricID)
        let ctrlNOC = try MatterCertificate.generateNOC(
            signerKey: rootKey, issuerDN: ctrlRCAC.subject,
            nodePublicKey: ctrlKey.publicKey, nodeID: ctrlNodeID, fabricID: fabricID
        )
        let ctrlFabric = FabricInfo(
            fabricIndex: FabricIndex(rawValue: 1), fabricID: fabricID,
            nodeID: ctrlNodeID, rcac: ctrlRCAC, icac: nil, noc: ctrlNOC, operationalKey: ctrlKey
        )

        // Responder (device)
        let devKey = P256.Signing.PrivateKey()
        let devNodeID = NodeID(rawValue: 0xBBBB)
        let devRCAC = try MatterCertificate.generateRCAC(key: rootKey, rcacID: 1, fabricID: fabricID)
        let devNOC = try MatterCertificate.generateNOC(
            signerKey: rootKey, issuerDN: devRCAC.subject,
            nodePublicKey: devKey.publicKey, nodeID: devNodeID, fabricID: fabricID
        )
        let devFabric = FabricInfo(
            fabricIndex: FabricIndex(rawValue: 2), fabricID: fabricID,
            nodeID: devNodeID, rcac: devRCAC, icac: nil, noc: devNOC, operationalKey: devKey
        )

        // CASE handshake
        let ctrlHandler = CASEProtocolHandler(fabricInfo: ctrlFabric, ipkEpochKey: ipk)
        let devHandler = CASEProtocolHandler(fabricInfo: devFabric, ipkEpochKey: ipk)

        let (sigma1, initCtx) = ctrlHandler.createSigma1(
            peerNodeID: devNodeID, peerFabricID: fabricID,
            peerRootPublicKey: rootKey.publicKey, initiatorSessionID: 10
        )
        let (sigma2, respCtx) = try devHandler.handleSigma1(payload: sigma1, responderSessionID: 20)
        let (sigma3, ctrlSession) = try ctrlHandler.handleSigma2(
            payload: sigma2, context: initCtx, responderRCAC: devRCAC, localSessionID: 10
        )
        let devSession = try devHandler.handleSigma3(
            payload: sigma3, context: respCtx, initiatorRCAC: ctrlRCAC, localSessionID: 20
        )

        // Build IM ReadRequest
        let readReqData = IMClient.readAttributeRequest(
            endpointID: EndpointID(rawValue: 1),
            clusterID: ClusterID(rawValue: 0x0006),
            attributeID: AttributeID(rawValue: 0)
        )

        // Encrypt with controller's session
        let nonce = Data(repeating: 0x01, count: 13)
        let encrypted = try MessageEncryption.encrypt(
            plaintext: readReqData, key: ctrlSession.encryptKey!, nonce: nonce, aad: Data()
        )

        // Decrypt on device side
        let decrypted = try MessageEncryption.decrypt(
            ciphertextWithMIC: encrypted, key: devSession.decryptKey!, nonce: nonce, aad: Data()
        )

        // Parse the ReadRequest
        let readReq = try ReadRequest.fromTLV(decrypted)
        #expect(readReq.attributeRequests.count == 1)
        #expect(readReq.attributeRequests[0].clusterID == ClusterID(rawValue: 0x0006))
        #expect(readReq.attributeRequests[0].attributeID == AttributeID(rawValue: 0))

        // Device builds a ReportData response
        let reportData = ReportData(attributeReports: [
            AttributeReportIB(attributeData: AttributeDataIB(
                dataVersion: DataVersion(rawValue: 1),
                path: readReq.attributeRequests[0],
                data: .bool(true) // OnOff = true
            ))
        ])
        let reportBytes = reportData.tlvEncode()

        // Encrypt response with device's session
        let encryptedReport = try MessageEncryption.encrypt(
            plaintext: reportBytes, key: devSession.encryptKey!, nonce: nonce, aad: Data()
        )

        // Controller decrypts and parses
        let decryptedReport = try MessageEncryption.decrypt(
            ciphertextWithMIC: encryptedReport, key: ctrlSession.decryptKey!, nonce: nonce, aad: Data()
        )
        let value = try IMClient.parseReadResponse(decryptedReport)
        #expect(value == .bool(true))
    }
}
