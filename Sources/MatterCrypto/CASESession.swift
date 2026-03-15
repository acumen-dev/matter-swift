// CASESession.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import MatterTypes

/// CASE (Certificate Authenticated Session Establishment) protocol implementation.
///
/// CASE establishes an encrypted session between two Matter nodes that share a common
/// fabric. It uses ECDH for key agreement, ECDSA for authentication, and HKDF for
/// key derivation. The protocol follows a 3-message Sigma pattern:
///
/// 1. **Sigma1** (Initiator → Responder): ephemeral key + destination ID
/// 2. **Sigma2** (Responder → Initiator): ephemeral key + encrypted(NOC + signature)
/// 3. **Sigma3** (Initiator → Responder): encrypted(NOC + signature)
///
/// After Sigma3, both sides derive matching session keys for message encryption.
public enum CASESession {

    // MARK: - Nonce Constants

    /// Nonce for encrypting/decrypting Sigma2 payloads.
    /// "NCASE_Sigma2N" padded to 13 bytes with a trailing zero.
    private static let sigma2Nonce: Data = {
        var n = Data("NCASE_Sigma2N".utf8)
        n.append(0) // pad to 13 bytes
        return n
    }()

    /// Nonce for encrypting/decrypting Sigma3 payloads.
    /// "NCASE_Sigma3N" is exactly 13 bytes.
    private static let sigma3Nonce = Data("NCASE_Sigma3N".utf8)

    // MARK: - Initiator Context

    /// State carried between initiator steps.
    public struct InitiatorContext: Sendable {
        public let initiatorRandom: Data
        public let initiatorSessionID: UInt16
        public let initiatorEphKey: P256.KeyAgreement.PrivateKey
        public let fabricInfo: FabricInfo
        public let ipk: Data
        /// Set when resumption was attempted; used to verify the responder's Sigma2Resume MIC.
        public let resumptionID: Data?
    }

    // MARK: - Responder Context

    /// State carried between responder steps.
    public struct ResponderContext: Sendable {
        public let responderRandom: Data
        public let responderSessionID: UInt16
        public let responderEphKey: P256.KeyAgreement.PrivateKey
        public let initiatorEphPubKey: Data
        public let fabricInfo: FabricInfo
        public let ipk: Data
        public let sharedSecret: Data
        public let s2k: SymmetricKey
        public let s3k: SymmetricKey
    }

    // MARK: - Initiator Step 1

    /// Create Sigma1 message (initiator begins CASE).
    ///
    /// Generates a random nonce, ephemeral key pair, and computes the destination ID
    /// that targets the responder's fabric+node.
    ///
    /// - Parameters:
    ///   - fabricInfo: The initiator's fabric information.
    ///   - peerNodeID: The target node's operational ID.
    ///   - peerFabricID: The target node's fabric ID.
    ///   - peerRootPublicKey: The target fabric's root CA public key.
    ///   - initiatorSessionID: Proposed session ID for the initiator side.
    /// - Returns: Tuple of (context for step 2, sigma1 TLV data).
    public static func initiatorStep1(
        fabricInfo: FabricInfo,
        peerNodeID: NodeID,
        peerFabricID: FabricID,
        peerRootPublicKey: P256.Signing.PublicKey,
        initiatorSessionID: UInt16
    ) -> (context: InitiatorContext, sigma1Data: Data) {
        let random = generateRandom(count: 32)
        let ephKey = P256.KeyAgreement.PrivateKey()
        let ipk = fabricInfo.deriveIPK()

        let destinationID = CASEKeyDerivation.computeDestinationID(
            initiatorRandom: random,
            rootPublicKey: Data(peerRootPublicKey.x963Representation),
            fabricID: peerFabricID,
            nodeID: peerNodeID,
            ipk: ipk
        )

        let sigma1 = Sigma1Message(
            initiatorRandom: random,
            initiatorSessionID: initiatorSessionID,
            destinationID: destinationID,
            initiatorEphPubKey: Data(ephKey.publicKey.x963Representation)
        )

        let context = InitiatorContext(
            initiatorRandom: random,
            initiatorSessionID: initiatorSessionID,
            initiatorEphKey: ephKey,
            fabricInfo: fabricInfo,
            ipk: ipk,
            resumptionID: nil
        )

        return (context, sigma1.tlvEncode())
    }

    // MARK: - Responder Step 1

    /// Process Sigma1 and create Sigma2 message (responder side).
    ///
    /// Verifies the destination ID matches this node, performs ECDH,
    /// derives sigma keys, signs TBS data, encrypts the payload, and
    /// assembles Sigma2.
    ///
    /// - Parameters:
    ///   - sigma1Data: The raw Sigma1 TLV bytes.
    ///   - fabricInfo: The responder's fabric information.
    ///   - responderSessionID: Proposed session ID for the responder side.
    /// - Returns: Tuple of (context for step 2, sigma2 TLV data).
    public static func responderStep1(
        sigma1Data: Data,
        fabricInfo: FabricInfo,
        responderSessionID: UInt16
    ) throws -> (context: ResponderContext, sigma2Data: Data) {
        let sigma1 = try Sigma1Message.fromTLV(sigma1Data)

        // Verify destination ID matches us
        let ipk = fabricInfo.deriveIPK()
        let expectedDestID = CASEKeyDerivation.computeDestinationID(
            initiatorRandom: sigma1.initiatorRandom,
            rootPublicKey: Data(fabricInfo.rootPublicKey.x963Representation),
            fabricID: fabricInfo.fabricID,
            nodeID: fabricInfo.nodeID,
            ipk: ipk
        )
        guard sigma1.destinationID == expectedDestID else {
            throw CASEError.destinationIDMismatch
        }

        // ECDH key agreement
        let responderEphKey = P256.KeyAgreement.PrivateKey()
        let initiatorEphPubKey = try P256.KeyAgreement.PublicKey(x963Representation: sigma1.initiatorEphPubKey)
        let sharedSecret = try responderEphKey.sharedSecretFromKeyAgreement(with: initiatorEphPubKey)
        let sharedSecretData = sharedSecret.withUnsafeBytes { Data($0) }

        let responderRandom = generateRandom(count: 32)
        let responderEphPubKeyData = Data(responderEphKey.publicKey.x963Representation)

        // Derive sigma keys
        let (s2k, s3k) = CASEKeyDerivation.deriveSigmaKeys(
            sharedSecret: sharedSecretData,
            ipk: ipk,
            responderRandom: responderRandom,
            responderEphPubKey: responderEphPubKeyData,
            initiatorEphPubKey: sigma1.initiatorEphPubKey
        )

        // Build and sign TBS2
        let nocTLV = fabricInfo.noc.tlvEncode()
        let icacTLV = fabricInfo.icac?.tlvEncode()

        let tbs2 = TBSData2(
            responderNOC: nocTLV,
            responderICAC: icacTLV,
            responderEphPubKey: responderEphPubKeyData,
            initiatorEphPubKey: sigma1.initiatorEphPubKey
        )
        let signature = try fabricInfo.operationalKey.signature(for: tbs2.tlvEncode())

        // Build and encrypt Sigma2 payload
        let resumptionID = generateRandom(count: 16)
        let sigma2Payload = Sigma2Decrypted(
            responderNOC: nocTLV,
            responderICAC: icacTLV,
            signature: Data(signature.derRepresentation),
            resumptionID: resumptionID
        )

        let encrypted2 = try MessageEncryption.encrypt(
            plaintext: sigma2Payload.tlvEncode(),
            key: s2k,
            nonce: sigma2Nonce,
            aad: Data()
        )

        let sigma2 = Sigma2Message(
            responderRandom: responderRandom,
            responderSessionID: responderSessionID,
            responderEphPubKey: responderEphPubKeyData,
            encrypted2: encrypted2
        )

        let context = ResponderContext(
            responderRandom: responderRandom,
            responderSessionID: responderSessionID,
            responderEphKey: responderEphKey,
            initiatorEphPubKey: sigma1.initiatorEphPubKey,
            fabricInfo: fabricInfo,
            ipk: ipk,
            sharedSecret: sharedSecretData,
            s2k: s2k,
            s3k: s3k
        )

        return (context, sigma2.tlvEncode())
    }

    // MARK: - Initiator Step 2

    /// Process Sigma2 and create Sigma3 message (initiator side).
    ///
    /// Decrypts Sigma2 payload, verifies responder's certificate chain and signature,
    /// signs TBS3, encrypts initiator payload, and derives session keys.
    ///
    /// - Parameters:
    ///   - context: The context from initiatorStep1.
    ///   - sigma2Data: The raw Sigma2 TLV bytes.
    ///   - responderRCAC: The responder's expected Root CA Certificate.
    /// - Returns: Tuple of (sigma3 TLV data, session keys).
    public static func initiatorStep2(
        context: InitiatorContext,
        sigma2Data: Data,
        responderRCAC: MatterCertificate
    ) throws -> (sigma3Data: Data, sessionKeys: SessionKeys, responderSessionID: UInt16) {
        let sigma2 = try Sigma2Message.fromTLV(sigma2Data)

        // ECDH key agreement
        let responderEphPubKey = try P256.KeyAgreement.PublicKey(x963Representation: sigma2.responderEphPubKey)
        let sharedSecret = try context.initiatorEphKey.sharedSecretFromKeyAgreement(with: responderEphPubKey)
        let sharedSecretData = sharedSecret.withUnsafeBytes { Data($0) }

        // Derive sigma keys
        let (s2k, s3k) = CASEKeyDerivation.deriveSigmaKeys(
            sharedSecret: sharedSecretData,
            ipk: context.ipk,
            responderRandom: sigma2.responderRandom,
            responderEphPubKey: sigma2.responderEphPubKey,
            initiatorEphPubKey: Data(context.initiatorEphKey.publicKey.x963Representation)
        )

        // Decrypt Sigma2 payload
        let decryptedData = try MessageEncryption.decrypt(
            ciphertextWithMIC: sigma2.encrypted2,
            key: s2k,
            nonce: sigma2Nonce,
            aad: Data()
        )
        let sigma2Decrypted = try Sigma2Decrypted.fromTLV(decryptedData)

        // Verify responder's certificate chain
        let responderNOC = try MatterCertificate.fromTLV(sigma2Decrypted.responderNOC)
        guard MatterCertificate.validateChain(noc: responderNOC, rcac: responderRCAC) else {
            throw CASEError.certificateChainInvalid
        }

        // Verify responder's signature
        let tbs2 = TBSData2(
            responderNOC: sigma2Decrypted.responderNOC,
            responderICAC: sigma2Decrypted.responderICAC,
            responderEphPubKey: sigma2.responderEphPubKey,
            initiatorEphPubKey: Data(context.initiatorEphKey.publicKey.x963Representation)
        )
        let responderPubKey = try responderNOC.subjectPublicKey()
        let responderSig = try P256.Signing.ECDSASignature(derRepresentation: sigma2Decrypted.signature)
        guard responderPubKey.isValidSignature(responderSig, for: tbs2.tlvEncode()) else {
            throw CASEError.signatureVerificationFailed
        }

        // Build and sign TBS3
        let initiatorNOCTLV = context.fabricInfo.noc.tlvEncode()
        let initiatorICACTLV = context.fabricInfo.icac?.tlvEncode()

        let tbs3 = TBSData3(
            initiatorNOC: initiatorNOCTLV,
            initiatorICAC: initiatorICACTLV,
            initiatorEphPubKey: Data(context.initiatorEphKey.publicKey.x963Representation),
            responderEphPubKey: sigma2.responderEphPubKey
        )
        let initiatorSig = try context.fabricInfo.operationalKey.signature(for: tbs3.tlvEncode())

        // Build and encrypt Sigma3 payload
        let sigma3Payload = Sigma3Decrypted(
            initiatorNOC: initiatorNOCTLV,
            initiatorICAC: initiatorICACTLV,
            signature: Data(initiatorSig.derRepresentation)
        )

        let encrypted3 = try MessageEncryption.encrypt(
            plaintext: sigma3Payload.tlvEncode(),
            key: s3k,
            nonce: sigma3Nonce,
            aad: Data()
        )

        let sigma3 = Sigma3Message(encrypted3: encrypted3)

        // Derive session keys
        let sessionKeys = CASEKeyDerivation.deriveSessionKeys(
            sharedSecret: sharedSecretData,
            ipk: context.ipk,
            responderRandom: sigma2.responderRandom,
            responderEphPubKey: sigma2.responderEphPubKey,
            initiatorEphPubKey: Data(context.initiatorEphKey.publicKey.x963Representation)
        )

        return (sigma3.tlvEncode(), sessionKeys, sigma2.responderSessionID)
    }

    // MARK: - Responder Step 2

    /// Process Sigma3 and derive session keys (responder side).
    ///
    /// Decrypts Sigma3 payload, verifies initiator's certificate chain and signature,
    /// and derives session keys.
    ///
    /// - Parameters:
    ///   - context: The context from responderStep1.
    ///   - sigma3Data: The raw Sigma3 TLV bytes.
    ///   - initiatorRCAC: The initiator's expected Root CA Certificate.
    /// - Returns: Tuple of session keys and the initiator's node ID (from their NOC).
    public static func responderStep2(
        context: ResponderContext,
        sigma3Data: Data,
        initiatorRCAC: MatterCertificate
    ) throws -> (SessionKeys, NodeID) {
        let sigma3 = try Sigma3Message.fromTLV(sigma3Data)

        // Decrypt Sigma3 payload
        let decryptedData = try MessageEncryption.decrypt(
            ciphertextWithMIC: sigma3.encrypted3,
            key: context.s3k,
            nonce: sigma3Nonce,
            aad: Data()
        )
        let sigma3Decrypted = try Sigma3Decrypted.fromTLV(decryptedData)

        // Verify initiator's certificate chain
        let initiatorNOC = try MatterCertificate.fromTLV(sigma3Decrypted.initiatorNOC)
        guard MatterCertificate.validateChain(noc: initiatorNOC, rcac: initiatorRCAC) else {
            throw CASEError.certificateChainInvalid
        }

        // Verify initiator's signature
        let tbs3 = TBSData3(
            initiatorNOC: sigma3Decrypted.initiatorNOC,
            initiatorICAC: sigma3Decrypted.initiatorICAC,
            initiatorEphPubKey: context.initiatorEphPubKey,
            responderEphPubKey: Data(context.responderEphKey.publicKey.x963Representation)
        )
        let initiatorPubKey = try initiatorNOC.subjectPublicKey()
        let initiatorSig = try P256.Signing.ECDSASignature(derRepresentation: sigma3Decrypted.signature)
        guard initiatorPubKey.isValidSignature(initiatorSig, for: tbs3.tlvEncode()) else {
            throw CASEError.signatureVerificationFailed
        }

        // Derive session keys
        let sessionKeys = CASEKeyDerivation.deriveSessionKeys(
            sharedSecret: context.sharedSecret,
            ipk: context.ipk,
            responderRandom: context.responderRandom,
            responderEphPubKey: Data(context.responderEphKey.publicKey.x963Representation),
            initiatorEphPubKey: context.initiatorEphPubKey
        )

        // Extract initiator's node ID from their NOC
        guard let initiatorNodeID = initiatorNOC.subject.nodeID else {
            throw CASEError.certificateChainInvalid
        }

        return (sessionKeys, initiatorNodeID)
    }

    // MARK: - Resumption Ticket Storage

    /// Store a resumption ticket after successful CASE establishment.
    ///
    /// Call this after `responderStep2` completes successfully. The ticket
    /// uses the `resumptionID` from the Sigma2 payload and the ECDH shared secret.
    ///
    /// - Parameters:
    ///   - resumptionID: The 16-byte resumption ID from `Sigma2Decrypted`.
    ///   - sharedSecret: The ECDH shared secret.
    ///   - peerNodeID: The initiator's node ID (from their NOC).
    ///   - fabricIndex: The local fabric index.
    ///   - peerFabricID: The initiator's fabric ID.
    ///   - ticketStore: The store where the ticket should be saved.
    ///   - ticketLifetime: Ticket validity period in seconds (default: 3600).
    public static func storeResumptionTicket(
        resumptionID: Data,
        sharedSecret: Data,
        peerNodeID: NodeID,
        fabricIndex: FabricIndex,
        peerFabricID: FabricID,
        ticketStore: ResumptionTicketStore,
        ticketLifetime: TimeInterval = 3600
    ) async {
        let ticket = ResumptionTicket(
            resumptionID: resumptionID,
            sharedSecret: sharedSecret,
            peerNodeID: peerNodeID,
            peerFabricID: peerFabricID,
            fabricIndex: fabricIndex,
            expiryDate: Date().addingTimeInterval(ticketLifetime)
        )
        await ticketStore.store(ticket: ticket)
    }

    // MARK: - Resumption Handling (Responder)

    /// Attempt to handle a Sigma1 with resumption fields (abbreviated session re-establishment).
    ///
    /// If the Sigma1 contains a `resumptionID` field and a matching unexpired ticket exists,
    /// returns a Sigma2Resume message and derived session keys. Otherwise returns `nil`,
    /// indicating the responder should fall back to the full Sigma exchange.
    ///
    /// - Parameters:
    ///   - sigma1: The decoded Sigma1 message.
    ///   - ticketStore: The store to look up resumption tickets.
    ///   - responderSessionID: The responder's proposed session ID.
    /// - Returns: Tuple of (sigma2ResumeData, sessionKeys, peerNodeID, fabricIndex) or nil.
    public static func tryResponderResumption(
        sigma1: Sigma1Message,
        ticketStore: ResumptionTicketStore,
        responderSessionID: UInt16
    ) async throws -> (sigma2ResumeData: Data, sessionKeys: SessionKeys, peerNodeID: NodeID, fabricIndex: FabricIndex)? {
        // Resumption requires both resumptionID and initiatorResumeMIC fields
        guard let incomingResumptionID = sigma1.resumptionID,
              let initiatorMIC = sigma1.initiatorResumeMIC else {
            return nil
        }

        // Look up and consume the ticket
        guard let ticket = await ticketStore.consume(resumptionID: incomingResumptionID) else {
            return nil
        }

        // Derive the resume key
        let resumeKey = try CASEResumption.deriveResumeKey(
            sharedSecret: ticket.sharedSecret,
            resumptionID: incomingResumptionID
        )

        // Verify the initiator's MIC before proceeding
        guard try CASEResumption.verifyInitiatorResumeMIC(
            resumeKey: resumeKey,
            initiatorRandom: sigma1.initiatorRandom,
            resumptionID: incomingResumptionID,
            initiatorEphPubKey: sigma1.initiatorEphPubKey,
            mic: initiatorMIC
        ) else {
            return nil
        }

        // Derive session keys for the resumed session
        let sessionKeys = try CASEResumption.deriveResumedSessionKeys(
            sharedSecret: ticket.sharedSecret,
            resumptionID: incomingResumptionID
        )

        // Generate a new resumption ID for the next resumption
        let newResumptionID = generateRandom(count: 16)

        // Compute responder resume MIC
        let responderMIC = try CASEResumption.computeResponderResumeMIC(
            resumeKey: resumeKey,
            initiatorRandom: sigma1.initiatorRandom,
            resumptionID: incomingResumptionID
        )

        let sigma2Resume = Sigma2ResumeMessage(
            resumptionID: newResumptionID,
            sigma2ResumeMIC: responderMIC,
            responderSessionID: responderSessionID
        )

        return (sigma2Resume.tlvEncode(), sessionKeys, ticket.peerNodeID, ticket.fabricIndex)
    }

    // MARK: - Resumption Handling (Initiator)

    /// Handle a Sigma2Resume response (abbreviated resumption).
    ///
    /// Call this when the responder sends Sigma2Resume instead of full Sigma2.
    /// Verifies the responder MIC and derives session keys from the original shared secret.
    ///
    /// - Parameters:
    ///   - context: The initiator context from `initiatorStep1WithResumption`.
    ///   - sigma2ResumeData: The raw Sigma2Resume TLV bytes.
    ///   - originalSharedSecret: The shared secret from the prior CASE exchange.
    /// - Returns: Tuple of (sessionKeys, responderSessionID).
    public static func initiatorHandleResume(
        context: InitiatorContext,
        sigma2ResumeData: Data,
        originalSharedSecret: Data
    ) throws -> (sessionKeys: SessionKeys, responderSessionID: UInt16) {
        let sigma2Resume = try Sigma2ResumeMessage.fromTLV(sigma2ResumeData)

        // Verify the responder's MIC using the original resumption ID from Sigma1
        if let originalResumptionID = context.resumptionID {
            let resumeKey = try CASEResumption.deriveResumeKey(
                sharedSecret: originalSharedSecret,
                resumptionID: originalResumptionID
            )
            let expectedMIC = try CASEResumption.computeResponderResumeMIC(
                resumeKey: resumeKey,
                initiatorRandom: context.initiatorRandom,
                resumptionID: originalResumptionID
            )
            guard expectedMIC == sigma2Resume.sigma2ResumeMIC else {
                throw CASEError.decryptionFailed
            }
        }

        // Derive session keys from the original shared secret and the new resumption ID
        let sessionKeys = try CASEResumption.deriveResumedSessionKeys(
            sharedSecret: originalSharedSecret,
            resumptionID: sigma2Resume.resumptionID
        )

        return (sessionKeys, sigma2Resume.responderSessionID)
    }

    /// Create Sigma1 with optional resumption fields for abbreviated re-establishment.
    ///
    /// Builds a Sigma1 message that includes `resumptionID` and `initiatorResumeMIC`
    /// fields, signaling to the responder that resumption should be attempted.
    ///
    /// - Parameters:
    ///   - fabricInfo: The initiator's fabric information.
    ///   - peerNodeID: The target node's operational ID.
    ///   - peerFabricID: The target node's fabric ID.
    ///   - peerRootPublicKey: The target fabric's root CA public key.
    ///   - initiatorSessionID: Proposed session ID for the initiator side.
    ///   - resumptionID: The 16-byte resumption ID from a prior CASE ticket.
    ///   - sharedSecret: The ECDH shared secret from the prior CASE exchange.
    /// - Returns: Tuple of (context for step 2, sigma1 TLV data).
    public static func initiatorStep1WithResumption(
        fabricInfo: FabricInfo,
        peerNodeID: NodeID,
        peerFabricID: FabricID,
        peerRootPublicKey: P256.Signing.PublicKey,
        initiatorSessionID: UInt16,
        resumptionID: Data,
        sharedSecret: Data
    ) throws -> (context: InitiatorContext, sigma1Data: Data) {
        let random = generateRandom(count: 32)
        let ephKey = P256.KeyAgreement.PrivateKey()
        let ipk = fabricInfo.deriveIPK()

        let destinationID = CASEKeyDerivation.computeDestinationID(
            initiatorRandom: random,
            rootPublicKey: Data(peerRootPublicKey.x963Representation),
            fabricID: peerFabricID,
            nodeID: peerNodeID,
            ipk: ipk
        )

        // Derive resume key and compute MIC
        let resumeKey = try CASEResumption.deriveResumeKey(
            sharedSecret: sharedSecret,
            resumptionID: resumptionID
        )
        let resumeMIC = try CASEResumption.computeInitiatorResumeMIC(
            resumeKey: resumeKey,
            initiatorRandom: random,
            resumptionID: resumptionID,
            initiatorEphPubKey: Data(ephKey.publicKey.x963Representation)
        )

        let sigma1 = Sigma1Message(
            initiatorRandom: random,
            initiatorSessionID: initiatorSessionID,
            destinationID: destinationID,
            initiatorEphPubKey: Data(ephKey.publicKey.x963Representation),
            resumptionID: resumptionID,
            initiatorResumeMIC: resumeMIC
        )

        let context = InitiatorContext(
            initiatorRandom: random,
            initiatorSessionID: initiatorSessionID,
            initiatorEphKey: ephKey,
            fabricInfo: fabricInfo,
            ipk: ipk,
            resumptionID: resumptionID
        )

        return (context, sigma1.tlvEncode())
    }

    // MARK: - Helpers

    private static func generateRandom(count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        for i in 0..<count { bytes[i] = UInt8.random(in: 0...255) }
        return Data(bytes)
    }
}
