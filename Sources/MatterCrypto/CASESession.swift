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
            ipk: ipk
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
    /// - Returns: Session keys.
    public static func responderStep2(
        context: ResponderContext,
        sigma3Data: Data,
        initiatorRCAC: MatterCertificate
    ) throws -> SessionKeys {
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

        return sessionKeys
    }

    // MARK: - Helpers

    private static func generateRandom(count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        for i in 0..<count { bytes[i] = UInt8.random(in: 0...255) }
        return Data(bytes)
    }
}
