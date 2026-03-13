// CASEProtocolHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import MatterTypes
import MatterCrypto

/// Wires CASE session establishment into the protocol layer.
///
/// Handles the Sigma1/Sigma2/Sigma3 exchange to establish an encrypted
/// `SecureSession` with derived session keys. Both initiator and responder
/// roles are supported.
///
/// Usage:
/// ```swift
/// // Responder: handle incoming Sigma1
/// let handler = CASEProtocolHandler(fabricInfo: myFabric)
/// let (sigma2, context) = try handler.handleSigma1(payload: sigma1Data)
/// // ... send sigma2 ...
/// let session = try handler.handleSigma3(payload: sigma3Data, context: context)
///
/// // Initiator: start CASE
/// let (sigma1, context) = try handler.createSigma1(peerNodeID: target, ...)
/// // ... send sigma1, receive sigma2 ...
/// let (sigma3, session) = try handler.handleSigma2(payload: sigma2Data, context: context)
/// // ... send sigma3 ...
/// ```
public struct CASEProtocolHandler: Sendable {

    private let fabricInfo: FabricInfo
    private let ipkEpochKey: Data

    /// Initialize a CASE protocol handler.
    ///
    /// - Parameters:
    ///   - fabricInfo: Local fabric info (NOC, keys, etc.)
    ///   - ipkEpochKey: Identity Protection Key epoch key (16 bytes).
    public init(fabricInfo: FabricInfo, ipkEpochKey: Data = Data(repeating: 0, count: 16)) {
        self.fabricInfo = fabricInfo
        self.ipkEpochKey = ipkEpochKey
    }

    // MARK: - Responder

    /// Context for an in-progress CASE responder handshake.
    public struct ResponderHandshakeContext: Sendable {
        let caseContext: CASESession.ResponderContext
        let initiatorSessionID: UInt16
    }

    /// Handle an incoming Sigma1 message (responder role).
    ///
    /// - Parameters:
    ///   - payload: Raw Sigma1 TLV payload.
    ///   - responderSessionID: Session ID to assign to this session.
    /// - Returns: Sigma2 payload to send, and context for completing the handshake.
    public func handleSigma1(
        payload: Data,
        responderSessionID: UInt16
    ) throws -> (sigma2Data: Data, context: ResponderHandshakeContext) {
        let (caseCtx, sigma2Data) = try CASESession.responderStep1(
            sigma1Data: payload,
            fabricInfo: fabricInfo,
            responderSessionID: responderSessionID
        )

        let sigma1 = try Sigma1Message.fromTLV(payload)
        let handshakeCtx = ResponderHandshakeContext(
            caseContext: caseCtx,
            initiatorSessionID: sigma1.initiatorSessionID
        )

        return (sigma2Data, handshakeCtx)
    }

    /// Handle an incoming Sigma3 message (responder role) and create a session.
    ///
    /// - Parameters:
    ///   - payload: Raw Sigma3 TLV payload.
    ///   - context: Context from `handleSigma1`.
    ///   - initiatorRCAC: The initiator's trusted root certificate (for chain validation).
    ///   - localSessionID: Local session ID for the new secure session.
    /// - Returns: A configured `SecureSession` with derived encryption keys.
    public func handleSigma3(
        payload: Data,
        context: ResponderHandshakeContext,
        initiatorRCAC: MatterCertificate,
        localSessionID: UInt16
    ) throws -> SecureSession {
        let (sessionKeys, peerNodeID) = try CASESession.responderStep2(
            context: context.caseContext,
            sigma3Data: payload,
            initiatorRCAC: initiatorRCAC
        )

        // Responder decrypts with I2R key, encrypts with R2I key
        return SecureSession(
            localSessionID: localSessionID,
            peerSessionID: context.initiatorSessionID,
            establishment: .case,
            peerNodeID: peerNodeID,
            fabricIndex: fabricInfo.fabricIndex,
            encryptKey: sessionKeys.r2iKey,
            decryptKey: sessionKeys.i2rKey,
            attestationKey: sessionKeys.attestationKey
        )
    }

    // MARK: - Initiator

    /// Context for an in-progress CASE initiator handshake.
    public struct InitiatorHandshakeContext: Sendable {
        let caseContext: CASESession.InitiatorContext
        let peerNodeID: NodeID
        let peerFabricID: FabricID
    }

    /// Create a Sigma1 message (initiator role).
    ///
    /// - Parameters:
    ///   - peerNodeID: Target node's ID.
    ///   - peerFabricID: Target node's fabric ID.
    ///   - peerRootPublicKey: Target node's root CA public key.
    ///   - initiatorSessionID: Session ID to propose.
    /// - Returns: Sigma1 payload to send, and context for completing the handshake.
    public func createSigma1(
        peerNodeID: NodeID,
        peerFabricID: FabricID,
        peerRootPublicKey: P256.Signing.PublicKey,
        initiatorSessionID: UInt16
    ) -> (sigma1Data: Data, context: InitiatorHandshakeContext) {
        let (caseCtx, sigma1Data) = CASESession.initiatorStep1(
            fabricInfo: fabricInfo,
            peerNodeID: peerNodeID,
            peerFabricID: peerFabricID,
            peerRootPublicKey: peerRootPublicKey,
            initiatorSessionID: initiatorSessionID
        )

        let handshakeCtx = InitiatorHandshakeContext(
            caseContext: caseCtx,
            peerNodeID: peerNodeID,
            peerFabricID: peerFabricID
        )

        return (sigma1Data, handshakeCtx)
    }

    /// Handle an incoming Sigma2 message (initiator role) and produce Sigma3.
    ///
    /// - Parameters:
    ///   - payload: Raw Sigma2 TLV payload.
    ///   - context: Context from `createSigma1`.
    ///   - responderRCAC: The responder's trusted root certificate (for chain validation).
    ///   - localSessionID: Local session ID for the new secure session.
    /// - Returns: Sigma3 payload to send, and the configured `SecureSession`.
    public func handleSigma2(
        payload: Data,
        context: InitiatorHandshakeContext,
        responderRCAC: MatterCertificate,
        localSessionID: UInt16
    ) throws -> (sigma3Data: Data, session: SecureSession) {
        let (sigma3Data, sessionKeys, responderSessionID) = try CASESession.initiatorStep2(
            context: context.caseContext,
            sigma2Data: payload,
            responderRCAC: responderRCAC
        )

        // Initiator encrypts with I2R key, decrypts with R2I key
        let session = SecureSession(
            localSessionID: localSessionID,
            peerSessionID: responderSessionID,
            establishment: .case,
            peerNodeID: context.peerNodeID,
            fabricIndex: fabricInfo.fabricIndex,
            encryptKey: sessionKeys.i2rKey,
            decryptKey: sessionKeys.r2iKey,
            attestationKey: sessionKeys.attestationKey
        )

        return (sigma3Data, session)
    }

    // MARK: - Exchange Header Helpers

    /// Build an exchange header for a CASE Sigma message.
    public static func exchangeHeader(
        opcode: SecureChannelOpcode,
        exchangeID: UInt16,
        isInitiator: Bool
    ) -> ExchangeHeader {
        ExchangeHeader(
            flags: ExchangeFlags(initiator: isInitiator, reliableDelivery: true),
            protocolOpcode: opcode.rawValue,
            exchangeID: exchangeID,
            protocolID: MatterProtocolID.secureChannel.rawValue
        )
    }
}
