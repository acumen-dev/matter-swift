// ControllerSession.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import MatterTypes
import MatterCrypto
import MatterProtocol

/// Controller-side CASE session establishment.
///
/// Wraps `CASEProtocolHandler` for establishing encrypted sessions to
/// commissioned devices. Each method is a pure step — caller handles
/// message transport.
///
/// ## Protocol Flow
///
/// 1. `createSigma1()` → send Sigma1
/// 2. `handleSigma2()` → receive Sigma2, send Sigma3, establish session
///
/// ```swift
/// let cs = ControllerSession(fabricManager: mgr)
/// let (sigma1, ctx) = cs.createSigma1(
///     peerNodeID: deviceNodeID,
///     initiatorSessionID: 42
/// )
/// // ... send sigma1, receive sigma2 ...
/// let (sigma3, session) = try cs.handleSigma2(
///     sigma2Data: sigma2,
///     context: ctx,
///     localSessionID: 42
/// )
/// // ... send sigma3 → session established ...
/// ```
public struct ControllerSession: Sendable {

    private let fabricManager: FabricManager

    public init(fabricManager: FabricManager) {
        self.fabricManager = fabricManager
    }

    // MARK: - Context

    /// Context for an in-progress CASE handshake.
    public struct HandshakeContext: Sendable {
        let caseContext: CASEProtocolHandler.InitiatorHandshakeContext
        let handler: CASEProtocolHandler
        let peerNodeID: NodeID
    }

    // MARK: - Sigma1

    /// Create a Sigma1 message to initiate a CASE session.
    ///
    /// - Parameters:
    ///   - peerNodeID: The target device's operational node ID.
    ///   - initiatorSessionID: Session ID to propose.
    /// - Returns: TLV-encoded Sigma1 and handshake context.
    public func createSigma1(
        peerNodeID: NodeID,
        initiatorSessionID: UInt16
    ) -> (sigma1: Data, context: HandshakeContext) {
        let fabricInfo = fabricManager.controllerFabricInfo
        let ipkEpochKey = fabricManager.ipkEpochKey

        let handler = CASEProtocolHandler(
            fabricInfo: fabricInfo,
            ipkEpochKey: ipkEpochKey
        )

        let (sigma1Data, caseCtx) = handler.createSigma1(
            peerNodeID: peerNodeID,
            peerFabricID: fabricInfo.fabricID,
            peerRootPublicKey: fabricInfo.rootPublicKey,
            initiatorSessionID: initiatorSessionID
        )

        let handshakeCtx = HandshakeContext(
            caseContext: caseCtx,
            handler: handler,
            peerNodeID: peerNodeID
        )

        return (sigma1Data, handshakeCtx)
    }

    // MARK: - Sigma2 → Sigma3 + Session

    /// Handle Sigma2 response and produce Sigma3 + secure session.
    ///
    /// - Parameters:
    ///   - sigma2Data: Raw Sigma2 TLV payload from the device.
    ///   - context: Context from `createSigma1()`.
    ///   - localSessionID: Local session ID for the new session.
    /// - Returns: TLV-encoded Sigma3 and the established secure session.
    public func handleSigma2(
        sigma2Data: Data,
        context: HandshakeContext,
        localSessionID: UInt16
    ) throws -> (sigma3: Data, session: SecureSession) {
        let fabricInfo = fabricManager.controllerFabricInfo

        // The responder's RCAC is our own RCAC (same fabric)
        let responderRCAC = fabricInfo.rcac

        let (sigma3Data, session) = try context.handler.handleSigma2(
            payload: sigma2Data,
            context: context.caseContext,
            responderRCAC: responderRCAC,
            localSessionID: localSessionID
        )

        return (sigma3Data, session)
    }
}
