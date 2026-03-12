// PASESession.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import MatterTypes
import MatterCrypto
import MatterProtocol

/// Controller-side PASE session establishment.
///
/// Wires the SPAKE2+ prover role into a step-by-step protocol flow
/// that mirrors `CASEProtocolHandler`. Each method takes context + response
/// data and returns the next message + updated context. No networking.
///
/// ## Protocol Flow (Initiator/Prover)
///
/// 1. `createPBKDFParamRequest()` → send PBKDFParamRequest
/// 2. `handlePBKDFParamResponse()` → receive PBKDFParamResponse, send Pake1
/// 3. `handlePake2()` → receive Pake2, send Pake3, establish session
///
/// ```swift
/// let pase = PASESession(passcode: 20202021)
/// let (pbkdfReq, ctx1) = pase.createPBKDFParamRequest(initiatorSessionID: 1)
/// // ... send pbkdfReq, receive pbkdfResp ...
/// let (pake1, ctx2) = try pase.handlePBKDFParamResponse(
///     pbkdfParamResponse: pbkdfResp,
///     context: ctx1
/// )
/// // ... send pake1, receive pake2 ...
/// let (pake3, session) = try pase.handlePake2(
///     pake2Data: pake2,
///     context: ctx2
/// )
/// // ... send pake3 → session established ...
/// ```
public struct PASESession: Sendable {

    /// The setup passcode for this commissioning session.
    private let passcode: UInt32

    public init(passcode: UInt32) {
        self.passcode = passcode
    }

    // MARK: - Context Types

    /// Context after PBKDFParamRequest has been sent.
    public struct PBKDFParamRequestContext: Sendable {
        public let initiatorRandom: Data
        public let initiatorSessionID: UInt16
        public let pbkdfParamRequestData: Data
    }

    /// Context after PBKDFParamResponse has been processed and Pake1 sent.
    public struct Pake1Context: Sendable {
        let proverContext: Spake2pProverContext
        let w1: Data
        let hashContext: Data
        let responderSessionID: UInt16
        let initiatorSessionID: UInt16
    }

    // MARK: - Step 1: PBKDFParamRequest

    /// Create the initial PBKDFParamRequest message.
    ///
    /// - Parameter initiatorSessionID: The session ID to propose to the device.
    /// - Returns: The TLV-encoded request and context for the next step.
    public func createPBKDFParamRequest(
        initiatorSessionID: UInt16
    ) -> (pbkdfParamRequest: Data, context: PBKDFParamRequestContext) {
        // Generate 32-byte random
        var initiatorRandom = Data(count: 32)
        for i in 0..<32 {
            initiatorRandom[i] = UInt8.random(in: 0...255)
        }

        let request = PASEMessages.PBKDFParamRequest(
            initiatorRandom: initiatorRandom,
            initiatorSessionID: initiatorSessionID
        )
        let encoded = request.tlvEncode()

        let context = PBKDFParamRequestContext(
            initiatorRandom: initiatorRandom,
            initiatorSessionID: initiatorSessionID,
            pbkdfParamRequestData: encoded
        )

        return (encoded, context)
    }

    // MARK: - Step 2: Handle PBKDFParamResponse → Pake1

    /// Process the device's PBKDFParamResponse and produce a Pake1 message.
    ///
    /// Derives SPAKE2+ w0/w1 from the passcode using the received PBKDF
    /// parameters, then runs the prover's step 1 to produce pA.
    ///
    /// - Parameters:
    ///   - pbkdfParamResponse: Raw TLV data of the PBKDFParamResponse.
    ///   - context: Context from `createPBKDFParamRequest()`.
    /// - Returns: TLV-encoded Pake1 message and context for step 3.
    public func handlePBKDFParamResponse(
        pbkdfParamResponse: Data,
        context: PBKDFParamRequestContext
    ) throws -> (pake1: Data, context: Pake1Context) {
        let response = try PASEMessages.PBKDFParamResponse.fromTLV(pbkdfParamResponse)

        // Verify the echoed initiator random matches
        guard response.initiatorRandom == context.initiatorRandom else {
            throw ControllerError.paseHandshakeFailed("Initiator random mismatch")
        }

        // Derive w0 and w1 from passcode + PBKDF parameters
        let (w0, w1) = Spake2p.deriveW0W1(
            passcode: passcode,
            salt: response.salt,
            iterations: Int(response.iterations)
        )

        // Compute SPAKE2+ hash context
        let hashContext = Spake2p.computeHashContext(
            pbkdfParamRequest: context.pbkdfParamRequestData,
            pbkdfParamResponse: pbkdfParamResponse
        )

        // Run prover step 1: generate pA
        let (proverCtx, pA) = try Spake2p.proverStep1(w0: w0)

        // Build Pake1 message
        let pake1 = PASEMessages.Pake1Message(pA: pA)
        let encoded = pake1.tlvEncode()

        let pake1Context = Pake1Context(
            proverContext: proverCtx,
            w1: w1,
            hashContext: hashContext,
            responderSessionID: response.responderSessionID,
            initiatorSessionID: context.initiatorSessionID
        )

        return (encoded, pake1Context)
    }

    // MARK: - Step 3: Handle Pake2 → Pake3 + Session

    /// Process the device's Pake2 message and produce Pake3 + session.
    ///
    /// Runs the prover's step 2 (verify cB, compute cA), derives session
    /// keys, and returns the Pake3 message and established session.
    ///
    /// - Parameters:
    ///   - pake2Data: Raw TLV data of the Pake2 message.
    ///   - context: Context from `handlePBKDFParamResponse()`.
    /// - Returns: TLV-encoded Pake3 message and the established secure session.
    public func handlePake2(
        pake2Data: Data,
        context: Pake1Context
    ) throws -> (pake3: Data, session: SecureSession, responderSessionID: UInt16) {
        let pake2 = try PASEMessages.Pake2Message.fromTLV(pake2Data)

        // Prover step 2: verify cB, compute cA and Ke
        let (cA, ke) = try Spake2p.proverStep2(
            context: context.proverContext,
            pB: pake2.pB,
            cB: pake2.cB,
            hashContext: context.hashContext,
            w1: context.w1
        )

        // Build Pake3 message
        let pake3 = PASEMessages.Pake3Message(cA: cA)
        let encoded = pake3.tlvEncode()

        // Derive session keys from Ke
        let sessionKeys = KeyDerivation.deriveSessionKeys(sharedSecret: ke)

        // Build secure session — initiator encrypts with I2R, decrypts with R2I
        let session = SecureSession(
            localSessionID: context.initiatorSessionID,
            peerSessionID: context.responderSessionID,
            establishment: .pase,
            peerNodeID: .unspecified,
            encryptKey: sessionKeys.i2rKey,
            decryptKey: sessionKeys.r2iKey,
            attestationKey: sessionKeys.attestationKey
        )

        return (encoded, session, context.responderSessionID)
    }
}
