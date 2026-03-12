// PASESessionTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
@testable import MatterController
@testable import MatterCrypto
@testable import MatterProtocol
import MatterTypes

@Suite("PASE Session")
struct PASESessionTests {

    /// Run a full PASE round-trip: prover (controller) ↔ verifier (device).
    private func runPASERoundTrip(
        passcode: UInt32 = 20202021,
        devicePasscode: UInt32? = nil
    ) throws -> (session: SecureSession, verifierKe: Data) {
        let actualDevicePasscode = devicePasscode ?? passcode

        // Device-side: pre-compute verifier from the device's passcode
        let salt = Data(repeating: 0xAA, count: 16)
        let iterations: Int = 1000
        let verifier = try Spake2p.computeVerifier(
            passcode: actualDevicePasscode,
            salt: salt,
            iterations: iterations
        )

        // --- Step 1: Controller creates PBKDFParamRequest ---
        let pase = PASESession(passcode: passcode)
        let (pbkdfReqData, ctx1) = pase.createPBKDFParamRequest(initiatorSessionID: 42)

        // Verify the request can be parsed
        let pbkdfReq = try PASEMessages.PBKDFParamRequest.fromTLV(pbkdfReqData)
        #expect(pbkdfReq.initiatorSessionID == 42)
        #expect(pbkdfReq.initiatorRandom.count == 32)

        // --- Device responds with PBKDFParamResponse ---
        var responderRandom = Data(count: 32)
        for i in 0..<32 { responderRandom[i] = UInt8.random(in: 0...255) }

        let pbkdfResp = PASEMessages.PBKDFParamResponse(
            initiatorRandom: pbkdfReq.initiatorRandom,
            responderRandom: responderRandom,
            responderSessionID: 100,
            iterations: UInt32(iterations),
            salt: salt
        )
        let pbkdfRespData = pbkdfResp.tlvEncode()

        // --- Step 2: Controller handles response, produces Pake1 ---
        let (pake1Data, ctx2) = try pase.handlePBKDFParamResponse(
            pbkdfParamResponse: pbkdfRespData,
            context: ctx1
        )

        let pake1 = try PASEMessages.Pake1Message.fromTLV(pake1Data)
        #expect(pake1.pA.count == 65) // Uncompressed P-256 point

        // --- Device runs verifier step 1: produce Pake2 ---
        let hashContext = Spake2p.computeHashContext(
            pbkdfParamRequest: pbkdfReqData,
            pbkdfParamResponse: pbkdfRespData
        )

        let (verifierCtx, pB, cB) = try Spake2p.verifierStep1(
            pA: pake1.pA,
            verifier: verifier,
            hashContext: hashContext
        )

        let pake2 = PASEMessages.Pake2Message(pB: pB, cB: cB)
        let pake2Data = pake2.tlvEncode()

        // --- Step 3: Controller handles Pake2, produces Pake3 ---
        let (pake3Data, session, responderSessionID) = try pase.handlePake2(
            pake2Data: pake2Data,
            context: ctx2
        )

        #expect(responderSessionID == 100)

        // --- Device verifies Pake3 ---
        let pake3 = try PASEMessages.Pake3Message.fromTLV(pake3Data)
        let verifierKe = try Spake2p.verifierStep2(
            context: verifierCtx,
            cA: pake3.cA
        )

        return (session, verifierKe)
    }

    @Test("Full PASE round-trip establishes session")
    func fullRoundTrip() throws {
        let (session, _) = try runPASERoundTrip()

        #expect(session.localSessionID == 42)
        #expect(session.peerSessionID == 100)
        #expect(session.establishment == .pase)
        #expect(session.peerNodeID == .unspecified)
    }

    @Test("Session has encryption keys")
    func sessionHasKeys() throws {
        let (session, _) = try runPASERoundTrip()

        #expect(session.encryptKey != nil)
        #expect(session.decryptKey != nil)
        #expect(session.attestationKey != nil)
    }

    @Test("Session keys match between prover and verifier")
    func sessionKeysMatch() throws {
        let (session, verifierKe) = try runPASERoundTrip()

        // Derive session keys from verifier's Ke
        let verifierSessionKeys = KeyDerivation.deriveSessionKeys(sharedSecret: verifierKe)

        // Prover encrypts with I2R, verifier decrypts with I2R
        // Prover decrypts with R2I, verifier encrypts with R2I
        let proverEncryptData = session.encryptKey!.withUnsafeBytes { Data($0) }
        let verifierI2RData = verifierSessionKeys.i2rKey.withUnsafeBytes { Data($0) }
        #expect(proverEncryptData == verifierI2RData)

        let proverDecryptData = session.decryptKey!.withUnsafeBytes { Data($0) }
        let verifierR2IData = verifierSessionKeys.r2iKey.withUnsafeBytes { Data($0) }
        #expect(proverDecryptData == verifierR2IData)
    }

    @Test("Wrong passcode fails Pake2 verification")
    func wrongPasscodeFails() throws {
        #expect(throws: MatterCrypto.CryptoError.self) {
            _ = try runPASERoundTrip(passcode: 20202021, devicePasscode: 12345678)
        }
    }

    @Test("PBKDFParamResponse with mismatched random fails")
    func mismatchedRandomFails() throws {
        let pase = PASESession(passcode: 20202021)
        let (_, ctx1) = pase.createPBKDFParamRequest(initiatorSessionID: 1)

        // Build response with wrong initiator random
        let badResponse = PASEMessages.PBKDFParamResponse(
            initiatorRandom: Data(repeating: 0xFF, count: 32),
            responderRandom: Data(repeating: 0x00, count: 32),
            responderSessionID: 1,
            iterations: 1000,
            salt: Data(repeating: 0x00, count: 16)
        )

        #expect(throws: ControllerError.self) {
            _ = try pase.handlePBKDFParamResponse(
                pbkdfParamResponse: badResponse.tlvEncode(),
                context: ctx1
            )
        }
    }

    @Test("Session IDs are preserved through handshake")
    func sessionIDsPreserved() throws {
        let pase = PASESession(passcode: 20202021)
        let (pbkdfReqData, ctx1) = pase.createPBKDFParamRequest(initiatorSessionID: 777)

        let pbkdfReq = try PASEMessages.PBKDFParamRequest.fromTLV(pbkdfReqData)
        #expect(pbkdfReq.initiatorSessionID == 777)
        #expect(ctx1.initiatorSessionID == 777)
    }

    @Test("Multiple independent PASE sessions")
    func multipleIndependentSessions() throws {
        let (session1, _) = try runPASERoundTrip()
        let (session2, _) = try runPASERoundTrip()

        // Sessions should have the same session IDs (since we use the same test params)
        // but different encryption keys (since SPAKE2+ uses random scalars)
        #expect(session1.localSessionID == session2.localSessionID)

        let key1 = session1.encryptKey!.withUnsafeBytes { Data($0) }
        let key2 = session2.encryptKey!.withUnsafeBytes { Data($0) }
        // Extremely unlikely to be equal due to random scalar generation
        #expect(key1 != key2)
    }
}
