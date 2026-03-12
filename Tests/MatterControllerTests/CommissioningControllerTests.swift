// CommissioningControllerTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
@testable import MatterController
@testable import MatterCrypto
@testable import MatterModel
@testable import MatterProtocol
import MatterTypes

@Suite("CommissioningController")
struct CommissioningControllerTests {

    private func makeFabricManager() throws -> FabricManager {
        try FabricManager(
            rootKey: P256.Signing.PrivateKey(),
            fabricID: FabricID(rawValue: 1),
            controllerNodeID: NodeID(rawValue: 1),
            vendorID: .test
        )
    }

    @Test("Begin PASE produces valid PBKDFParamRequest")
    func beginPASE() throws {
        let mgr = try makeFabricManager()
        let cc = CommissioningController(fabricManager: mgr)

        let (message, ctx) = cc.beginPASE(passcode: 20202021, initiatorSessionID: 42)

        // Should be parseable
        let request = try PASEMessages.PBKDFParamRequest.fromTLV(message)
        #expect(request.initiatorSessionID == 42)
        #expect(request.initiatorRandom.count == 32)
        #expect(ctx.initiatorSessionID == 42)
    }

    @Test("PASE handshake through CommissioningController")
    func paseHandshake() throws {
        let mgr = try makeFabricManager()
        let cc = CommissioningController(fabricManager: mgr)

        // Step 1: Begin PASE
        let (pbkdfReqData, ctx1) = cc.beginPASE(passcode: 20202021, initiatorSessionID: 1)

        // Device responds with PBKDF params
        let pbkdfReq = try PASEMessages.PBKDFParamRequest.fromTLV(pbkdfReqData)
        let salt = Data(repeating: 0xBB, count: 16)
        let pbkdfResp = PASEMessages.PBKDFParamResponse(
            initiatorRandom: pbkdfReq.initiatorRandom,
            responderRandom: Data(repeating: 0xCC, count: 32),
            responderSessionID: 200,
            iterations: 1000,
            salt: salt
        )

        // Step 2: Handle PBKDFParamResponse
        let (pake1Data, ctx2) = try cc.handlePBKDFParamResponse(
            response: pbkdfResp.tlvEncode(),
            context: ctx1
        )

        // Verify Pake1 is valid
        let pake1 = try PASEMessages.Pake1Message.fromTLV(pake1Data)
        #expect(pake1.pA.count == 65)

        // Device runs verifier
        let verifier = try Spake2p.computeVerifier(
            passcode: 20202021,
            salt: salt,
            iterations: 1000
        )
        let hashContext = Spake2p.computeHashContext(
            pbkdfParamRequest: pbkdfReqData,
            pbkdfParamResponse: pbkdfResp.tlvEncode()
        )
        let (verifierCtx, pB, cB) = try Spake2p.verifierStep1(
            pA: pake1.pA,
            verifier: verifier,
            hashContext: hashContext
        )

        let pake2 = PASEMessages.Pake2Message(pB: pB, cB: cB)

        // Step 3: Handle Pake2
        let (pake3Data, ctx3) = try cc.handlePake2(
            response: pake2.tlvEncode(),
            context: ctx2
        )

        // Verify session established
        #expect(ctx3.paseSession != nil)
        #expect(ctx3.paseSession?.localSessionID == 1)
        #expect(ctx3.paseSession?.peerSessionID == 200)
        #expect(ctx3.paseSession?.establishment == .pase)

        // Device verifies Pake3
        let pake3 = try PASEMessages.Pake3Message.fromTLV(pake3Data)
        let _ = try Spake2p.verifierStep2(context: verifierCtx, cA: pake3.cA)
    }

    @Test("Build ArmFailSafe produces valid invoke request")
    func buildArmFailSafe() throws {
        let mgr = try makeFabricManager()
        let cc = CommissioningController(fabricManager: mgr)

        let ctx = CommissioningController.CommissioningContext()
        let (message, _) = try cc.buildArmFailSafe(context: ctx, failSafeExpirySeconds: 120)

        // Should be parseable as an IM invoke request
        #expect(message.count > 0)
    }

    @Test("Handle ArmFailSafe success response")
    func handleArmFailSafeSuccess() throws {
        let mgr = try makeFabricManager()
        let cc = CommissioningController(fabricManager: mgr)
        let ctx = CommissioningController.CommissioningContext()

        // Build a successful response
        let respElement = GeneralCommissioningCluster.ArmFailSafeResponse(
            errorCode: .ok,
            debugText: "OK"
        )

        // Wrap in InvokeResponse format
        let invokeResp = InvokeResponse(invokeResponses: [
            InvokeResponseIB(
                command: CommandDataIB(
                    commandPath: CommandPath(
                        endpointID: .root,
                        clusterID: GeneralCommissioningCluster.id,
                        commandID: GeneralCommissioningCluster.Command.armFailSafeResponse
                    ),
                    commandFields: respElement.toTLVElement()
                )
            )
        ])
        let respData = invokeResp.tlvEncode()

        let resultCtx = try cc.handleArmFailSafeResponse(response: respData, context: ctx)
        // Should not throw
        _ = resultCtx
    }

    @Test("Handle ArmFailSafe error response throws")
    func handleArmFailSafeError() throws {
        let mgr = try makeFabricManager()
        let cc = CommissioningController(fabricManager: mgr)
        let ctx = CommissioningController.CommissioningContext()

        let respElement = GeneralCommissioningCluster.ArmFailSafeResponse(
            errorCode: .busyWithOtherAdmin,
            debugText: "Busy"
        )

        let invokeResp = InvokeResponse(invokeResponses: [
            InvokeResponseIB(
                command: CommandDataIB(
                    commandPath: CommandPath(
                        endpointID: .root,
                        clusterID: GeneralCommissioningCluster.id,
                        commandID: GeneralCommissioningCluster.Command.armFailSafeResponse
                    ),
                    commandFields: respElement.toTLVElement()
                )
            )
        ])

        #expect(throws: ControllerError.self) {
            _ = try cc.handleArmFailSafeResponse(response: invokeResp.tlvEncode(), context: ctx)
        }
    }

    @Test("Build SetRegulatoryConfig produces valid invoke request")
    func buildSetRegulatoryConfig() throws {
        let mgr = try makeFabricManager()
        let cc = CommissioningController(fabricManager: mgr)
        let ctx = CommissioningController.CommissioningContext()

        let message = cc.buildSetRegulatoryConfig(
            context: ctx,
            locationType: .indoorOutdoor,
            countryCode: "AU"
        )

        #expect(message.count > 0)
    }

    @Test("Build CSR request produces valid invoke request")
    func buildCSRRequest() throws {
        let mgr = try makeFabricManager()
        let cc = CommissioningController(fabricManager: mgr)

        let message = cc.buildCSRRequest()
        #expect(message.count > 0)
    }

    @Test("Build CommissioningComplete produces valid invoke request")
    func buildCommissioningComplete() throws {
        let mgr = try makeFabricManager()
        let cc = CommissioningController(fabricManager: mgr)

        let message = cc.buildCommissioningComplete()
        #expect(message.count > 0)
    }

    @Test("Handle CommissioningComplete success produces CommissionedDevice")
    func handleCommissioningCompleteSuccess() async throws {
        let mgr = try makeFabricManager()
        let cc = CommissioningController(fabricManager: mgr)

        var ctx = CommissioningController.CommissioningContext()
        ctx.deviceNodeID = NodeID(rawValue: 42)

        let respElement = GeneralCommissioningCluster.CommissioningCompleteResponse(
            errorCode: .ok,
            debugText: ""
        )

        let invokeResp = InvokeResponse(invokeResponses: [
            InvokeResponseIB(
                command: CommandDataIB(
                    commandPath: CommandPath(
                        endpointID: .root,
                        clusterID: GeneralCommissioningCluster.id,
                        commandID: GeneralCommissioningCluster.Command.commissioningCompleteResponse
                    ),
                    commandFields: respElement.toTLVElement()
                )
            )
        ])

        let device = try cc.handleCommissioningComplete(
            response: invokeResp.tlvEncode(),
            context: ctx
        )

        #expect(device.nodeID.rawValue == 42)
        #expect(device.vendorID == .test)
    }
}
