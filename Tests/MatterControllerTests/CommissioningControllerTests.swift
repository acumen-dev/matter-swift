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

    private func locationCapabilityReport(_ value: UInt64) -> Data {
        ReportData(
            attributeReports: [AttributeReportIB(attributeData: AttributeDataIB(
                path: AttributePath(
                    endpointID: .root,
                    clusterID: GeneralCommissioningCluster.id,
                    attributeID: GeneralCommissioningCluster.Attribute.locationCapability
                ),
                data: .unsignedInt(value)
            ))],
            suppressResponse: true
        ).tlvEncode()
    }

    @Test("SetRegulatoryConfig location follows the device's LocationCapability",
          arguments: [
            (UInt64(0), GeneralCommissioningCluster.RegulatoryLocationType.indoor),
            (1, .outdoor),
            (2, .indoorOutdoor),
          ])
    func locationFollowsCapability(capability: UInt64, expected: GeneralCommissioningCluster.RegulatoryLocationType) throws {
        let cc = CommissioningController(fabricManager: try makeFabricManager())
        #expect(try cc.handleLocationCapabilityResponse(locationCapabilityReport(capability)) == expected)
    }

    @Test("An IndoorOutdoor device gets the preferred location")
    func indoorOutdoorUsesPreferred() throws {
        let cc = CommissioningController(fabricManager: try makeFabricManager())
        #expect(try cc.handleLocationCapabilityResponse(locationCapabilityReport(2), preferred: .outdoor) == .outdoor)
    }

    @Test("An out-of-range LocationCapability fails commissioning")
    func unknownCapabilityThrows() throws {
        let cc = CommissioningController(fabricManager: try makeFabricManager())
        for raw: UInt64 in [3, 0x1_00] {
            let error = #expect(throws: ControllerError.self) {
                try cc.handleLocationCapabilityResponse(locationCapabilityReport(raw))
            }
            guard case .commissioningFailed? = error else {
                Issue.record("expected commissioningFailed for \(raw), got \(String(describing: error))")
                continue
            }
        }
    }

    @Test("The LocationCapability read targets GeneralCommissioning on the root endpoint")
    func readLocationCapabilityRequest() throws {
        let cc = CommissioningController(fabricManager: try makeFabricManager())
        let request = try ReadRequest.fromTLV(cc.buildReadLocationCapability())
        #expect(request.attributeRequests == [AttributePath(
            endpointID: .root,
            clusterID: GeneralCommissioningCluster.id,
            attributeID: GeneralCommissioningCluster.Attribute.locationCapability
        )])
    }

    @Test("Build CSR request produces valid invoke request")
    func buildCSRRequest() throws {
        let mgr = try makeFabricManager()
        let cc = CommissioningController(fabricManager: mgr)

        let (message, nonce) = cc.buildCSRRequest()
        #expect(message.count > 0)
        #expect(nonce.count == 32)
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
        ctx.deviceFabricIndex = FabricIndex(rawValue: 5)
        ctx.dacVendorID = 0xFFF2
        ctx.dacProductID = 0x8001
        ctx.attestation = .verified(paaSubject: "CN=Test PAA", vendorID: 0xFFF2, productID: 0x8001)

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
        // The device's identifiers are its DAC's, not the controller's own vendor.
        #expect(device.vendorID == VendorID(rawValue: 0xFFF2))
        #expect(device.productID == ProductID(rawValue: 0x8001))
        #expect(device.attestation == ctx.attestation)
        #expect(device.fabricIndex == FabricIndex(rawValue: 5))
    }

    @Test("Handle CommissioningComplete without the device's fabric index fails commissioning")
    func handleCommissioningCompleteWithoutFabricIndex() throws {
        let cc = CommissioningController(fabricManager: try makeFabricManager())
        var ctx = CommissioningController.CommissioningContext()
        ctx.deviceNodeID = NodeID(rawValue: 42)

        let invokeResp = InvokeResponse(invokeResponses: [
            InvokeResponseIB(
                command: CommandDataIB(
                    commandPath: CommandPath(
                        endpointID: .root,
                        clusterID: GeneralCommissioningCluster.id,
                        commandID: GeneralCommissioningCluster.Command.commissioningCompleteResponse
                    ),
                    commandFields: GeneralCommissioningCluster.CommissioningCompleteResponse(
                        errorCode: .ok, debugText: ""
                    ).toTLVElement()
                )
            )
        ])

        let error = #expect(throws: ControllerError.self) {
            try cc.handleCommissioningComplete(response: invokeResp.tlvEncode(), context: ctx)
        }
        guard case .commissioningFailed? = error else {
            Issue.record("expected commissioningFailed, got \(String(describing: error))")
            return
        }
    }

    // MARK: - Response checks

    private func statusResponse(_ status: UInt8) -> Data {
        InvokeResponse(invokeResponses: [
            InvokeResponseIB(status: CommandStatusIB(
                commandPath: CommandPath(
                    endpointID: .root,
                    clusterID: ClusterID(rawValue: 0x003E),
                    commandID: CommandID(rawValue: 0x0B)
                ),
                status: StatusIB(status: status)
            ))
        ]).tlvEncode()
    }

    private func nocResponse(_ resp: OperationalCredentialsCluster.NOCResponse) -> Data {
        InvokeResponse(invokeResponses: [
            InvokeResponseIB(command: CommandDataIB(
                commandPath: CommandPath(
                    endpointID: .root,
                    clusterID: ClusterID(rawValue: 0x003E),
                    commandID: CommandID(rawValue: 0x08)
                ),
                commandFields: resp.toTLVElement()
            ))
        ]).tlvEncode()
    }

    /// The DAC key that signs ``csrResponse(csr:nonce:signedBy:)`` and the PASE attestation
    /// challenge it signs over, as ``attestedContext()`` carries them.
    private static let dacKey = P256.Signing.PrivateKey()
    private static let challenge = Data(repeating: 0x5C, count: 16)

    /// A context as attestation leaves it: the DAC key and the attestation challenge.
    private func attestedContext() -> CommissioningController.CommissioningContext {
        var ctx = CommissioningController.CommissioningContext()
        ctx.dacPublicKey = Self.dacKey.publicKey
        ctx.attestationChallenge = Self.challenge
        return ctx
    }

    private func csrResponse(csr: Data, nonce: Data, signedBy key: P256.Signing.PrivateKey = dacKey) throws -> Data {
        let elements = TLVEncoder.encode(
            .structure([
                .init(tag: .contextSpecific(1), value: .octetString(csr)),
                .init(tag: .contextSpecific(2), value: .octetString(nonce))
            ])
        )
        let resp = OperationalCredentialsCluster.CSRResponse(
            nocsrElements: elements,
            attestationSignature: try key.signature(for: elements + Self.challenge).rawRepresentation
        )
        return InvokeResponse(invokeResponses: [
            InvokeResponseIB(command: CommandDataIB(
                commandPath: CommandPath(
                    endpointID: .root,
                    clusterID: ClusterID(rawValue: 0x003E),
                    commandID: CommandID(rawValue: 0x05)
                ),
                commandFields: resp.toTLVElement()
            ))
        ]).tlvEncode()
    }

    @Test("CSR response: matching nonce and valid CSR issues a NOC for the CSR's key")
    func csrResponseAccepted() async throws {
        let cc = CommissioningController(fabricManager: try makeFabricManager())
        let nonce = Data((0..<32).map { UInt8($0) })
        let deviceKey = P256.Signing.PrivateKey()
        let csr = try PKCS10CSRBuilder.buildCSR(privateKey: deviceKey)
        let result = try await cc.handleCSRResponse(
            response: try csrResponse(csr: csr, nonce: nonce),
            expectedNonce: nonce,
            deviceNodeID: NodeID(rawValue: 2),
            context: attestedContext()
        )
        let request = try InvokeRequest.fromTLV(result.addNOCMessage)
        let fields = try #require(request.invokeRequests.first?.commandFields)
        let addNOC = try OperationalCredentialsCluster.AddNOCCommand.fromTLVElement(fields)
        let noc = try MatterCertificate.fromTLV(addNOC.nocValue)
        #expect(noc.publicKey == deviceKey.publicKey.x963Representation)
    }

    @Test("CSR response: nonce mismatch is rejected")
    func csrResponseNonceMismatch() async throws {
        let cc = CommissioningController(fabricManager: try makeFabricManager())
        let csr = try PKCS10CSRBuilder.buildCSR(privateKey: P256.Signing.PrivateKey())
        let sent = Data(repeating: 1, count: 32)
        let echoed = Data(repeating: 2, count: 32)
        await #expect(throws: ControllerError.commissioningFailed("CSR nonce mismatch")) {
            _ = try await cc.handleCSRResponse(
                response: try csrResponse(csr: csr, nonce: echoed),
                expectedNonce: sent,
                deviceNodeID: NodeID(rawValue: 2),
                context: attestedContext()
            )
        }
    }

    @Test("CSR response: a CSR with a bad signature is rejected")
    func csrResponseBadSignature() async throws {
        let cc = CommissioningController(fabricManager: try makeFabricManager())
        var csr = try PKCS10CSRBuilder.buildCSR(privateKey: P256.Signing.PrivateKey())
        let range = try #require(csr.range(of: Data("Matter".utf8)))
        csr[range.lowerBound] ^= 0x01
        let nonce = Data(repeating: 7, count: 32)
        do {
            _ = try await cc.handleCSRResponse(
                response: try csrResponse(csr: csr, nonce: nonce),
                expectedNonce: nonce,
                deviceNodeID: NodeID(rawValue: 2),
                context: attestedContext()
            )
            Issue.record("expected failure")
        } catch ControllerError.commissioningFailed(let message) {
            #expect(message.hasPrefix("Invalid CSR"))
            #expect(message.contains("badSignature"), "the failure must be the signature check, got \(message)")
        }
    }

    @Test("CSR response: an attestation signature by a key other than the DAC's is rejected")
    func csrResponseNotSignedByDAC() async throws {
        let cc = CommissioningController(fabricManager: try makeFabricManager())
        let csr = try PKCS10CSRBuilder.buildCSR(privateKey: P256.Signing.PrivateKey())
        let nonce = Data(repeating: 3, count: 32)
        await #expect(throws: ControllerError.commissioningFailed("CSR attestation signature invalid")) {
            _ = try await cc.handleCSRResponse(
                response: try csrResponse(csr: csr, nonce: nonce, signedBy: P256.Signing.PrivateKey()),
                expectedNonce: nonce,
                deviceNodeID: NodeID(rawValue: 2),
                context: attestedContext()
            )
        }
    }

    @Test("CSR response: without a DAC key from attestation it is rejected, never accepted unchecked")
    func csrResponseWithoutDACKey() async throws {
        let cc = CommissioningController(fabricManager: try makeFabricManager())
        let csr = try PKCS10CSRBuilder.buildCSR(privateKey: P256.Signing.PrivateKey())
        let nonce = Data(repeating: 4, count: 32)
        var context = CommissioningController.CommissioningContext()
        context.attestationChallenge = Self.challenge
        do {
            _ = try await cc.handleCSRResponse(
                response: try csrResponse(csr: csr, nonce: nonce),
                expectedNonce: nonce,
                deviceNodeID: NodeID(rawValue: 2),
                context: context
            )
            Issue.record("expected failure")
        } catch ControllerError.commissioningFailed(let message) {
            #expect(message.hasPrefix("CSR attestation signature cannot be checked"))
        }
    }

    // MARK: - Attestation

    private static let fingerprint = Data(repeating: 0xF1, count: 32)

    private func failed(_ reason: AttestationFailureReason, fingerprint: Data? = fingerprint) -> AttestationResult {
        .failed(AttestationFailure(reason: reason, dacFingerprint: fingerprint, detail: "test"))
    }

    @Test("Attestation: a verified result records the PAA and the DAC's VID/PID and key")
    func attestationVerified() throws {
        let cc = CommissioningController(fabricManager: try makeFabricManager())
        let key = P256.Signing.PrivateKey().publicKey
        let verified = VerifiedAttestation(
            vendorID: 0xFFF2, productID: 0x8001, paaSubject: "CN=Test PAA",
            dacFingerprint: Self.fingerprint, dacPublicKey: key)
        let ctx = try cc.applyAttestationResult(
            .verified(verified), dac: Data(), approvingUnverifiedDevice: nil, approvedAt: Date(),
            context: .init())
        #expect(ctx.attestation == .verified(paaSubject: "CN=Test PAA", vendorID: 0xFFF2, productID: 0x8001))
        #expect(ctx.dacPublicKey?.x963Representation == key.x963Representation)
        #expect(ctx.dacVendorID == 0xFFF2 && ctx.dacProductID == 0x8001)
    }

    @Test("Attestation: a failure is thrown unless its exact fingerprint is approved")
    func attestationFailureNeedsExactApproval() throws {
        let cc = CommissioningController(fabricManager: try makeFabricManager())
        var other = Self.fingerprint
        other[other.startIndex] ^= 0x01
        for approval in [nil, other] {
            #expect(throws: ControllerError.attestationFailed(
                AttestationFailure(reason: .untrustedRoot, dacFingerprint: Self.fingerprint, detail: "test"))) {
                _ = try cc.applyAttestationResult(
                    failed(.untrustedRoot), dac: Data(), approvingUnverifiedDevice: approval, approvedAt: Date(),
                    context: .init())
            }
        }
    }

    @Test("Attestation: a malformed failure is never approved, with or without a fingerprint")
    func malformedNeverApproved() throws {
        let cc = CommissioningController(fabricManager: try makeFabricManager())
        for fingerprint in [nil, Self.fingerprint] {
            #expect(throws: ControllerError.attestationFailed(
                AttestationFailure(reason: .malformed, dacFingerprint: fingerprint, detail: "test"))) {
                _ = try cc.applyAttestationResult(
                    failed(.malformed, fingerprint: fingerprint), dac: Data(),
                    approvingUnverifiedDevice: Self.fingerprint, approvedAt: Date(), context: .init())
            }
        }
    }

    @Test("Attestation: an approved failure carries on with the DAC's own key and identifiers")
    func approvedFailureUsesDAC() throws {
        let cc = CommissioningController(fabricManager: try makeFabricManager())
        let creds = try DeviceAttestationCredentials.testCredentials(vendorID: 0xFFF2, productID: 0x8001)
        let fingerprint = Data(SHA256.hash(data: creds.dacCertificate))
        let approvedAt = Date(timeIntervalSince1970: 1_800_000_000)
        let ctx = try cc.applyAttestationResult(
            failed(.untrustedRoot, fingerprint: fingerprint), dac: creds.dacCertificate,
            approvingUnverifiedDevice: fingerprint, approvedAt: approvedAt, context: .init())
        #expect(ctx.attestation == .overridden(dacFingerprint: fingerprint, reason: .untrustedRoot, approvedAt: approvedAt))
        #expect(ctx.dacPublicKey?.x963Representation == creds.dacPrivateKey.publicKey.x963Representation)
        #expect(ctx.dacVendorID == 0xFFF2 && ctx.dacProductID == 0x8001)
    }

    @Test("Attestation: an approved failure whose DAC key cannot be read is thrown")
    func approvedFailureWithoutDACKey() throws {
        let cc = CommissioningController(fabricManager: try makeFabricManager())
        #expect(throws: ControllerError.attestationFailed(
            AttestationFailure(reason: .untrustedRoot, dacFingerprint: Self.fingerprint, detail: "test"))) {
            _ = try cc.applyAttestationResult(
                failed(.untrustedRoot), dac: Data([0x30, 0x00]), approvingUnverifiedDevice: Self.fingerprint,
                approvedAt: Date(), context: .init())
        }
    }

    @Test("AttestationResponse: elements and signature are returned; a missing field is an error")
    func attestationResponseParsing() throws {
        let cc = CommissioningController(fabricManager: try makeFabricManager())
        func response(_ fields: [TLVElement.TLVField]) -> Data {
            InvokeResponse(invokeResponses: [
                InvokeResponseIB(command: CommandDataIB(
                    commandPath: CommandPath(
                        endpointID: .root,
                        clusterID: ClusterID(rawValue: 0x003E),
                        commandID: CommandID(rawValue: 0x01)
                    ),
                    commandFields: .structure(fields)
                ))
            ]).tlvEncode()
        }
        let elements = Data([1, 2, 3])
        let signature = Data(repeating: 9, count: 64)
        let parsed = try cc.handleAttestationResponse(response([
            .init(tag: .contextSpecific(0), value: .octetString(elements)),
            .init(tag: .contextSpecific(1), value: .octetString(signature)),
        ]))
        #expect(parsed.elements == elements && parsed.signature == signature)
        #expect(throws: ControllerError.self) {
            _ = try cc.handleAttestationResponse(response([
                .init(tag: .contextSpecific(0), value: .octetString(elements)),
            ]))
        }
    }

    @Test("Basic Information: a 16-bit value is read; anything else fails naming the attribute")
    func basicInformationResponse() throws {
        let cc = CommissioningController(fabricManager: try makeFabricManager())
        func report(_ value: TLVElement) -> Data {
            ReportData(attributeReports: [
                AttributeReportIB(attributeData: AttributeDataIB(
                    dataVersion: DataVersion(rawValue: 1),
                    path: AttributePath(
                        endpointID: .root, clusterID: BasicInformationCluster.id,
                        attributeID: BasicInformationCluster.Attribute.vendorID),
                    data: value
                ))
            ]).tlvEncode()
        }
        #expect(try cc.handleBasicInformationResponse(report(.unsignedInt(0xFFF2)), name: "VendorID") == 0xFFF2)
        for bad in [TLVElement.unsignedInt(0x1_0000), .utf8String("x")] {
            do {
                _ = try cc.handleBasicInformationResponse(report(bad), name: "VendorID")
                Issue.record("expected failure for \(bad)")
            } catch ControllerError.commissioningFailed(let message) {
                #expect(message.hasPrefix("Basic Information VendorID"))
            }
        }
    }

    @Test("AddTrustedRootCert: success passes, failure throws")
    func addTrustedRootCertResponse() throws {
        let cc = CommissioningController(fabricManager: try makeFabricManager())
        try cc.handleAddTrustedRootCertResponse(statusResponse(0x00))
        #expect(throws: ControllerError.self) {
            try cc.handleAddTrustedRootCertResponse(statusResponse(0x81))
        }
    }

    @Test("AddNOC: returns the device-assigned fabric index")
    func addNOCReturnsIndex() throws {
        let cc = CommissioningController(fabricManager: try makeFabricManager())
        let index = try cc.handleNOCResponse(nocResponse(.init(statusCode: .ok, fabricIndex: FabricIndex(rawValue: 3))))
        #expect(index == FabricIndex(rawValue: 3))
    }

    @Test("AddNOC: a non-ok status throws")
    func addNOCFailureThrows() throws {
        let cc = CommissioningController(fabricManager: try makeFabricManager())
        // A fabric index is present, so the status alone must cause the throw.
        let error = #expect(throws: ControllerError.self) {
            try cc.handleNOCResponse(nocResponse(.init(statusCode: .tableIsFull, fabricIndex: FabricIndex(rawValue: 3))))
        }
        guard case .commissioningFailed(let message)? = error else {
            Issue.record("expected commissioningFailed, got \(String(describing: error))")
            return
        }
        #expect(message.contains("tableIsFull"), "the failure must be the status, got \(message)")
    }

    @Test("AddNOC: a status-only response throws")
    func addNOCStatusOnlyThrows() throws {
        let cc = CommissioningController(fabricManager: try makeFabricManager())
        #expect(throws: ControllerError.self) {
            try cc.handleNOCResponse(statusResponse(0x00))
        }
    }

    @Test("ACL write: all SUCCESS passes, any failure throws")
    func aclWriteResponse() throws {
        let cc = CommissioningController(fabricManager: try makeFabricManager())
        let path = AttributePath(endpointID: .root, clusterID: ClusterID(rawValue: 0x001F), attributeID: AccessControlCluster.Attribute.acl)
        let ok = WriteResponse(writeResponses: [AttributeStatusIB(path: path, status: .success)]).tlvEncode()
        let bad = WriteResponse(writeResponses: [
            AttributeStatusIB(path: path, status: .success),
            AttributeStatusIB(path: path, status: .invalidAction)
        ]).tlvEncode()
        try cc.handleACLWriteResponse(ok)
        #expect(throws: ControllerError.self) { try cc.handleACLWriteResponse(bad) }
    }
}
