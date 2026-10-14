// ChipAttestationMeasurementTests.swift
// Copyright 2026 Monagle Pty Ltd
//
// What chip-all-clusters-app actually presents for device attestation, checked against
// TestAttestation.chipDevelopmentTrustStore(). Skips silently when the app has not been
// built (make ref-setup-app).

#if canImport(Network)
import Testing
import Foundation
import Crypto
import MatterTypes
import MatterModel
import MatterProtocol
import MatterTransport
import MatterCrypto
import MatterTestSupport
@testable import MatterController

// MARK: - ChipAttestationMeasurementTests

@Suite("CHIP device attestation", .serialized)
struct ChipAttestationMeasurementTests {

    static let passcode: UInt32 = 20202021
    /// 2026-10-14T00:00:00Z, inside the validity of the development chain and test PAA.
    static let now = Date(timeIntervalSince1970: 1_791_936_000)
    static let hangGuard: Duration = .seconds(30)

    private struct Failure: Error, CustomStringConvertible {
        let description: String
    }

    @Test("chip-all-clusters-app attests against chipDevelopmentTrustStore", .timeLimit(.minutes(3)))
    func appAttests() async throws {
        guard ChipAppRunner.findBinary() != nil else { return }   // skip when not built

        let kvs = FileManager.default.temporaryDirectory.appendingPathComponent("chip-kvs-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: kvs) }
        let port = freeUDPPort()
        try #require(port != 0, "a free port for the app")
        let app = try await ChipAppRunner.start(passcode: Self.passcode, port: port, kvsPath: kvs)
        let transport = LoopbackTransport()
        let messenger = ControllerMessenger(transport: transport, localNodeID: ControllerMessenger.randomEphemeralNodeID())

        var failure: (any Error)?
        do {
            try await transport.bind(port: 0)
            try await Self.measure(app: app, messenger: messenger, port: port)
        } catch {
            failure = error
        }
        await messenger.stop()
        await transport.close()
        await app.stop()
        if let failure {
            Issue.record("\(failure)\n--- app log ---\n\(app.log)")
        }
    }

    private static func measure(app: ChipAppRunner, messenger: ControllerMessenger, port: UInt16) async throws {
        let address = MatterAddress(host: "127.0.0.1", port: port)
        let cc = CommissioningController(fabricManager: try FabricManager(
            rootKey: P256.Signing.PrivateKey(), fabricID: FabricID(rawValue: 1),
            controllerNodeID: NodeID(rawValue: 1), vendorID: .test))

        // PASE on one unsecured exchange.
        let (pbkdfReq, ctx1) = cc.beginPASE(passcode: passcode, initiatorSessionID: 1)
        let handshake = await messenger.openExchange(peer: address)
        let context: CommissioningController.CommissioningContext
        do {
            let pbkdfResp = try await handshake.request(
                protocolID: .secureChannel, opcode: SecureChannelOpcode.pbkdfParamRequest.rawValue,
                payload: pbkdfReq, timeout: hangGuard)
            let (pake1, ctx2) = try cc.handlePBKDFParamResponse(response: pbkdfResp.payload, context: ctx1)
            let pake2 = try await handshake.request(
                protocolID: .secureChannel, opcode: SecureChannelOpcode.pasePake1.rawValue,
                payload: pake1, timeout: hangGuard)
            let (pake3, ctx3) = try cc.handlePake2(response: pake2.payload, context: ctx2)
            let status = try await handshake.request(
                protocolID: .secureChannel, opcode: SecureChannelOpcode.pasePake3.rawValue,
                payload: pake3, timeout: hangGuard)
            guard try StatusReportMessage.decode(from: status.payload).generalStatus == .success else {
                throw Failure(description: "PASE did not succeed")
            }
            context = ctx3
        } catch {
            await handshake.close()
            throw error
        }
        await handshake.close()

        guard let session = context.paseSession, let challenge = context.attestationChallenge else {
            throw Failure(description: "no PASE session or attestation challenge")
        }
        try await messenger.registerSession(session, peerAddress: address)

        func request(_ opcode: InteractionModelOpcode, _ payload: Data) async throws -> Data {
            let exchange = try await messenger.openExchange(sessionID: session.localSessionID)
            do {
                let response = try await exchange.request(
                    protocolID: .interactionModel, opcode: opcode.rawValue, payload: payload, timeout: hangGuard)
                await exchange.close()
                return response.payload
            } catch {
                await exchange.close()
                throw error
            }
        }

        // As commissioning does: the fail-safe is armed before the attestation commands.
        let (arm, _) = try cc.buildArmFailSafe(context: context)
        _ = try cc.handleArmFailSafeResponse(response: try await request(.invokeRequest, arm), context: context)

        // AttestationRequest with a random nonce.
        let (attestationRequest, nonce) = cc.buildAttestationRequest()
        let attestationResponse = try await request(.invokeRequest, attestationRequest)
        guard case .structure(let fields)? = try IMClient.parseInvokeResponse(attestationResponse),
              let elements = fields.first(where: { $0.tag == .contextSpecific(0) })?.value.dataValue,
              let signature = fields.first(where: { $0.tag == .contextSpecific(1) })?.value.dataValue
        else { throw Failure(description: "AttestationResponse is missing its elements or signature") }

        // DAC and PAI.
        let dac = try cc.handleCertificateChainResponse(
            try await request(.invokeRequest, cc.buildCertificateChainRequest(certificateType: 1)))
        let pai = try cc.handleCertificateChainResponse(
            try await request(.invokeRequest, cc.buildCertificateChainRequest(certificateType: 2)))

        // Basic Information VendorID and ProductID.
        func basicInformation(_ attribute: UInt32) async throws -> UInt16 {
            let read = IMClient.readAttributeRequest(
                endpointID: .root, clusterID: ClusterID(rawValue: 0x0028), attributeID: AttributeID(rawValue: attribute))
            guard let value = try IMClient.parseReadResponse(try await request(.readRequest, read)).uintValue,
                  let narrowed = UInt16(exactly: value)
            else { throw Failure(description: "Basic Information 0x\(String(attribute, radix: 16)) is not a UInt16") }
            return narrowed
        }
        let vendorID = try await basicInformation(0x0002)
        let productID = try await basicInformation(0x0004)

        let result = await DeviceAttestationVerifier(trustStore: try TestAttestation.chipDevelopmentTrustStore()).verify(
            dac: dac, pai: pai, attestationElements: elements, attestationSignature: signature,
            attestationChallenge: challenge, sentNonce: nonce,
            basicInformation: (vendorID, productID), now: now)

        // Recorded for the report.
        let (_, elementsTLV) = try TLVDecoder.decode(elements)
        var signerKeyIdentifier = "unreadable"
        if case .structure(let elementFields) = elementsTLV,
           let cdBytes = elementFields.first(where: { $0.tag == .contextSpecific(1) })?.value.dataValue,
           let cd = try? CertificationDeclaration(cmsDER: cdBytes) {
            signerKeyIdentifier = cd.signerKeyIdentifier.map { String(format: "%02X", $0) }.joined()
        }

        guard case .verified(let verified) = result else {
            throw Failure(description: "the app's attestation did not verify: \(result)\n"
                + "Basic Information VID 0x\(String(vendorID, radix: 16)) PID 0x\(String(productID, radix: 16)); "
                + "CD signer SKI \(signerKeyIdentifier)\nDAC \(dac.base64EncodedString())\nPAI \(pai.base64EncodedString())")
        }
        #expect(verified.vendorID == vendorID && verified.productID == productID)
    }
}
#endif
