// AttestationValidationTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
@testable import MatterController
@testable import MatterCrypto
@testable import MatterModel
@testable import MatterProtocol
import MatterTypes

/// Helpers for building simulated AttestationResponse data,
/// mirroring what the device-side OperationalCredentialsHandler produces.
private func buildAttestationResponse(
    nonce: Data,
    challenge: Data,
    dacKey: P256.Signing.PrivateKey
) throws -> Data {
    let cd = Data("testCD".utf8)
    let attestationElements = TLVEncoder.encode(
        .structure([
            .init(tag: .contextSpecific(1), value: .octetString(cd)),
            .init(tag: .contextSpecific(2), value: .octetString(nonce)),
            .init(tag: .contextSpecific(3), value: .unsignedInt(0)),
        ])
    )

    let messageToSign = attestationElements + challenge
    let sig = try dacKey.signature(for: messageToSign)

    let responseFields = TLVElement.structure([
        .init(tag: .contextSpecific(0), value: .octetString(attestationElements)),
        .init(tag: .contextSpecific(1), value: .octetString(Data(sig.derRepresentation))),
    ])

    // Wrap in InvokeResponse format
    let invokeResp = InvokeResponse(invokeResponses: [
        InvokeResponseIB(
            command: CommandDataIB(
                commandPath: CommandPath(
                    endpointID: .root,
                    clusterID: ClusterID(rawValue: 0x003E),
                    commandID: OperationalCredentialsCluster.Command.attestationResponse
                ),
                commandFields: responseFields
            )
        )
    ])
    return invokeResp.tlvEncode()
}

/// Build a minimal DER X.509 certificate containing a P-256 public key.
/// Delegates to the test credentials factory from DeviceAttestationCredentials.
private func buildTestDAC() throws -> (Data, P256.Signing.PrivateKey) {
    let creds = try DeviceAttestationCredentials.testCredentials()
    return (creds.dacCertificate, creds.dacPrivateKey)
}

@Suite("AttestationValidation")
struct AttestationValidationTests {

    private func makeFabricManager() throws -> FabricManager {
        try FabricManager(
            rootKey: P256.Signing.PrivateKey(),
            fabricID: FabricID(rawValue: 1),
            controllerNodeID: NodeID(rawValue: 1),
            vendorID: .test
        )
    }

    // MARK: - Test 1: Valid attestation response passes validation

    @Test("Valid AttestationResponse with matching nonce and correct signature passes validation")
    func validAttestationPasses() throws {
        let mgr = try makeFabricManager()
        let cc = CommissioningController(fabricManager: mgr)

        // Generate a fresh DAC key pair
        let (dacCertDER, dacKey) = try buildTestDAC()

        // Set up nonce and challenge
        var nonceBytes = [UInt8](repeating: 0xAB, count: 32)
        nonceBytes[0] = 0x01
        let sentNonce = Data(nonceBytes)

        var challengeBytes = [UInt8](repeating: 0xCD, count: 16)
        challengeBytes[0] = 0x02
        let challenge = Data(challengeBytes)

        // Build a valid AttestationResponse using the matching key
        let responseData = try buildAttestationResponse(
            nonce: sentNonce,
            challenge: challenge,
            dacKey: dacKey
        )

        // Extract DAC public key from the DER cert
        let dacPublicKey = try cc.extractPublicKeyFromCertificate(dacCertDER)
        #expect(dacPublicKey.rawRepresentation == dacKey.publicKey.rawRepresentation,
                "Extracted public key should match the DAC key")

        // Validate — should not throw
        #expect(throws: Never.self) {
            try cc.validateAttestationResponse(
                response: responseData,
                sentNonce: sentNonce,
                attestationChallenge: challenge,
                dacPublicKey: dacPublicKey
            )
        }
    }

    // MARK: - Test 2: Mismatched nonce causes validation failure

    @Test("AttestationResponse with mismatched nonce fails with attestationValidationFailed")
    func mismatchedNonceFails() throws {
        let mgr = try makeFabricManager()
        let cc = CommissioningController(fabricManager: mgr)

        let (_, dacKey) = try buildTestDAC()

        // Nonce we send vs different nonce device uses in the response
        let sentNonce = Data(repeating: 0xAA, count: 32)
        let differentNonce = Data(repeating: 0xBB, count: 32)  // device uses a different nonce
        let challenge = Data(repeating: 0xCC, count: 16)

        // Build response with the WRONG nonce echoed back
        let responseData = try buildAttestationResponse(
            nonce: differentNonce,
            challenge: challenge,
            dacKey: dacKey
        )

        let dacPublicKey = dacKey.publicKey

        // Validate — should throw attestationValidationFailed
        #expect(throws: ControllerError.self) {
            try cc.validateAttestationResponse(
                response: responseData,
                sentNonce: sentNonce,
                attestationChallenge: challenge,
                dacPublicKey: dacPublicKey
            )
        }

        // Verify it's specifically the nonce mismatch error
        do {
            try cc.validateAttestationResponse(
                response: responseData,
                sentNonce: sentNonce,
                attestationChallenge: challenge,
                dacPublicKey: dacPublicKey
            )
        } catch ControllerError.attestationValidationFailed(let reason) {
            #expect(reason.contains("nonce"), "Error message should mention nonce mismatch")
        } catch {
            Issue.record("Expected attestationValidationFailed, got: \(error)")
        }
    }
}
