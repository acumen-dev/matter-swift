// DeviceAttestationTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
import MatterTypes
@testable import MatterDevice
@testable import MatterModel
@testable import MatterCrypto

// MARK: - Test Helpers

private let ep0 = EndpointID(rawValue: 0)

private func makeStore(handler: some ClusterHandler) -> AttributeStore {
    let store = AttributeStore()
    for (attr, value) in handler.initialAttributes() {
        store.set(endpoint: ep0, cluster: handler.clusterID, attribute: attr, value: value)
    }
    return store
}

// MARK: - DeviceAttestationCredentials Tests

@Suite("Device Attestation Credentials")
struct DeviceAttestationCredentialsTests {

    @Test("testCredentials generates non-empty DAC, PAI, and CD")
    func testCredentialsNotEmpty() throws {
        let credentials = try DeviceAttestationCredentials.testCredentials()

        #expect(!credentials.dacCertificate.isEmpty, "DAC certificate should not be empty")
        #expect(!credentials.paiCertificate.isEmpty, "PAI certificate should not be empty")
        #expect(!credentials.certificationDeclaration.isEmpty, "CD should not be empty")
    }

    @Test("testCredentials DAC and PAI are valid DER SEQUENCE structures")
    func testCredentialsDERStructure() throws {
        let credentials = try DeviceAttestationCredentials.testCredentials()

        // DAC must start with SEQUENCE tag (0x30)
        #expect(credentials.dacCertificate.first == 0x30,
                "DAC certificate must begin with DER SEQUENCE tag")
        // PAI must start with SEQUENCE tag (0x30)
        #expect(credentials.paiCertificate.first == 0x30,
                "PAI certificate must begin with DER SEQUENCE tag")
    }

    @Test("testCredentials DAC can sign and verify data")
    func testCredentialsDACKeyCanSign() throws {
        let credentials = try DeviceAttestationCredentials.testCredentials()

        let testData = Data("Hello Attestation".utf8)
        let signature = try credentials.dacPrivateKey.signature(for: testData)
        let verified = credentials.dacPrivateKey.publicKey.isValidSignature(signature, for: testData)
        #expect(verified, "DAC key should be able to sign and verify data")
    }

    @Test("testCredentials CD is CMS SignedData wrapping a TLV payload")
    func testCredentialsCDTLV() throws {
        let vendorID: UInt16 = 0xFFF1
        let productID: UInt16 = 0x8000
        let credentials = try DeviceAttestationCredentials.testCredentials(
            vendorID: vendorID,
            productID: productID
        )

        let cd = credentials.certificationDeclaration

        // CD must be DER ContentInfo (SEQUENCE tag 0x30) per Matter spec §6.3.5
        #expect(cd.first == 0x30, "CD must be a DER-encoded ContentInfo (SEQUENCE)")

        // Expect at least 50 bytes — CMS envelope + TLV payload
        #expect(cd.count > 50, "CD must be large enough to contain CMS envelope and TLV payload")

        // Locate the inner TLV by scanning for Matter id-cd OID bytes.
        // The Matter CD OID (1.3.6.1.4.1.37244.1.1) DER-encoded is:
        //   06 0A 2B 06 01 04 01 82 A2 7C 01 01
        let matterCDOID: [UInt8] = [0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x01, 0x01]
        let cdBytes = [UInt8](cd)
        let oidFound = cdBytes.count >= matterCDOID.count && (0...(cdBytes.count - matterCDOID.count)).contains {
            Array(cdBytes[$0..<$0 + matterCDOID.count]) == matterCDOID
        }
        #expect(oidFound, "CD CMS envelope should contain the Matter id-cd OID (1.3.6.1.4.1.37244.1.1)")
    }
}

// MARK: - AttestationRequest Handler Tests

@Suite("AttestationRequest Handler")
struct AttestationRequestHandlerTests {

    @Test("AttestationRequest returns attestationElements with nonce echo and valid signature")
    func attestationRequestReturnsValidResponse() throws {
        let commissioningState = CommissioningState()
        commissioningState.attestationCredentials = try DeviceAttestationCredentials.testCredentials()

        // Simulate a PASE session attestation challenge
        var challengeBytes = [UInt8](repeating: 0, count: 16)
        for i in 0..<16 { challengeBytes[i] = UInt8(i + 1) }
        commissioningState.attestationChallenge = Data(challengeBytes)

        // Arm fail-safe so commands are accepted
        commissioningState.armFailSafe(expiresAt: Date().addingTimeInterval(300))

        let handler = OperationalCredentialsHandler(commissioningState: commissioningState)
        let store = makeStore(handler: handler)

        // Build AttestationRequest fields: { 0: attestationNonce }
        var nonce = [UInt8](repeating: 0, count: 32)
        for i in 0..<32 { nonce[i] = UInt8(i + 10) }
        let nonceData = Data(nonce)

        let requestFields = TLVElement.structure([
            .init(tag: .contextSpecific(0), value: .octetString(nonceData))
        ])

        let response = try handler.handleCommand(
            commandID: OperationalCredentialsCluster.Command.attestationRequest,
            fields: requestFields,
            store: store,
            endpointID: ep0
        )

        guard case .structure(let fields) = response else {
            Issue.record("Response should be a TLV structure")
            return
        }

        // Field 0: attestationElements
        guard let attestationElementsData = fields.first(where: { $0.tag == .contextSpecific(0) })?.value.dataValue else {
            Issue.record("Response should contain attestationElements at tag 0")
            return
        }
        #expect(!attestationElementsData.isEmpty, "attestationElements should not be empty")

        // Decode attestationElements and verify nonce is echoed
        let (_, elementsElement) = try TLVDecoder.decode(attestationElementsData)
        guard case .structure(let elemFields) = elementsElement else {
            Issue.record("attestationElements should be a TLV structure")
            return
        }
        let echoedNonce = elemFields.first(where: { $0.tag == .contextSpecific(2) })?.value.dataValue
        #expect(echoedNonce == nonceData, "Nonce should be echoed in attestationElements")

        // Field 1: attestationSignature
        guard let sigData = fields.first(where: { $0.tag == .contextSpecific(1) })?.value.dataValue else {
            Issue.record("Response should contain attestationSignature at tag 1")
            return
        }
        #expect(!sigData.isEmpty, "attestationSignature should not be empty")

        // Per Matter spec §11.17.6.3 the signature is a 64-byte raw r‖s encoding.
        #expect(sigData.count == 64, "attestationSignature should be 64 bytes (raw r‖s)")

        // Verify signature with DAC public key
        let credentials = commissioningState.attestationCredentials!
        let messageToVerify = attestationElementsData + commissioningState.attestationChallenge!
        let sig = try P256.Signing.ECDSASignature(rawRepresentation: sigData)
        let verified = credentials.dacPrivateKey.publicKey.isValidSignature(sig, for: messageToVerify)
        #expect(verified, "attestationSignature should verify with DAC public key")
    }
}

// MARK: - CertificateChainRequest Handler Tests

@Suite("CertificateChainRequest Handler")
struct CertificateChainRequestHandlerTests {

    private func makeHandler() throws -> (OperationalCredentialsHandler, CommissioningState) {
        let commissioningState = CommissioningState()
        commissioningState.attestationCredentials = try DeviceAttestationCredentials.testCredentials()
        commissioningState.armFailSafe(expiresAt: Date().addingTimeInterval(300))
        let handler = OperationalCredentialsHandler(commissioningState: commissioningState)
        return (handler, commissioningState)
    }

    @Test("CertificateChainRequest type 1 returns non-empty DAC DER bytes")
    func certificateChainRequestDAC() throws {
        let (handler, state) = try makeHandler()
        let store = makeStore(handler: handler)

        let requestFields = TLVElement.structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(1))  // type 1 = DAC
        ])

        let response = try handler.handleCommand(
            commandID: OperationalCredentialsCluster.Command.certificateChainRequest,
            fields: requestFields,
            store: store,
            endpointID: ep0
        )

        guard case .structure(let fields) = response,
              let certData = fields.first(where: { $0.tag == .contextSpecific(0) })?.value.dataValue else {
            Issue.record("Response should contain certificate at tag 0")
            return
        }

        #expect(!certData.isEmpty, "DAC certificate data should not be empty")
        #expect(certData.first == 0x30, "DAC should be a valid DER SEQUENCE")
        #expect(certData == state.attestationCredentials?.dacCertificate,
                "Returned DAC should match stored credentials")
    }

    @Test("CertificateChainRequest type 2 returns non-empty PAI DER bytes")
    func certificateChainRequestPAI() throws {
        let (handler, state) = try makeHandler()
        let store = makeStore(handler: handler)

        let requestFields = TLVElement.structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(2))  // type 2 = PAI
        ])

        let response = try handler.handleCommand(
            commandID: OperationalCredentialsCluster.Command.certificateChainRequest,
            fields: requestFields,
            store: store,
            endpointID: ep0
        )

        guard case .structure(let fields) = response,
              let certData = fields.first(where: { $0.tag == .contextSpecific(0) })?.value.dataValue else {
            Issue.record("Response should contain certificate at tag 0")
            return
        }

        #expect(!certData.isEmpty, "PAI certificate data should not be empty")
        #expect(certData.first == 0x30, "PAI should be a valid DER SEQUENCE")
        #expect(certData == state.attestationCredentials?.paiCertificate,
                "Returned PAI should match stored credentials")
    }
}
