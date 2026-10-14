// DeviceAttestationTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
import MatterTypes
@testable import MatterDevice
@testable import MatterModel
@testable import MatterCrypto
import MatterTestSupport

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

        // The envelope must parse as Matter's CMS shape and carry the declared VID and PID.
        let parsed = try CertificationDeclaration(cmsDER: cd)
        #expect(parsed.vendorID == vendorID)
        #expect(parsed.productIDs == [productID])
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

// MARK: - End-to-End Attestation Tests

@Suite("Test credentials attest end to end", .timeLimit(.minutes(5)))
struct TestCredentialsAttestationTests {

    /// 2026-10-14T00:00:00Z, inside the test certificates' 2024 to 2034 validity.
    static let now = Date(timeIntervalSince1970: 1_791_936_000)
    static let challenge = Data((1...16).map { UInt8($0) })
    static let nonce = Data((10..<42).map { UInt8($0) })

    /// Runs the device-side AttestationRequest and CertificateChainRequest handlers and feeds
    /// what they return to the verifier.
    static func attest(
        _ creds: DeviceAttestationCredentials, trustStore: AttestationTrustStore,
        basicInformation: (vendorID: UInt16, productID: UInt16) = (0xFFF1, 0x8000)
    ) async throws -> AttestationResult {
        let state = CommissioningState()
        state.attestationCredentials = creds
        state.attestationChallenge = challenge
        state.armFailSafe(expiresAt: Date().addingTimeInterval(300))
        let handler = OperationalCredentialsHandler(commissioningState: state)
        let store = makeStore(handler: handler)

        let response = try handler.handleCommand(
            commandID: OperationalCredentialsCluster.Command.attestationRequest,
            fields: .structure([.init(tag: .contextSpecific(0), value: .octetString(nonce))]),
            store: store, endpointID: ep0)
        guard case .structure(let fields) = response,
              let elements = fields.first(where: { $0.tag == .contextSpecific(0) })?.value.dataValue,
              let signature = fields.first(where: { $0.tag == .contextSpecific(1) })?.value.dataValue
        else { throw TestError.noResponse }

        func certificate(_ type: UInt64) throws -> Data {
            let reply = try handler.handleCommand(
                commandID: OperationalCredentialsCluster.Command.certificateChainRequest,
                fields: .structure([.init(tag: .contextSpecific(0), value: .unsignedInt(type))]),
                store: store, endpointID: ep0)
            guard case .structure(let fields) = reply,
                  let der = fields.first(where: { $0.tag == .contextSpecific(0) })?.value.dataValue
            else { throw TestError.noResponse }
            return der
        }

        return await DeviceAttestationVerifier(trustStore: trustStore).verify(
            dac: try certificate(1), pai: try certificate(2),
            attestationElements: elements, attestationSignature: signature,
            attestationChallenge: challenge, sentNonce: nonce,
            basicInformation: basicInformation, now: now)
    }

    enum TestError: Error { case noResponse }

    static func failureReason(_ result: AttestationResult) -> AttestationFailureReason? {
        if case .failed(let failure) = result { return failure.reason }
        return nil
    }

    @Test("testCredentials verifies against TestAttestation.trustStore(for:)")
    func verifiesEndToEnd() async throws {
        let creds = try DeviceAttestationCredentials.testCredentials()
        let result = try await Self.attest(creds, trustStore: try TestAttestation.trustStore(for: creds))
        guard case .verified = result else {
            Issue.record("expected verified, got \(result)")
            return
        }
    }

    @Test("a non-default VID and PID verify when Basic Information reports them")
    func customIdentifiers() async throws {
        let creds = try DeviceAttestationCredentials.testCredentials(vendorID: 0xFFF2, productID: 0x1234)
        let result = try await Self.attest(
            creds, trustStore: try TestAttestation.trustStore(for: creds), basicInformation: (0xFFF2, 0x1234))
        guard case .verified = result else {
            Issue.record("expected verified, got \(result)")
            return
        }
    }

    @Test("the CD is signed by the dedicated CD key, named by its SubjectKeyIdentifier")
    func cdSignerIsTheDedicatedKey() throws {
        let creds = try DeviceAttestationCredentials.testCredentials()
        let cd = try CertificationDeclaration(cmsDER: creds.certificationDeclaration)
        let cdKey = try CDSigningKey(certificateDER: try #require(creds.cdSigningCertificate))
        let paiKey = try CDSigningKey(certificateDER: creds.paiCertificate)
        #expect(cd.signerKeyIdentifier == cdKey.keyIdentifier)
        #expect(cd.signerKeyIdentifier != paiKey.keyIdentifier)
        #expect(cd.verifySignature(keys: [cdKey]) == .valid)
        #expect(cd.verifySignature(keys: [paiKey]) == .unknownSigningKey)
        #expect(cd.vendorID == 0xFFF1 && cd.productIDs == [0x8000])
    }

    @Test("a store that trusts the PAI key rather than the CD key gives cdUnknownSigningKey")
    func paiKeyDoesNotSignTheCD() async throws {
        let creds = try DeviceAttestationCredentials.testCredentials()
        let store = try AttestationTrustStore(
            paas: [creds.paaCertificate],
            cdSigningKeys: [try CDSigningKey(certificateDER: creds.paiCertificate)],
            provenance: TrustStoreProvenance(source: "test"))
        let result = try await Self.attest(creds, trustStore: store)
        #expect(Self.failureReason(result) == .cdUnknownSigningKey)
    }

    @Test("another set of credentials' trust store does not verify these credentials")
    func foreignStoreRejects() async throws {
        let creds = try DeviceAttestationCredentials.testCredentials()
        let foreign = try DeviceAttestationCredentials.testCredentials()
        let result = try await Self.attest(creds, trustStore: try TestAttestation.trustStore(for: foreign))
        #expect(Self.failureReason(result) == .untrustedRoot)
    }

    @Test("chipDevelopmentTrustStore holds the test PAA and the test and production-001 CD keys")
    func chipStoreContents() throws {
        let store = try TestAttestation.chipDevelopmentTrustStore()
        #expect(store.paas.count == 1)
        let keys = Set(store.cdSigningKeys)
        #expect(keys.contains(try CDSigningKey(certificateDER: try AttestationFixtures.testCDSigningCert)))
        #expect(keys.contains(try CDSigningKey(certificateDER: try AttestationFixtures.productionCDSigningCerts[0])))
        #expect(keys.count == 2)
    }

    @Test("the dev chain verifies against chipDevelopmentTrustStore with the example CD")
    func devChainWithExampleCD() async throws {
        let key = try P256.Signing.PrivateKey(derRepresentation: try AttestationFixtures.devDACPrivateKey)
        let elements = TLVEncoder.encode(.structure([
            .init(tag: .contextSpecific(1), value: .octetString(try AttestationFixtures.exampleCD)),
            .init(tag: .contextSpecific(2), value: .octetString(Self.nonce)),
            .init(tag: .contextSpecific(3), value: .unsignedInt(0)),
        ]))
        let signature = try key.signature(for: elements + Self.challenge).rawRepresentation
        let result = await DeviceAttestationVerifier(trustStore: try TestAttestation.chipDevelopmentTrustStore()).verify(
            dac: try AttestationFixtures.devDAC, pai: try AttestationFixtures.devPAI,
            attestationElements: elements, attestationSignature: signature,
            attestationChallenge: Self.challenge, sentNonce: Self.nonce,
            basicInformation: (0xFFF1, 0x8000), now: Self.now)
        guard case .verified = result else {
            Issue.record("expected verified, got \(result)")
            return
        }
    }
}
