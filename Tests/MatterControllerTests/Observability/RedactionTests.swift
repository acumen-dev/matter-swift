// RedactionTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
import MatterTypes
@testable import MatterCrypto
@testable import MatterProtocol
import MatterTestSupport
@testable import MatterController

@Suite("Redacted descriptions", .timeLimit(.minutes(1)))
struct RedactionTests {

    /// Every way a value reaches text: interpolation, `String(describing:)`,
    /// `String(reflecting:)` and `dump`.
    static func renderings(_ value: Any) -> [String] {
        var dumped = ""
        dump(value, to: &dumped)
        return ["\(value)", String(describing: value), String(reflecting: value), dumped]
    }

    static func expectAbsent(_ secrets: [String], in value: Any, sourceLocation: SourceLocation = #_sourceLocation) {
        for text in renderings(value) {
            for secret in secrets {
                #expect(!text.contains(secret), "\(type(of: value)) rendered \(secret.prefix(8))…", sourceLocation: sourceLocation)
            }
        }
    }

    /// A redacted type's mirror carries exactly `labels`, and every child is ``isPlain(_:)``.
    static func expectMirror(_ value: Any, labels: Set<String>, sourceLocation: SourceLocation = #_sourceLocation) {
        let children = Mirror(reflecting: value).children
        #expect(Set(children.compactMap(\.label)) == labels, "\(type(of: value)) mirror labels", sourceLocation: sourceLocation)
        for child in children {
            #expect(isPlain(child.value), "\(type(of: value)) mirror child \(child.label ?? "?") is \(type(of: child.value))", sourceLocation: sourceLocation)
        }
    }

    /// The values a redacted mirror may show: text, integers, booleans, identifiers, enums
    /// without payloads, and optionals of those. Bytes, keys, contexts, dates, collections
    /// and any other struct are refused.
    static func isPlain(_ value: Any) -> Bool {
        switch value {
        case is String, is Bool, is any BinaryInteger, is NodeID, is FabricID, is FabricIndex, is VendorID:
            return true
        default:
            let mirror = Mirror(reflecting: value)
            switch mirror.displayStyle {
            case .enum?: return mirror.children.isEmpty
            case .optional?: return mirror.children.allSatisfy { isPlain($0.value) }
            default: return false
            }
        }
    }

    static func bytes(_ key: SymmetricKey) -> Data { key.withUnsafeBytes { Data($0) } }

    @Test("SecureSession renders ids and never its keys")
    func secureSession() {
        let encrypt = SymmetricKey(size: .bits128), decrypt = SymmetricKey(size: .bits128), attestation = SymmetricKey(size: .bits128)
        let session = SecureSession(
            localSessionID: 0x0A, peerSessionID: 0x14, establishment: .case, peerNodeID: NodeID(rawValue: 0x42),
            encryptKey: encrypt, decryptKey: decrypt, attestationKey: attestation
        )
        #expect(String(describing: session) == "SecureSession(local: 0xA, peer: 0x14, case, peerNode: 0x42, keys: <redacted>)")
        Self.expectAbsent([encrypt, decrypt, attestation].flatMap { SecretForms.of(Self.bytes($0)) }, in: session)
        Self.expectMirror(session, labels: ["localSessionID", "peerSessionID", "establishment", "peerNodeID", "keys"])
    }

    @Test("PASESession and its SPAKE2+ contexts never render the passcode, w0, w1 or the prover scalar")
    func paseContexts() throws {
        let pase = PASESession(passcode: 20202021)
        #expect(String(describing: pase) == "PASESession(passcode: <redacted>)")
        Self.expectAbsent(["20202021"], in: pase)
        Self.expectMirror(pase, labels: ["passcode"])

        let (request, requestContext) = pase.createPBKDFParamRequest(initiatorSessionID: 0x10)
        #expect(String(describing: requestContext) == "PBKDFParamRequestContext(initiatorSession: 0x10, payload: <redacted>)")
        Self.expectAbsent(SecretForms.of(request) + SecretForms.of(requestContext.initiatorRandom), in: requestContext)
        Self.expectMirror(requestContext, labels: ["initiatorSessionID", "payload"])

        let (w0, w1) = Spake2p.deriveW0W1(passcode: 20202021, salt: Data(repeating: 0x5A, count: 16), iterations: 1000)
        let (prover, _) = try Spake2p.proverStep1(w0: w0)
        #expect(String(describing: prover) == "Spake2pProverContext(<redacted>)")
        Self.expectAbsent(SecretForms.of(w0), in: prover)
        Self.expectMirror(prover, labels: [])

        let verifier = try Spake2p.computeVerifier(passcode: 20202021, salt: Data(repeating: 0x5A, count: 16), iterations: 1000)
        let (_, pA) = try Spake2p.proverStep1(w0: w0)
        let (verifierContext, _, _) = try Spake2p.verifierStep1(pA: pA, verifier: verifier, hashContext: Data(repeating: 1, count: 32))
        #expect(String(describing: verifierContext) == "Spake2pVerifierContext(<redacted>)")
        Self.expectAbsent(
            SecretForms.of(verifierContext.ke) + SecretForms.of(Self.bytes(verifierContext.kcA)) + SecretForms.of(verifierContext.y.rawRepresentation),
            in: verifierContext
        )
        Self.expectMirror(verifierContext, labels: [])

        let pake1 = PASESession.Pake1Context(
            proverContext: prover, w1: w1, hashContext: Data(repeating: 1, count: 32),
            responderSessionID: 0x20, initiatorSessionID: 0x10
        )
        #expect(String(describing: pake1) == "Pake1Context(initiatorSession: 0x10, responderSession: 0x20, secrets: <redacted>)")
        Self.expectAbsent(SecretForms.of(w0) + SecretForms.of(w1), in: pake1)
        Self.expectMirror(pake1, labels: ["initiatorSessionID", "responderSessionID", "secrets"])

        var context = CommissioningController.CommissioningContext()
        context.paseSessionHelper = pase
        context.pasePake1Context = pake1
        context.initiatorSessionID = 0x10
        context.attestationChallenge = Data(repeating: 0xC3, count: 16)
        #expect(String(describing: context).hasPrefix("CommissioningContext(initiatorSession: 0x10"))
        Self.expectAbsent(["20202021"] + SecretForms.of(w0) + SecretForms.of(w1) + SecretForms.of(Data(repeating: 0xC3, count: 16)), in: context)
        Self.expectMirror(context, labels: ["summary"])
    }

    @Test("A CASE handshake context never renders the fabric IPK or its ephemeral state")
    func caseContext() throws {
        let fabric = try FabricManager(
            rootKey: P256.Signing.PrivateKey(), fabricID: FabricID(rawValue: 1),
            controllerNodeID: NodeID(rawValue: 1), vendorID: .test
        )
        let (_, handshake) = ControllerSession(fabricManager: fabric).createSigma1(peerNodeID: NodeID(rawValue: 0x42), initiatorSessionID: 7)
        #expect(String(describing: handshake) == "HandshakeContext(peerNode: 0x42, keys: <redacted>)")
        Self.expectAbsent(SecretForms.of(fabric.ipkEpochKey), in: handshake)
        Self.expectMirror(handshake, labels: ["peerNodeID", "keys"])
        for text in Self.renderings(handshake) {
            #expect(!text.contains("caseContext"))
            #expect(!text.contains("PrivateKey"))
        }

        let inner = handshake.caseContext
        #expect(String(describing: inner) == "InitiatorHandshakeContext(peerNode: 0x42, peerFabric: 0x1, keys: <redacted>)")
        Self.expectAbsent(SecretForms.of(fabric.ipkEpochKey), in: inner)
        Self.expectMirror(inner, labels: ["peerNodeID", "keys"])
        for text in Self.renderings(inner) {
            #expect(!text.contains("caseContext"))
            #expect(!text.contains("PrivateKey"))
        }
    }

    @Test("SetupCode and Configuration never render the passcode, the code or the root key")
    func setupCodeAndConfiguration() throws {
        let code = try SetupCode(parsing: "34970112332")
        #expect(String(describing: code) == "SetupCode(passcode: <redacted>, discriminator: short(15), flow: 0)")
        Self.expectAbsent(["20202021", "34970112332"], in: code)
        Self.expectMirror(code, labels: ["passcode", "discriminator"])

        let configuration = MatterController.Configuration(fabricID: FabricID(rawValue: 1))
        #expect(String(describing: configuration).contains("rootKey: <redacted>"))
        Self.expectAbsent(SecretForms.of(configuration.rootKey.rawRepresentation), in: configuration)
        Self.expectMirror(configuration, labels: ["summary"])
    }

    @Test("The mirror allowlist refuses bytes, keys, contexts and dates, and accepts plain values")
    func mirrorAllowlist() throws {
        let fabric = try makeTestFabric()
        let (_, handshake) = ControllerSession(fabricManager: fabric.manager).createSigma1(peerNodeID: NodeID(rawValue: 0x42), initiatorSessionID: 7)
        let refused: [Any] = [
            Data([0xAB, 0x01]), [UInt8]([0xAB, 0x01]), SymmetricKey(size: .bits128), P256.Signing.PrivateKey(),
            P256.KeyAgreement.PrivateKey(), handshake.caseContext, fabric.deviceFabric, Date(), Optional(Data([1])) as Any,
            TLVElement.octetString(Data([1])),
        ]
        for value in refused {
            #expect(!Self.isPlain(value), "\(type(of: value)) must be refused")
        }
        let accepted: [Any] = [
            "text", UInt16(10), 42, true, NodeID(rawValue: 0x42), FabricID(rawValue: 1), FabricIndex(rawValue: 1),
            VendorID.test, SessionEstablishment.case, Optional<NodeID>.none as Any, Optional("text") as Any,
        ]
        for value in accepted {
            #expect(Self.isPlain(value), "\(type(of: value)) must be accepted")
        }
    }

    @Test("Spake2pVerifier and SessionKeys never render w0, L or a key")
    func verifierAndSessionKeys() throws {
        let verifier = try Spake2p.computeVerifier(passcode: 20202021, salt: Data(repeating: 0x5A, count: 16), iterations: 1000)
        #expect(String(describing: verifier) == "Spake2pVerifier(<redacted>)")
        Self.expectAbsent(SecretForms.of(verifier.w0) + SecretForms.of(verifier.L) + SecretForms.of(verifier.serialized), in: verifier)
        Self.expectMirror(verifier, labels: ["summary"])

        let keys = KeyDerivation.deriveSessionKeys(sharedSecret: Data(repeating: 0x33, count: 32))
        #expect(String(describing: keys) == "SessionKeys(<redacted>)")
        Self.expectAbsent([keys.i2rKey, keys.r2iKey, keys.attestationKey].flatMap { SecretForms.of(Self.bytes($0)) }, in: keys)
        Self.expectMirror(keys, labels: ["summary"])
    }

    @Test("FabricInfo, ResumptionTicket and DeviceAttestationCredentials never render a private key, the IPK or the shared secret")
    func fabricTicketAndCredentials() throws {
        let fabric = try makeTestFabric().deviceFabric
        #expect(String(describing: fabric) == "FabricInfo(fabricIndex: 1, fabricID: 0x1, nodeID: 0x42, keys: <redacted>)")
        Self.expectAbsent(
            SecretForms.of(fabric.operationalKey.rawRepresentation) + SecretForms.of(fabric.ipkEpochKey) + SecretForms.of(fabric.deriveIPK()),
            in: fabric
        )
        Self.expectMirror(fabric, labels: ["summary"])

        let resumptionID = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        let sharedSecret = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let ticket = ResumptionTicket(
            resumptionID: resumptionID, sharedSecret: sharedSecret, peerNodeID: NodeID(rawValue: 0x42),
            peerFabricID: FabricID(rawValue: 1), fabricIndex: FabricIndex(rawValue: 1),
            expiryDate: Date(timeIntervalSinceReferenceDate: 0)
        )
        #expect(String(describing: ticket)
                == "ResumptionTicket(peerNode: 0x42, peerFabric: 0x1, fabricIndex: 1, expires: 2001-01-01 00:00:00 +0000, secrets: <redacted>)")
        Self.expectAbsent(SecretForms.of(resumptionID) + SecretForms.of(sharedSecret), in: ticket)
        Self.expectMirror(ticket, labels: ["summary"])

        let credentials = try DeviceAttestationCredentials.testCredentials()
        #expect(String(describing: credentials) == "DeviceAttestationCredentials(dacPrivateKey: <redacted>)")
        Self.expectAbsent(SecretForms.of(credentials.dacPrivateKey.rawRepresentation), in: credentials)
        Self.expectMirror(credentials, labels: ["summary"])
    }

    @Test("The CASE initiator and responder contexts never render an ephemeral key, the IPK, the shared secret or a Sigma payload")
    func caseSessionContexts() throws {
        let testFabric = try makeTestFabric()
        let controllerFabric = testFabric.manager.controllerFabricInfo, deviceFabric = testFabric.deviceFabric
        let (initiator, sigma1) = CASESession.initiatorStep1(
            fabricInfo: controllerFabric, peerNodeID: deviceFabric.nodeID, peerFabricID: deviceFabric.fabricID,
            peerRootPublicKey: deviceFabric.rootPublicKey, initiatorSessionID: 7
        )
        #expect(String(describing: initiator) == "InitiatorContext(initiatorSession: 0x7, keys: <redacted>)")
        Self.expectAbsent(
            SecretForms.of(initiator.initiatorEphKey.rawRepresentation) + SecretForms.of(initiator.ipk) + SecretForms.of(sigma1)
                + SecretForms.of(controllerFabric.operationalKey.rawRepresentation) + SecretForms.of(controllerFabric.ipkEpochKey),
            in: initiator
        )
        Self.expectMirror(initiator, labels: ["summary"])

        let (_, handshake) = try CASEProtocolHandler(fabricInfo: deviceFabric).handleSigma1(payload: sigma1, responderSessionID: 300)
        let responder = handshake.caseContext
        let responderSecrets = SecretForms.of(responder.responderEphKey.rawRepresentation) + SecretForms.of(responder.ipk)
            + SecretForms.of(responder.sharedSecret.withUnsafeBytes { Data($0) }) + SecretForms.of(responder.sigma1Bytes)
            + SecretForms.of(responder.sigma2Bytes) + SecretForms.of(deviceFabric.operationalKey.rawRepresentation)
        #expect(String(describing: responder) == "ResponderContext(responderSession: 0x12C, keys: <redacted>)")
        Self.expectAbsent(responderSecrets, in: responder)
        Self.expectMirror(responder, labels: ["summary"])

        #expect(String(describing: handshake) == "ResponderHandshakeContext(initiatorSession: 0x7, responderSession: 0x12C, keys: <redacted>)")
        Self.expectAbsent(responderSecrets, in: handshake)
        Self.expectMirror(handshake, labels: ["summary"])
        for text in Self.renderings(handshake) {
            #expect(!text.contains("caseContext"))
            #expect(!text.contains("PrivateKey"))
        }
    }
}
