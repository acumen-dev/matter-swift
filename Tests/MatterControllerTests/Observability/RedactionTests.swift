// RedactionTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
import MatterTypes
import MatterCrypto
import MatterProtocol
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

    /// A redacted type's mirror carries exactly `labels`, and none of the children is a byte or key value.
    static func expectMirror(_ value: Any, labels: Set<String>, sourceLocation: SourceLocation = #_sourceLocation) {
        let children = Mirror(reflecting: value).children
        #expect(Set(children.compactMap(\.label)) == labels, "\(type(of: value)) mirror labels", sourceLocation: sourceLocation)
        for child in children {
            let secret = child.value is Data || child.value is SymmetricKey || child.value is P256.Signing.PrivateKey
            #expect(!secret, "\(type(of: value)) mirror child \(child.label ?? "?")", sourceLocation: sourceLocation)
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
        Self.expectAbsent(SecretForms.of(verifier.w0) + SecretForms.of(verifier.L), in: verifierContext)
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
}
