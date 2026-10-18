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

    /// No rendering of `value` contains any needle. Build needles with `needles(...)`, which
    /// requires each secret to be non-empty.
    static func expectAbsent(_ secrets: [Needle], in value: Any, sourceLocation: SourceLocation = #_sourceLocation) {
        for text in renderings(value) {
            for secret in secrets {
                #expect(!text.contains(secret.form), "\(type(of: value)) rendered the \(secret.name) (\(secret.form.prefix(8))…)", sourceLocation: sourceLocation)
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

    @Test("SecureSession renders ids and never its keys")
    func secureSession() throws {
        let encrypt = SymmetricKey(size: .bits128), decrypt = SymmetricKey(size: .bits128), attestation = SymmetricKey(size: .bits128)
        let session = SecureSession(
            localSessionID: 0x0A, peerSessionID: 0x14, establishment: .case, peerNodeID: NodeID(rawValue: 0x42),
            encryptKey: encrypt, decryptKey: decrypt, attestationKey: attestation
        )
        #expect(String(describing: session) == "SecureSession(local: 0xA, peer: 0x14, case, peerNode: 0x42, keys: <redacted>)")
        Self.expectAbsent(try needles("encrypt key", encrypt) + needles("decrypt key", decrypt) + needles("attestation key", attestation), in: session)
        Self.expectMirror(session, labels: ["localSessionID", "peerSessionID", "establishment", "peerNodeID", "keys"])
    }

    @Test("PASESession and its SPAKE2+ contexts never render the passcode, w0, w1 or the prover scalar")
    func paseContexts() throws {
        let pase = PASESession(passcode: 20202021)
        #expect(String(describing: pase) == "PASESession(passcode: <redacted>)")
        Self.expectAbsent(try needles(passcode: 20202021), in: pase)
        Self.expectMirror(pase, labels: ["passcode"])

        let (request, requestContext) = pase.createPBKDFParamRequest(initiatorSessionID: 0x10)
        #expect(String(describing: requestContext) == "PBKDFParamRequestContext(initiatorSession: 0x10, payload: <redacted>)")
        Self.expectAbsent(try needles("request", request) + needles("requestContext.initiatorRandom", requestContext.initiatorRandom), in: requestContext)
        Self.expectMirror(requestContext, labels: ["initiatorSessionID", "payload"])

        let (w0, w1) = Spake2p.deriveW0W1(passcode: 20202021, salt: Data(repeating: 0x5A, count: 16), iterations: 1000)
        let (prover, _) = try Spake2p.proverStep1(w0: w0)
        #expect(String(describing: prover) == "Spake2pProverContext(<redacted>)")
        Self.expectAbsent(try needles("w0", w0), in: prover)
        Self.expectMirror(prover, labels: [])

        let verifier = try Spake2p.computeVerifier(passcode: 20202021, salt: Data(repeating: 0x5A, count: 16), iterations: 1000)
        let (_, pA) = try Spake2p.proverStep1(w0: w0)
        let (verifierContext, _, _) = try Spake2p.verifierStep1(pA: pA, verifier: verifier, hashContext: Data(repeating: 1, count: 32))
        #expect(String(describing: verifierContext) == "Spake2pVerifierContext(<redacted>)")
        Self.expectAbsent(
            try needles("verifierContext.ke", verifierContext.ke) + needles("verifierContext.kcA", verifierContext.kcA) + needles("verifierContext.y", verifierContext.y.rawRepresentation),
            in: verifierContext
        )
        Self.expectMirror(verifierContext, labels: [])

        let pake1 = PASESession.Pake1Context(
            proverContext: prover, w1: w1, hashContext: Data(repeating: 1, count: 32),
            responderSessionID: 0x20, initiatorSessionID: 0x10
        )
        #expect(String(describing: pake1) == "Pake1Context(initiatorSession: 0x10, responderSession: 0x20, secrets: <redacted>)")
        Self.expectAbsent(try needles("w0", w0) + needles("w1", w1), in: pake1)
        Self.expectMirror(pake1, labels: ["initiatorSessionID", "responderSessionID", "secrets"])

        var context = CommissioningController.CommissioningContext()
        context.paseSessionHelper = pase
        context.pasePake1Context = pake1
        context.initiatorSessionID = 0x10
        context.attestationChallenge = Data(repeating: 0xC3, count: 16)
        #expect(String(describing: context).hasPrefix("CommissioningContext(initiatorSession: 0x10"))
        Self.expectAbsent(try needles(passcode: 20202021) + needles("w0", w0) + needles("w1", w1) + needles("attestation challenge", Data(repeating: 0xC3, count: 16)), in: context)
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
        Self.expectAbsent(try needles("fabric.ipkEpochKey", fabric.ipkEpochKey), in: handshake)
        Self.expectMirror(handshake, labels: ["peerNodeID", "keys"])
        for text in Self.renderings(handshake) {
            #expect(!text.contains("caseContext"))
            #expect(!text.contains("PrivateKey"))
        }

        let inner = handshake.caseContext
        #expect(String(describing: inner) == "InitiatorHandshakeContext(peerNode: 0x42, peerFabric: 0x1, keys: <redacted>)")
        Self.expectAbsent(try needles("fabric.ipkEpochKey", fabric.ipkEpochKey), in: inner)
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
        Self.expectAbsent(try needles(setupCode: "34970112332"), in: code)
        Self.expectMirror(code, labels: ["passcode", "discriminator"])

        let configuration = MatterController.Configuration(fabricID: FabricID(rawValue: 1))
        #expect(String(describing: configuration).contains("rootKey: <redacted>"))
        Self.expectAbsent(try needles("configuration.rootKey", configuration.rootKey.rawRepresentation), in: configuration)
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
        Self.expectAbsent(try needles("verifier.w0", verifier.w0) + needles("verifier.L", verifier.L) + needles("verifier.serialized", verifier.serialized), in: verifier)
        Self.expectMirror(verifier, labels: ["summary"])

        let keys = KeyDerivation.deriveSessionKeys(sharedSecret: Data(repeating: 0x33, count: 32))
        #expect(String(describing: keys) == "SessionKeys(<redacted>)")
        Self.expectAbsent(try needles("i2r key", keys.i2rKey) + needles("r2i key", keys.r2iKey) + needles("attestation key", keys.attestationKey), in: keys)
        Self.expectMirror(keys, labels: ["summary"])
    }

    @Test("FabricInfo, ResumptionTicket and DeviceAttestationCredentials never render a private key, the IPK or the shared secret")
    func fabricTicketAndCredentials() throws {
        let fabric = try makeTestFabric().deviceFabric
        #expect(String(describing: fabric) == "FabricInfo(fabricIndex: 1, fabricID: 0x1, nodeID: 0x42, keys: <redacted>)")
        Self.expectAbsent(
            try needles("fabric.operationalKey", fabric.operationalKey.rawRepresentation) + needles("fabric.ipkEpochKey", fabric.ipkEpochKey) + needles("IPK", fabric.deriveIPK()),
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
        Self.expectAbsent(try needles("resumptionID", resumptionID) + needles("sharedSecret", sharedSecret), in: ticket)
        Self.expectMirror(ticket, labels: ["summary"])

        let credentials = try DeviceAttestationCredentials.testCredentials()
        #expect(String(describing: credentials) == "DeviceAttestationCredentials(dacPrivateKey: <redacted>)")
        Self.expectAbsent(try needles("credentials.dacPrivateKey", credentials.dacPrivateKey.rawRepresentation), in: credentials)
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
            try needles("initiator.initiatorEphKey", initiator.initiatorEphKey.rawRepresentation) + needles("initiator.ipk", initiator.ipk) + needles("sigma1", sigma1)
                + needles("controllerFabric.operationalKey", controllerFabric.operationalKey.rawRepresentation) + needles("controllerFabric.ipkEpochKey", controllerFabric.ipkEpochKey),
            in: initiator
        )
        Self.expectMirror(initiator, labels: ["summary"])

        let (_, handshake) = try CASEProtocolHandler(fabricInfo: deviceFabric).handleSigma1(payload: sigma1, responderSessionID: 300)
        let responder = handshake.caseContext
        let responderSecrets = try needles("responder.responderEphKey", responder.responderEphKey.rawRepresentation) + needles("responder.ipk", responder.ipk)
            + needles("responder.sharedSecret", responder.sharedSecret.withUnsafeBytes { Data($0) }) + needles("responder.sigma1Bytes", responder.sigma1Bytes)
            + needles("responder.sigma2Bytes", responder.sigma2Bytes) + needles("deviceFabric.operationalKey", deviceFabric.operationalKey.rawRepresentation)
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

    @Test("Keys at rest and their holders never render a root key, an operational key, the IPK or a ticket's secrets")
    func keysAtRestAndHolders() async throws {
        let testFabric = try makeTestFabric()
        let manager = testFabric.manager, controllerFabric = manager.controllerFabricInfo
        let managerSecrets = try needles("root key", testFabric.rootKey.rawRepresentation)
            + needles("controller operational key", controllerFabric.operationalKey.rawRepresentation)
            + needles("IPK epoch key", manager.ipkEpochKey)
        #expect(String(describing: manager) == "FabricManager(fabricIndex: 1, fabricID: 0x1, controllerNodeID: 0x1, vendorID: 0xFFF1, keys: <redacted>)")
        Self.expectAbsent(managerSecrets, in: manager)
        Self.expectMirror(manager, labels: ["summary"])

        let identity = manager.toStoredIdentity()
        #expect(String(describing: identity) == "StoredControllerIdentity(fabricIndex: 1, fabricID: 0x1, controllerNodeID: 0x1, vendorID: 0xFFF1, keys: <redacted>)")
        Self.expectAbsent(managerSecrets, in: identity)
        Self.expectMirror(identity, labels: ["summary"])
        // The container is not redacted itself: every rendering shows its identity through the
        // identity's redaction (raw key bytes would render only as `32 bytes`, which no needle matches).
        let state = StoredControllerState(identity: identity, nextNodeID: 2)
        Self.expectAbsent(managerSecrets, in: state)
        for text in Self.renderings(state) {
            #expect(text.contains("StoredControllerIdentity(fabricIndex: 1, fabricID: 0x1, controllerNodeID: 0x1, vendorID: 0xFFF1, keys: <redacted>)"))
            #expect(!text.contains("rootKeyRaw") && !text.contains("operationalKeyRaw") && !text.contains("ipkEpochKey"))
        }

        let handlerEpochKey = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        let handler = CASEProtocolHandler(fabricInfo: testFabric.deviceFabric, ipkEpochKey: handlerEpochKey)
        #expect(String(describing: handler) == "CASEProtocolHandler(fabricIndex: 1, fabricID: 0x1, nodeID: 0x42, keys: <redacted>)")
        Self.expectAbsent(
            try needles("handler IPK epoch key", handlerEpochKey)
                + needles("device operational key", testFabric.deviceFabric.operationalKey.rawRepresentation)
                + needles("fabric IPK epoch key", testFabric.deviceFabric.ipkEpochKey),
            in: handler
        )
        Self.expectMirror(handler, labels: ["summary"])

        let operationalKeyRaw = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let fabricEpochKey = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        let stored = StoredFabric(
            fabricIndex: 1, nocTLV: Data([1]), icacTLV: nil, rcacTLV: Data([2]), operationalKeyRaw: operationalKeyRaw,
            ipkEpochKey: fabricEpochKey, caseAdminSubject: 1, adminVendorId: 0xFFF1
        )
        #expect(String(describing: stored) == "StoredFabric(fabricIndex: 1, caseAdminSubject: 0x1, adminVendorId: 0xFFF1, keys: <redacted>)")
        Self.expectAbsent(try needles("stored operational key", operationalKeyRaw) + needles("stored IPK epoch key", fabricEpochKey), in: stored)
        Self.expectMirror(stored, labels: ["summary"])

        let resumptionID = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        let sharedSecret = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let store = ResumptionTicketStore()
        await store.store(ticket: ResumptionTicket(
            resumptionID: resumptionID, sharedSecret: sharedSecret, peerNodeID: NodeID(rawValue: 0x42),
            peerFabricID: FabricID(rawValue: 1), fabricIndex: FabricIndex(rawValue: 1), expiryDate: Date().addingTimeInterval(60)
        ))
        #expect(await store.count == 1)
        #expect(String(describing: store) == "ResumptionTicketStore(maxTickets: 64, tickets: <redacted>)")
        Self.expectAbsent(try needles("resumption ID", resumptionID) + needles("shared secret", sharedSecret), in: store)
        Self.expectMirror(store, labels: ["summary"])
    }
}
