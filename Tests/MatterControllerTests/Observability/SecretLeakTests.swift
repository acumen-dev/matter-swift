// SecretLeakTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
import MatterTypes
@testable import MatterCrypto
@testable import MatterProtocol
import MatterTestSupport
@testable import MatterController

@Suite("No secret is recorded", .timeLimit(.minutes(1)))
struct SecretLeakTests {

    /// The session's keys; `attestation` is false for a test session built without an attestation key.
    private static func sessionNeedles(
        _ name: String, _ session: SecureSession, attestation: Bool = true, sourceLocation: SourceLocation = #_sourceLocation
    ) throws -> [Needle] {
        try needles("\(name) encrypt key", session.encryptKey, sourceLocation: sourceLocation)
            + needles("\(name) decrypt key", session.decryptKey, sourceLocation: sourceLocation)
            + (attestation ? needles("\(name) attestation key", session.attestationKey, sourceLocation: sourceLocation) : [])
    }

    private static func random(_ count: Int) -> Data {
        Data((0..<count).map { _ in UInt8.random(in: 0...255) })
    }

    /// The next frame the controller sent that decodes under `session` (unsecured when nil), is
    /// not a standalone ack, and was not seen before (MRP may retransmit on the real clock).
    /// Frames of other sessions are skipped: the controller acks a phase's last message on the
    /// session that phase used.
    private func nextFrame(_ peer: inout TestPeer, session: SecureSession?, seen: inout Set<String>) async throws -> PeerFrame {
        while true {
            let data = try await peer.nextDatagram()
            let decoded: PeerFrame?
            if let session {
                decoded = try? ScriptedPeer.decodeSecured(data, session: session)
            } else {
                decoded = (try? ScriptedPeer.decodeUnsecured(data)).flatMap { $0.messageHeader.sessionID == 0 ? $0 : nil }
            }
            guard let frame = decoded, !frame.isStandaloneAck else { continue }
            if seen.insert("\(frame.messageHeader.sessionID)/\(frame.counter)").inserted { return frame }
        }
    }

    private func invokeSuccess(_ endpoint: EndpointID, _ cluster: ClusterID, _ command: CommandID) -> Data {
        InvokeResponse(invokeResponses: [InvokeResponseIB(status: CommandStatusIB(
            commandPath: CommandPath(endpointID: endpoint, clusterID: cluster, commandID: command), status: StatusIB(status: 0)
        ))]).tlvEncode()
    }

    @Test("No log line, metadata value, span attribute or span event carries a key, the passcode, the setup code or a raw payload")
    func noSecretsRecorded() async throws {
        let (rig, fabric) = try await makeCASEControllerRig()
        var peer = TestPeer(link: rig.link)
        var seen = Set<String>()
        var secrets: [Needle] = []
        let address = rig.link.b.address
        let node = rig.node

        // 1. A PASE attempt with the passcode in flight, refused at PBKDFParamResponse.
        let refused = Task { try await rig.controller.commission(address: address, setupCode: 20202021) }
        let pbkdf = try await nextFrame(&peer, session: nil, seen: &seen)
        try await peer.send(ScriptedPeer.unsecuredReply(
            to: pbkdf, protocolID: .secureChannel, opcode: SecureChannelOpcode.statusReport.rawValue,
            payload: StatusReportMessage(generalStatus: .failure, protocolID: 0, protocolStatus: 0).encode(), counter: 700
        ))
        await #expect(throws: (any Error).self) { _ = try await refused.value }
        secrets += try needles("PBKDFParamRequest payload", pbkdf.payload)

        // 2. A PASE that succeeds, then ArmFailSafe over the PASE session, refused by the device.
        let salt = Self.random(32)
        let verifier = try Spake2p.computeVerifier(passcode: 20202021, salt: salt, iterations: 1000)
        let commissioning = Task { try await rig.controller.commission(address: address, setupCode: 20202021) }
        let pbkdfRequest = try await nextFrame(&peer, session: nil, seen: &seen)
        let pbkdfParams = try PASEMessages.PBKDFParamRequest.fromTLV(pbkdfRequest.payload)
        let pbkdfResponse = PASEMessages.PBKDFParamResponse(
            initiatorRandom: pbkdfParams.initiatorRandom,
            responderRandom: Self.random(32), responderSessionID: 100, iterations: 1000, salt: salt
        ).tlvEncode()
        try await peer.send(ScriptedPeer.unsecuredReply(
            to: pbkdfRequest, protocolID: .secureChannel, opcode: SecureChannelOpcode.pbkdfParamResponse.rawValue,
            payload: pbkdfResponse, counter: 710
        ))
        let pake1 = try await nextFrame(&peer, session: nil, seen: &seen)
        let (verifierContext, pB, cB) = try Spake2p.verifierStep1(
            pA: try PASEMessages.Pake1Message.fromTLV(pake1.payload).pA, verifier: verifier,
            hashContext: Spake2p.computeHashContext(pbkdfParamRequest: pbkdfRequest.payload, pbkdfParamResponse: pbkdfResponse)
        )
        let pake2 = PASEMessages.Pake2Message(pB: pB, cB: cB).tlvEncode()
        try await peer.send(ScriptedPeer.unsecuredReply(
            to: pake1, protocolID: .secureChannel, opcode: SecureChannelOpcode.pasePake2.rawValue, payload: pake2, counter: 711
        ))
        let pake3 = try await nextFrame(&peer, session: nil, seen: &seen)
        let ke = try Spake2p.verifierStep2(context: verifierContext, cA: try PASEMessages.Pake3Message.fromTLV(pake3.payload).cA)
        try await peer.send(ScriptedPeer.unsecuredReply(
            to: pake3, protocolID: .secureChannel, opcode: SecureChannelOpcode.statusReport.rawValue,
            payload: StatusReportMessage(generalStatus: .success, protocolID: 0, protocolStatus: 0).encode(), counter: 712
        ))
        let paseKeys = KeyDerivation.deriveSessionKeys(sharedSecret: ke)
        let pasePeer = SecureSession(
            localSessionID: 100, peerSessionID: pbkdfParams.initiatorSessionID, establishment: .pase,
            peerNodeID: .unspecified, encryptKey: paseKeys.r2iKey, decryptKey: paseKeys.i2rKey, attestationKey: paseKeys.attestationKey
        )
        let armFailSafe = try await nextFrame(&peer, session: pasePeer, seen: &seen)
        #expect(armFailSafe.exchangeHeader.protocolOpcode == InteractionModelOpcode.invokeRequest.rawValue)
        try await peer.send(ScriptedPeer.securedReply(
            to: armFailSafe, session: pasePeer, protocolID: .interactionModel,
            opcode: InteractionModelOpcode.statusResponse.rawValue, payload: IMStatusResponse(status: 0x01).tlvEncode()
        ))
        await #expect(throws: (any Error).self) { _ = try await commissioning.value }
        secrets += try needles(passcode: 20202021)
        secrets += try needles("PBKDF salt", salt)
        secrets += try needles("SPAKE2+ w0", verifier.w0)
        secrets += try needles("SPAKE2+ L", verifier.L)
        secrets += try needles("SPAKE2+ Ke", ke)
        secrets += try Self.sessionNeedles("PASE", pasePeer)
        secrets += try needles("PBKDFParamRequest payload", pbkdfRequest.payload)
        secrets += try needles("PBKDFParamResponse payload", pbkdfResponse)
        secrets += try needles("Pake1 payload", pake1.payload)
        secrets += try needles("Pake2 payload", pake2)
        secrets += try needles("Pake3 payload", pake3.payload)
        secrets += try needles("ArmFailSafe payload", armFailSafe.payload)

        // 3. A successful CASE: Sigma1 → Sigma2 → Sigma3 → StatusReport against the device's real handler.
        let device = CASEProtocolHandler(fabricInfo: fabric.deviceFabric)
        let establishing = Task { try await rig.controller.session(for: node) }
        let sigma1 = try await nextFrame(&peer, session: nil, seen: &seen)
        #expect(sigma1.exchangeHeader.protocolOpcode == SecureChannelOpcode.caseSigma1.rawValue)
        let (sigma2, responder) = try device.handleSigma1(payload: sigma1.payload, responderSessionID: 300)
        try await peer.send(ScriptedPeer.unsecuredReply(
            to: sigma1, protocolID: .secureChannel, opcode: SecureChannelOpcode.caseSigma2.rawValue, payload: sigma2, counter: 800
        ))
        let sigma3 = try await nextFrame(&peer, session: nil, seen: &seen)
        let casePeer = try device.handleSigma3(
            payload: sigma3.payload, context: responder, initiatorRCAC: fabric.manager.controllerFabricInfo.rcac, localSessionID: 300
        )
        try await peer.send(ScriptedPeer.unsecuredReply(
            to: sigma3, protocolID: .secureChannel, opcode: SecureChannelOpcode.statusReport.rawValue,
            payload: StatusReportMessage(generalStatus: .success, protocolID: 0, protocolStatus: 0).encode(), counter: 801
        ))
        let caseSession = try await establishing.value
        let ipkEpochKey = await rig.controller.ipkEpochKey
        secrets += try Self.sessionNeedles("CASE controller", caseSession)
        secrets += try Self.sessionNeedles("CASE device", casePeer)
        secrets += try needles("CASE shared secret", responder.caseContext.sharedSecret.withUnsafeBytes { Data($0) })
        secrets += try needles("CASE responder ephemeral key", responder.caseContext.responderEphKey.rawRepresentation)
        secrets += try needles("IPK", responder.caseContext.ipk)
        secrets += try needles("IPK epoch key", ipkEpochKey)
        secrets += try needles("root key", fabric.rootKey.rawRepresentation)
        secrets += try needles("controller NOC private key", fabric.manager.controllerFabricInfo.operationalKey.rawRepresentation)
        secrets += try needles("device NOC private key", fabric.deviceFabric.operationalKey.rawRepresentation)
        secrets += try needles("Sigma1 payload", sigma1.payload)
        secrets += try needles("Sigma2 payload", sigma2)
        secrets += try needles("Sigma3 payload", sigma3.payload)

        // 4. IM over the CASE session, everything at trace: a plain invoke, then the three
        // sensitive clusters with secrets in their fields and values.
        let root = EndpointID(rawValue: 0)
        let endpoint = EndpointID(rawValue: 1), cluster = ClusterID(rawValue: 0x0102), command = CommandID(rawValue: 0x05)
        let fields: TLVElement = .structure([.init(tag: .contextSpecific(0), value: .unsignedInt(5000))])
        let call = Task {
            try await rig.controller.invokeCommand(nodeID: node, endpointID: endpoint, clusterID: cluster, commandID: command, commandFields: fields)
        }
        let invoke = try await nextFrame(&peer, session: casePeer, seen: &seen)
        try await peer.send(ScriptedPeer.securedReply(
            to: invoke, session: casePeer, protocolID: .interactionModel,
            opcode: InteractionModelOpcode.invokeResponse.rawValue, payload: invokeSuccess(endpoint, cluster, command)
        ))
        _ = try await call.value
        secrets += try needles("decrypted invoke payload", invoke.payload)

        // An octet string renders as `octetString(16 bytes)` even unredacted; a number renders in
        // full, so it is what catches a sensitive cluster that stops being redacted.
        let number: UInt64 = 0xDEADBEEF
        let numberNeedles = ["3735928559", "DEADBEEF", "deadbeef"].map { Needle(name: "sensitive-cluster number", form: $0) }
        func withNumber(_ bytes: Data) -> TLVElement {
            .structure([.init(tag: .contextSpecific(0), value: .octetString(bytes)), .init(tag: .contextSpecific(1), value: .unsignedInt(number))])
        }

        let operationalCredentials = ClusterID(rawValue: 0x003E), addNOC = CommandID(rawValue: 0x06)
        let addNOCFields: TLVElement = .structure([
            .init(tag: .contextSpecific(2), value: .octetString(ipkEpochKey)),
            .init(tag: .contextSpecific(3), value: .unsignedInt(number)),
        ])
        let addNOCCall = Task {
            try await rig.controller.invokeCommand(
                nodeID: node, endpointID: root, clusterID: operationalCredentials, commandID: addNOC, commandFields: addNOCFields
            )
        }
        let addNOCRequest = try await nextFrame(&peer, session: casePeer, seen: &seen)
        try await peer.send(ScriptedPeer.securedReply(
            to: addNOCRequest, session: casePeer, protocolID: .interactionModel,
            opcode: InteractionModelOpcode.invokeResponse.rawValue, payload: invokeSuccess(root, operationalCredentials, addNOC)
        ))
        _ = try await addNOCCall.value
        secrets += try needles("AddNOC payload", addNOCRequest.payload)

        let adminCommissioning = ClusterID(rawValue: 0x003C), openWindow = CommandID(rawValue: 0x00)
        let openWindowFields: TLVElement = .structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(180)),
            .init(tag: .contextSpecific(1), value: .octetString(verifier.serialized)),
            .init(tag: .contextSpecific(2), value: .unsignedInt(3840)),
            .init(tag: .contextSpecific(3), value: .unsignedInt(1000)),
            .init(tag: .contextSpecific(4), value: .octetString(salt)),
        ])
        let openWindowCall = Task {
            try await rig.controller.invokeCommand(
                nodeID: node, endpointID: root, clusterID: adminCommissioning, commandID: openWindow, commandFields: openWindowFields
            )
        }
        let openWindowRequest = try await nextFrame(&peer, session: casePeer, seen: &seen)
        try await peer.send(ScriptedPeer.securedReply(
            to: openWindowRequest, session: casePeer, protocolID: .interactionModel,
            opcode: InteractionModelOpcode.invokeResponse.rawValue, payload: invokeSuccess(root, adminCommissioning, openWindow)
        ))
        _ = try await openWindowCall.value
        secrets += try needles("OpenCommissioningWindow payload", openWindowRequest.payload)

        let groupKeyManagement = ClusterID(rawValue: 0x003F), attribute = AttributeID(rawValue: 0)
        let groupKey = Self.random(16)
        let groupPath = AttributePath(endpointID: root, clusterID: groupKeyManagement, attributeID: attribute)
        let read = Task {
            try await rig.controller.readAttribute(nodeID: node, endpointID: root, clusterID: groupKeyManagement, attributeID: attribute)
        }
        let readRequest = try await nextFrame(&peer, session: casePeer, seen: &seen)
        let readResponse = ReportData(attributeReports: [AttributeReportIB(attributeData: AttributeDataIB(path: groupPath, data: withNumber(groupKey)))]).tlvEncode()
        try await peer.send(ScriptedPeer.securedReply(
            to: readRequest, session: casePeer, protocolID: .interactionModel,
            opcode: InteractionModelOpcode.reportData.rawValue, payload: readResponse
        ))
        #expect(try await read.value == withNumber(groupKey))
        secrets += try needles("group key", groupKey)
        secrets += try needles("decrypted ReportData payload", readResponse)

        let written = Self.random(16)
        let write = Task {
            try await rig.controller.writeAttribute(
                nodeID: node, endpointID: root, clusterID: adminCommissioning, attributeID: attribute, value: withNumber(written)
            )
        }
        let writeRequest = try await nextFrame(&peer, session: casePeer, seen: &seen)
        try await peer.send(ScriptedPeer.securedReply(
            to: writeRequest, session: casePeer, protocolID: .interactionModel,
            opcode: InteractionModelOpcode.writeResponse.rawValue,
            payload: WriteResponse(writeResponses: [AttributeStatusIB(
                path: AttributePath(endpointID: root, clusterID: adminCommissioning, attributeID: attribute), status: StatusIB(status: 0)
            )]).tlvEncode()
        ))
        #expect(try await write.value == true)
        secrets += try needles("written value", written)
        secrets += try needles("WriteRequest payload", writeRequest.payload)

        // 5. A subscription to a group-key attribute: a priming report, then one data report.
        let subscriptionID = SubscriptionID(rawValue: 7)
        let primed = Self.random(16), reported = Self.random(16)
        let subscribing = Task {
            try await rig.controller.subscribe(nodeID: node, SubscriptionRequest(attributePaths: [groupPath], minInterval: 1, maxInterval: 10))
        }
        let subscribeRequest = try await nextFrame(&peer, session: casePeer, seen: &seen)
        #expect(subscribeRequest.exchangeHeader.protocolOpcode == InteractionModelOpcode.subscribeRequest.rawValue)
        try await peer.send(ScriptedPeer.securedReply(
            to: subscribeRequest, session: casePeer, protocolID: .interactionModel, opcode: InteractionModelOpcode.reportData.rawValue,
            payload: ReportData(subscriptionID: subscriptionID, attributeReports: [
                AttributeReportIB(attributeData: AttributeDataIB(path: groupPath, data: .octetString(primed))),
            ]).tlvEncode()
        ))
        let primingStatus = try await nextFrame(&peer, session: casePeer, seen: &seen)
        try await peer.send(ScriptedPeer.securedReply(
            to: primingStatus, session: casePeer, protocolID: .interactionModel, opcode: InteractionModelOpcode.subscribeResponse.rawValue,
            payload: SubscribeResponse(subscriptionID: subscriptionID, maxInterval: 10).tlvEncode()
        ))
        let subscription = try await subscribing.value
        var events = subscription.events.makeAsyncIterator()
        let established = await events.next()
        try #require(established?.isEstablished == true, "expected .established, got \(String(describing: established))")
        let priming = await events.next()
        try #require(priming?.isReport == true, "expected the priming report, got \(String(describing: priming))")
        try await peer.send(ScriptedPeer.secured(
            session: casePeer, exchangeID: 0x5000, initiator: true, protocolID: .interactionModel,
            opcode: InteractionModelOpcode.reportData.rawValue,
            payload: ReportData(subscriptionID: subscriptionID, attributeReports: [
                AttributeReportIB(attributeData: AttributeDataIB(path: groupPath, data: withNumber(reported))),
            ]).tlvEncode()
        ))
        let report = await events.next()
        try #require(report?.isReport == true, "expected the data report, got \(String(describing: report))")
        await subscription.cancel()
        secrets += try needles("primed group key", primed)
        secrets += numberNeedles
        secrets += try needles("reported group key", reported)

        // 6. Accidental interpolation of every redacted type the controller side holds.
        let setupCode = try SetupCode(parsing: "34970112332")
        let credentials = try DeviceAttestationCredentials.testCredentials()
        rig.telemetry.logger().info("""
            accidental: \(caseSession) \(casePeer) \(rig.configuration) \(setupCode) \(PASESession(passcode: 20202021)) \
            \(verifier) \(paseKeys) \(fabric.deviceFabric) \(fabric.manager.controllerFabricInfo) \(responder) \
            \(responder.caseContext) \(credentials)
            """)
        secrets += try needles(setupCode: "34970112332")
        secrets += try needles("DAC private key", credentials.dacPrivateKey.rawRepresentation)
        await rig.controller.stop()

        // 7. An unreachable node: MRP gives up and the session is invalidated.
        let silent = try await makeControllerRig(mrp: fastMRP)
        silent.link.setDropProbability(1, from: .a)
        let silentNode = silent.node
        await #expect(throws: ControllerError.peerUnreachable(silentNode)) {
            _ = try await silent.controller.invokeCommand(
                nodeID: silentNode, endpointID: endpoint, clusterID: cluster, commandID: command, commandFields: fields
            )
        }
        secrets += try Self.sessionNeedles("unreachable", silent.controllerSession, attestation: false)
        secrets += try needles("unreachable IPK epoch key", await silent.controller.ipkEpochKey)
        secrets += try needles("unreachable root key", silent.configuration.rootKey.rawRepresentation)
        await silent.controller.stop()

        // Every path was traced.
        let recorded = rig.telemetry.allRecordedText() + silent.telemetry.allRecordedText()
        for prefix in [
            "PASE failed after", "PASE session established in", "CASE session established in", "IM invoke request",
            "IM read value", "IM write request", "Subscription established", "Report 0x0/0x3F/0x0", "Peer unreachable",
        ] {
            #expect(recorded.contains { $0.hasPrefix(prefix) }, "no \"\(prefix)\" line: the path was not traced")
        }
        for span in ["matter.pase", "matter.case", "matter.im.invoke", "matter.im.read", "matter.im.write", "matter.subscribe", "matter.report", "matter.exchange"] {
            #expect(!rig.telemetry.finishedSpans(named: span).isEmpty, "no \(span) span")
        }

        for needle in secrets {
            for text in recorded where text.contains(needle.form) {
                Issue.record("recorded the \(needle.name) (\(needle.form.prefix(8))…) in \(text.prefix(80))")
            }
        }
    }
}

private extension SubscriptionEvent {
    var isEstablished: Bool { if case .established = self { true } else { false } }
    var isReport: Bool { if case .report = self { true } else { false } }
}
