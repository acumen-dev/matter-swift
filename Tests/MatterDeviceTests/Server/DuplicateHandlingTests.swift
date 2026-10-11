// DuplicateHandlingTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Synchronization
import MatterTypes
import MatterTransport
import MatterProtocol
import MatterCrypto
@testable import MatterDevice

@Suite("Device server duplicate detection", .timeLimit(.minutes(1)))
struct DuplicateHandlingTests {

    static let passcode: UInt32 = 20202021
    static let salt = Data(repeating: 0xAB, count: 32)
    static let iterations = 1000

    let sender = MatterAddress(host: "127.0.0.1", port: 12345)

    // MARK: - Unsecured handshake replay

    @Test("A retransmitted PBKDFParamRequest is answered with the byte-identical reply")
    func pbkdfReplayIsVerbatim() async throws {
        let rig = try await startServer()
        let request = Self.unsecuredMessage(
            payload: Self.pbkdfRequest(initiatorSessionID: 100).tlvEncode(),
            opcode: .pbkdfParamRequest,
            counter: 1
        )
        rig.transport.injectDatagram(request, from: sender)
        try await waitForSentCount(rig.transport, atLeast: 1)
        rig.transport.injectDatagram(request, from: sender)
        try await waitForSentCount(rig.transport, atLeast: 2)

        let sent = rig.transport.sentMessages
        #expect(sent.count == 2)
        #expect(sent[0].0 == sent[1].0, "the replay must carry the original message counter")
        await rig.server.stop()
    }

    @Test("A retransmitted Pake1 is answered with the original Pake2, byte for byte")
    func pake1ReplayIsVerbatim() async throws {
        let rig = try await startServer()
        let pase = try await performPASE(rig.transport)
        let before = rig.transport.sentCount

        rig.transport.injectDatagram(pase.pake1Message, from: sender)
        try await waitForSentCount(rig.transport, atLeast: before + 1)

        let sent = rig.transport.sentMessages
        #expect(sent.count == before + 1)
        #expect(sent[before].0 == pase.pake2Message)
        await rig.server.stop()
    }

    @Test("A retransmitted Pake3 replays the StatusReport instead of being dropped")
    func pake3ReplayIsVerbatim() async throws {
        let rig = try await startServer()
        let pase = try await performPASE(rig.transport)
        let before = rig.transport.sentCount

        rig.transport.injectDatagram(pase.pake3Message, from: sender)
        try await waitForSentCount(rig.transport, atLeast: before + 1)

        let sent = rig.transport.sentMessages
        #expect(sent.count == before + 1)
        #expect(sent[before].0 == pase.statusReportMessage)
        await rig.server.stop()
    }

    // MARK: - Secured duplicate detection

    @Test("A duplicate secured InvokeRequest executes once and is acknowledged again")
    func duplicateInvokeExecutesOnce() async throws {
        let toggles = ToggleCounter()
        let rig = try await startServer(onOffChanged: { _ in toggles.increment() })
        let pase = try await performPASE(rig.transport)
        let session = pase.session()
        let invoke = try Self.toggleRequest(endpointID: rig.light.endpointID, session: session, exchangeID: 0x0101)
        let before = rig.transport.sentCount

        rig.transport.injectDatagram(invoke.message, from: sender)
        try await waitForSentCount(rig.transport, atLeast: before + 1)
        rig.transport.injectDatagram(invoke.message, from: sender)
        try await waitForFrame(rig.transport, after: before, session: session) {
            $0.isStandaloneAck && $0.exchange.acknowledgedMessageCounter == invoke.counter
        }

        let frames = try Self.decodeFrames(Array(rig.transport.sentMessages[before...]), session: session)
        let responses = frames.filter { $0.exchange.protocolOpcode == InteractionModelOpcode.invokeResponse.rawValue }
        #expect(!responses.isEmpty)
        #expect(Set(responses.map(\.counter)).count == 1, "MRP re-sends one response; a second execution would add a new counter")
        #expect(toggles.value == 1)
        await rig.server.stop()
    }

    @Test("A secured message below the counter window is acknowledged but never processed")
    func outOfWindowDropped() async throws {
        let toggles = ToggleCounter()
        let rig = try await startServer(onOffChanged: { _ in toggles.increment() })
        let pase = try await performPASE(rig.transport)
        let current = pase.session(initialSendCounter: 1000)
        let stale = pase.session(initialSendCounter: 10)
        let before = rig.transport.sentCount

        let first = try Self.toggleRequest(endpointID: rig.light.endpointID, session: current, exchangeID: 0x0201)
        rig.transport.injectDatagram(first.message, from: sender)
        try await waitForFrame(rig.transport, after: before, session: current) {
            $0.exchange.acknowledgedMessageCounter == first.counter
        }

        let old = try Self.toggleRequest(endpointID: rig.light.endpointID, session: stale, exchangeID: 0x0202)
        rig.transport.injectDatagram(old.message, from: sender)
        // The server handles datagrams in order: once the next request is
        // answered, the stale one has been processed.
        let second = try Self.toggleRequest(endpointID: rig.light.endpointID, session: current, exchangeID: 0x0203)
        rig.transport.injectDatagram(second.message, from: sender)
        try await waitForFrame(rig.transport, after: before, session: current) {
            $0.exchange.acknowledgedMessageCounter == second.counter
        }

        let frames = try Self.decodeFrames(Array(rig.transport.sentMessages[before...]), session: current)
        #expect(frames.contains { $0.isStandaloneAck && $0.exchange.acknowledgedMessageCounter == old.counter },
                "a behind-window reliable message is acked like a duplicate, so the peer stops retransmitting")
        #expect(toggles.value == 2, "the stale request must not be processed")
        await rig.server.stop()
    }

    // MARK: - Rig

    struct Rig {
        let server: MatterDeviceServer
        let transport: MockServerUDPTransport
        let light: BridgedEndpoint
    }

    private func startServer(onOffChanged: (@Sendable (Bool) -> Void)? = nil) async throws -> Rig {
        let transport = MockServerUDPTransport()
        let bridge = MatterBridge()
        let light = bridge.addDimmableLight(name: "Duplicate Light", onOffChanged: onOffChanged)
        let server = MatterDeviceServer(
            bridge: bridge,
            transport: transport,
            discovery: MockServerDiscovery(),
            config: .init(
                discriminator: 3840,
                passcode: Self.passcode,
                port: 5540,
                salt: Self.salt,
                iterations: Self.iterations
            )
        )
        try await server.start()
        return Rig(server: server, transport: transport, light: light)
    }

    struct PASEResult {
        let keys: SessionKeys
        let initiatorSessionID: UInt16
        let responderSessionID: UInt16
        let pake1Message: Data
        let pake2Message: Data
        let pake3Message: Data
        let statusReportMessage: Data

        /// The commissioner's side of the PASE session.
        func session(initialSendCounter: UInt32? = nil) -> SecureSession {
            SecureSession(
                localSessionID: initiatorSessionID,
                peerSessionID: responderSessionID,
                establishment: .pase,
                peerNodeID: NodeID(rawValue: 0),
                initialSendCounter: initialSendCounter,
                encryptKey: keys.i2rKey,
                decryptKey: keys.r2iKey
            )
        }
    }

    /// Run PASE as the commissioner against the server (counters 1, 2, 3).
    private func performPASE(_ transport: MockServerUDPTransport) async throws -> PASEResult {
        let initiatorSessionID: UInt16 = 100
        let start = transport.sentCount
        let request = Self.pbkdfRequest(initiatorSessionID: initiatorSessionID)
        let requestTLV = request.tlvEncode()

        transport.injectDatagram(Self.unsecuredMessage(payload: requestTLV, opcode: .pbkdfParamRequest, counter: 1), from: sender)
        try await waitForSentCount(transport, atLeast: start + 1)
        let responseTLV = try Self.unsecuredBody(transport.sentMessages[start].0)
        let pbkdfResponse = try PASEMessages.PBKDFParamResponse.fromTLV(responseTLV)

        let hashContext = Spake2p.computeHashContext(pbkdfParamRequest: requestTLV, pbkdfParamResponse: responseTLV)
        let (w0, w1) = Spake2p.deriveW0W1(passcode: Self.passcode, salt: Self.salt, iterations: Self.iterations)
        let (proverContext, pA) = try Spake2p.proverStep1(w0: w0)

        let pake1Message = Self.unsecuredMessage(payload: PASEMessages.Pake1Message(pA: pA).tlvEncode(), opcode: .pasePake1, counter: 2)
        transport.injectDatagram(pake1Message, from: sender)
        try await waitForSentCount(transport, atLeast: start + 2)
        let pake2Message = transport.sentMessages[start + 1].0
        let pake2 = try PASEMessages.Pake2Message.fromTLV(Self.unsecuredBody(pake2Message))
        let (cA, ke) = try Spake2p.proverStep2(context: proverContext, pB: pake2.pB, cB: pake2.cB, hashContext: hashContext, w1: w1)

        let pake3Message = Self.unsecuredMessage(payload: PASEMessages.Pake3Message(cA: cA).tlvEncode(), opcode: .pasePake3, counter: 3)
        transport.injectDatagram(pake3Message, from: sender)
        try await waitForSentCount(transport, atLeast: start + 3)
        let statusReportMessage = transport.sentMessages[start + 2].0
        let status = try StatusReportMessage.decode(from: Self.unsecuredBody(statusReportMessage))
        guard status.generalStatus == .success else { throw DuplicateTestError.paseFailed }

        return PASEResult(
            keys: KeyDerivation.deriveSessionKeys(sharedSecret: ke),
            initiatorSessionID: initiatorSessionID,
            responderSessionID: pbkdfResponse.responderSessionID,
            pake1Message: pake1Message,
            pake2Message: pake2Message,
            pake3Message: pake3Message,
            statusReportMessage: statusReportMessage
        )
    }

    // MARK: - Frames

    struct Frame {
        let counter: UInt32
        let exchange: ExchangeHeader

        var isStandaloneAck: Bool {
            exchange.protocolID == MatterProtocolID.secureChannel.rawValue
                && exchange.protocolOpcode == SecureChannelOpcode.standaloneAck.rawValue
        }
    }

    static func decodeFrames(_ datagrams: [(Data, MatterAddress)], session: SecureSession) throws -> [Frame] {
        try datagrams.map { data, _ in
            let (messageHeader, exchangeHeader, _) = try SecureMessageCodec.decode(data: data, session: session)
            return Frame(counter: messageHeader.messageCounter, exchange: exchangeHeader)
        }
    }

    static func toggleRequest(endpointID: EndpointID, session: SecureSession, exchangeID: UInt16) throws -> (message: Data, counter: UInt32) {
        let payload = IMClient.invokeCommandRequest(
            endpointID: endpointID,
            clusterID: ClusterID(rawValue: 0x0006),   // OnOff
            commandID: CommandID(rawValue: 0x0002)    // Toggle
        )
        let header = ExchangeHeader(
            flags: ExchangeFlags(initiator: true, reliableDelivery: true),
            protocolOpcode: InteractionModelOpcode.invokeRequest.rawValue,
            exchangeID: exchangeID,
            protocolID: MatterProtocolID.interactionModel.rawValue
        )
        let message = try SecureMessageCodec.encode(exchangeHeader: header, payload: payload, session: session, sourceNodeID: NodeID(rawValue: 0))
        let (messageHeader, _) = try MessageHeader.decode(from: message)
        return (message, messageHeader.messageCounter)
    }

    static func pbkdfRequest(initiatorSessionID: UInt16) -> PASEMessages.PBKDFParamRequest {
        var random = Data(count: 32)
        random.withUnsafeMutableBytes { buffer in
            var rng = SystemRandomNumberGenerator()
            for offset in stride(from: 0, to: 32, by: 8) {
                buffer.storeBytes(of: rng.next(), toByteOffset: offset, as: UInt64.self)
            }
        }
        return PASEMessages.PBKDFParamRequest(initiatorRandom: random, initiatorSessionID: initiatorSessionID)
    }

    static func unsecuredMessage(payload: Data, opcode: SecureChannelOpcode, counter: UInt32) -> Data {
        MatterMessage.encodeUnsecured(
            messageHeader: MessageHeader(sessionID: 0, messageCounter: counter),
            exchangeHeader: ExchangeHeader(
                flags: ExchangeFlags(initiator: true, reliableDelivery: true),
                protocolOpcode: opcode.rawValue,
                exchangeID: 1,
                protocolID: MatterProtocolID.secureChannel.rawValue
            ),
            payload: payload
        )
    }

    static func unsecuredBody(_ data: Data) throws -> Data {
        try MatterMessage.decodeUnsecured(from: data).payload
    }

    // MARK: - Waiting for outcomes

    private func waitForSentCount(_ transport: MockServerUDPTransport, atLeast count: Int) async throws {
        let deadline = ContinuousClock.now + .seconds(10)
        while transport.sentCount < count {
            guard ContinuousClock.now < deadline else { throw DuplicateTestError.timedOut }
            try await Task.sleep(for: .milliseconds(20))
        }
    }

    private func waitForFrame(
        _ transport: MockServerUDPTransport,
        after start: Int,
        session: SecureSession,
        where predicate: (Frame) -> Bool
    ) async throws {
        let deadline = ContinuousClock.now + .seconds(10)
        while true {
            let frames = try Self.decodeFrames(Array(transport.sentMessages[start...]), session: session)
            if frames.contains(where: predicate) { return }
            guard ContinuousClock.now < deadline else { throw DuplicateTestError.timedOut }
            try await Task.sleep(for: .milliseconds(20))
        }
    }
}

private enum DuplicateTestError: Error {
    case paseFailed
    case timedOut
}

/// Counts OnOff changes reported by the bridged light.
private final class ToggleCounter: Sendable {
    private let count = Mutex(0)
    func increment() { count.withLock { $0 += 1 } }
    var value: Int { count.withLock { $0 } }
}
