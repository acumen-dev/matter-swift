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
        let ack = try #require(frames.first { $0.isStandaloneAck && $0.exchange.acknowledgedMessageCounter == invoke.counter })
        #expect(ack.exchange.exchangeID == 0x0101)
        #expect(!ack.exchange.flags.initiator, "the controller opened the exchange, so the device's ack is not from the initiator")
        let responses = frames.filter { $0.exchange.protocolOpcode == InteractionModelOpcode.invokeResponse.rawValue }
        #expect(!responses.isEmpty)
        #expect(Set(responses.map(\.counter)).count == 1, "MRP re-sends one response; a second execution would add a new counter")
        #expect(toggles.value == 1)
        await rig.server.stop()
    }

    @Test("A response whose first send fails is still tracked, so the MRP loop recovers it")
    func failedFirstSendIsRecovered() async throws {
        let toggles = ToggleCounter()
        let rig = try await startServer(onOffChanged: { _ in toggles.increment() })
        let pase = try await performPASE(rig.transport)
        let session = pase.session()
        let invoke = try Self.toggleRequest(endpointID: rig.light.endpointID, session: session, exchangeID: 0x0301)
        let before = rig.transport.sentCount

        rig.transport.failNextSends(1)
        rig.transport.injectDatagram(invoke.message, from: sender)
        // The retransmission arrives after the response's first send failed.
        rig.transport.injectDatagram(invoke.message, from: sender)
        try await waitForFrame(rig.transport, after: before, session: session) {
            $0.isStandaloneAck && $0.exchange.acknowledgedMessageCounter == invoke.counter
        }
        // The MRP loop re-sends the tracked response.
        try await waitForFrame(rig.transport, after: before, session: session) {
            $0.exchange.protocolOpcode == InteractionModelOpcode.invokeResponse.rawValue
        }
        // The send that failed was the response itself, and the frame that
        // reached the peer is that same message, retransmitted.
        let dropped = try Self.decodeFrames(rig.transport.droppedMessages, session: session)
        try #require(dropped.count == 1)
        #expect(dropped[0].exchange.protocolOpcode == InteractionModelOpcode.invokeResponse.rawValue)
        #expect(dropped[0].exchange.exchangeID == 0x0301)
        let frames = try Self.decodeFrames(Array(rig.transport.sentMessages[before...]), session: session)
        let responses = frames.filter { $0.exchange.protocolOpcode == InteractionModelOpcode.invokeResponse.rawValue }
        #expect(!responses.isEmpty)
        #expect(responses.allSatisfy { $0.counter == dropped[0].counter }, "MRP re-sends the dropped response under its own counter")
        #expect(toggles.value == 1)
        await rig.server.stop()
    }

    // MARK: - Chunked reports

    @Test("A chunked read whose first chunk send fails still delivers every chunk exactly once, in order")
    func failedFirstChunkSendDeliversEveryChunk() async throws {
        let rig = try await startServer(extraLights: 2)
        let pase = try await performPASE(rig.transport)
        let session = pase.session()

        let reference = try await readChunked(rig, session: session, exchangeID: 0x0501)
        try #require(reference.count >= 3, "the wildcard read must be chunked for this test to mean anything")

        let failing = try await readChunked(rig, session: session, exchangeID: 0x0502, failSendBefore: 0)
        try #require(rig.transport.droppedMessages.count == 1)
        let dropped = try Self.decodeFrames(rig.transport.droppedMessages, session: session)
        #expect(dropped[0].exchange.exchangeID == 0x0502)
        #expect(dropped[0].payload == failing.first?.payload, "the failed send was chunk 1")
        #expect(failing.map(\.payload) == reference.map(\.payload))
        await rig.server.stop()
    }

    @Test("A chunked read whose second chunk send fails never repeats a chunk under a new counter")
    func failedLaterChunkSendIsNotRepeated() async throws {
        let rig = try await startServer(extraLights: 2)
        let pase = try await performPASE(rig.transport)
        let session = pase.session()

        let reference = try await readChunked(rig, session: session, exchangeID: 0x0601)
        try #require(reference.count >= 3, "the wildcard read must be chunked for this test to mean anything")

        let failing = try await readChunked(rig, session: session, exchangeID: 0x0602, failSendBefore: 1)
        try #require(rig.transport.droppedMessages.count == 1)
        let dropped = try Self.decodeFrames(rig.transport.droppedMessages, session: session)
        #expect(dropped[0].exchange.exchangeID == 0x0602)
        #expect(dropped[0].payload == failing.dropFirst().first?.payload, "the failed send was chunk 2")
        #expect(failing.map(\.payload) == reference.map(\.payload), "each chunk once, in order")
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

    private func startServer(onOffChanged: (@Sendable (Bool) -> Void)? = nil, extraLights: Int = 0) async throws -> Rig {
        let transport = MockServerUDPTransport()
        let bridge = MatterBridge()
        let light = bridge.addDimmableLight(name: "Duplicate Light", onOffChanged: onOffChanged)
        for index in 0..<extraLights {
            _ = bridge.addDimmableLight(name: "Extra Light \(index)")
        }
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
        let payload: Data

        var isStandaloneAck: Bool {
            exchange.protocolID == MatterProtocolID.secureChannel.rawValue
                && exchange.protocolOpcode == SecureChannelOpcode.standaloneAck.rawValue
        }
    }

    static func decodeFrames(_ datagrams: [(Data, MatterAddress)], session: SecureSession) throws -> [Frame] {
        try datagrams.map { data, _ in
            let (messageHeader, exchangeHeader, payload) = try SecureMessageCodec.decode(data: data, session: session)
            return Frame(counter: messageHeader.messageCounter, exchange: exchangeHeader, payload: payload)
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

    /// Read every attribute as the client on `exchangeID`, acknowledging each
    /// new chunk with a StatusResponse (piggybacking its ack), and return the
    /// ReportData frames in arrival order, one per message counter (an MRP
    /// retransmission repeats a counter and is not a new chunk).
    ///
    /// - Parameter failSendBefore: make the server's send of the chunk with
    ///   this index fail once (it is armed just before the message that
    ///   triggers that send).
    private func readChunked(
        _ rig: Rig,
        session: SecureSession,
        exchangeID: UInt16,
        failSendBefore failIndex: Int? = nil
    ) async throws -> [Frame] {
        let start = rig.transport.sentCount
        let read = ReadRequest(attributeRequests: [AttributePath()], isFabricFiltered: false)
        if failIndex == 0 { rig.transport.failNextSends(1) }
        rig.transport.injectDatagram(
            try Self.securedRequest(session: session, exchangeID: exchangeID, opcode: .readRequest, payload: read.tlvEncode()),
            from: sender
        )

        var chunks: [Frame] = []
        while true {
            let seen = Set(chunks.map(\.counter))
            let chunk = try await waitForFrameValue(rig.transport, after: start, session: session) {
                $0.exchange.exchangeID == exchangeID
                    && $0.exchange.protocolOpcode == InteractionModelOpcode.reportData.rawValue
                    && !seen.contains($0.counter)
            }
            chunks.append(chunk)
            guard try ReportData.fromTLV(chunk.payload).moreChunkedMessages else {
                // Acknowledge the final chunk and wait for the server's ack of
                // that: the exchange is then closed, so nothing on it is still
                // being retransmitted when a later read arms a send failure.
                let final = try Self.securedRequest(
                    session: session, exchangeID: exchangeID, opcode: .statusResponse,
                    payload: IMStatusResponse.success.tlvEncode(), acknowledging: chunk.counter
                )
                let finalCounter = try MessageHeader.decode(from: final).header.messageCounter
                rig.transport.injectDatagram(final, from: sender)
                try await waitForFrame(rig.transport, after: start, session: session) {
                    $0.exchange.exchangeID == exchangeID && $0.isStandaloneAck
                        && $0.exchange.acknowledgedMessageCounter == finalCounter
                }
                return chunks
            }
            if failIndex == chunks.count { rig.transport.failNextSends(1) }
            rig.transport.injectDatagram(
                try Self.securedRequest(
                    session: session, exchangeID: exchangeID, opcode: .statusResponse,
                    payload: IMStatusResponse.success.tlvEncode(), acknowledging: chunk.counter
                ),
                from: sender
            )
        }
    }

    static func securedRequest(
        session: SecureSession,
        exchangeID: UInt16,
        opcode: InteractionModelOpcode,
        payload: Data,
        acknowledging ackCounter: UInt32? = nil
    ) throws -> Data {
        let header = ExchangeHeader(
            flags: ExchangeFlags(initiator: true, reliableDelivery: true),
            protocolOpcode: opcode.rawValue,
            exchangeID: exchangeID,
            protocolID: MatterProtocolID.interactionModel.rawValue,
            acknowledgedMessageCounter: ackCounter
        )
        return try SecureMessageCodec.encode(exchangeHeader: header, payload: payload, session: session, sourceNodeID: NodeID(rawValue: 0))
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

    /// Waits for the device to have sent `count` messages. No deadline: the
    /// suite's `.timeLimit` is the hang guard.
    private func waitForSentCount(_ transport: MockServerUDPTransport, atLeast count: Int) async throws {
        try await transport.awaitSent(atLeast: count)
    }

    private func waitForFrame(
        _ transport: MockServerUDPTransport,
        after start: Int,
        session: SecureSession,
        where predicate: (Frame) -> Bool
    ) async throws {
        _ = try await waitForFrameValue(transport, after: start, session: session, where: predicate)
    }

    /// The first frame sent after `start` matching `predicate`. Each sent
    /// frame is decoded once, as it arrives; no deadline (the suite's
    /// `.timeLimit` is the hang guard).
    private func waitForFrameValue(
        _ transport: MockServerUDPTransport,
        after start: Int,
        session: SecureSession,
        where predicate: (Frame) -> Bool
    ) async throws -> Frame {
        var next = start
        while true {
            try await transport.awaitSent(atLeast: next + 1)
            let sent = transport.sentMessages
            let frames = try Self.decodeFrames(Array(sent[next...]), session: session)
            next = sent.count
            if let frame = frames.first(where: predicate) { return frame }
        }
    }
}

private enum DuplicateTestError: Error {
    case paseFailed
}

/// Counts OnOff changes reported by the bridged light.
private final class ToggleCounter: Sendable {
    private let count = Mutex(0)
    func increment() { count.withLock { $0 += 1 } }
    var value: Int { count.withLock { $0 } }
}
