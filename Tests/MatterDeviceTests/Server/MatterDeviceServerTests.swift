// MatterDeviceServerTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTransport
import MatterProtocol
import MatterCrypto
@testable import MatterDevice

@Suite("MatterDeviceServer")
struct MatterDeviceServerTests {

    // MARK: - Lifecycle Tests

    @Test("Server start binds transport and advertises")
    func serverStartBindsAndAdvertises() async throws {
        let transport = MockServerUDPTransport()
        let discovery = MockServerDiscovery()
        let bridge = MatterBridge()

        let server = MatterDeviceServer(
            bridge: bridge,
            transport: transport,
            discovery: discovery,
            config: .init(discriminator: 3840, passcode: 20202021, port: 5540)
        )

        try await server.start()

        // Verify transport was bound
        let boundPort = transport.boundPort
        #expect(boundPort == 5540)

        // The initial advertisement is posted from a Task spawned by openBasicWindow;
        // poll until it arrives so Linux schedulers (which are less eager than macOS)
        // don't cause a spurious failure.
        try await waitForAdvertisedCount(discovery, atLeast: 1)

        // Verify discovery was called
        let services = await discovery.advertisedServices
        #expect(services.count == 1)
        if services.count >= 1 {
            #expect(services[0].serviceType == .commissionable)
            #expect(services[0].txtRecords["D"] == "3840")
            #expect(services[0].txtRecords["CM"] == "1")
        }

        await server.stop()
    }

    @Test("Server stop cancels advertising and closes transport")
    func serverStop() async throws {
        let transport = MockServerUDPTransport()
        let discovery = MockServerDiscovery()
        let bridge = MatterBridge()

        let server = MatterDeviceServer(
            bridge: bridge,
            transport: transport,
            discovery: discovery
        )

        try await server.start()
        await server.stop()

        let isAdvertising = await discovery.isAdvertising
        #expect(isAdvertising == false)

        let isClosed = transport.isClosed
        #expect(isClosed == true)
    }

    // MARK: - PASE Handshake Tests

    @Test("Full PASE handshake establishes session")
    func fullPASEHandshake() async throws {
        let transport = MockServerUDPTransport()
        let discovery = MockServerDiscovery()
        let bridge = MatterBridge()

        let config = MatterDeviceServer.Config(
            discriminator: 3840,
            passcode: 20202021,
            port: 5540,
            salt: Data(repeating: 0xAB, count: 32),
            iterations: 1000
        )

        let server = MatterDeviceServer(
            bridge: bridge,
            transport: transport,
            discovery: discovery,
            config: config
        )

        try await server.start()

        let sender = MatterAddress(host: "127.0.0.1", port: 12345)

        // Step 1: Send PBKDFParamRequest
        var initiatorRandom = Data(count: 32)
        initiatorRandom.withUnsafeMutableBytes { buf in
            var rng = SystemRandomNumberGenerator()
            buf.storeBytes(of: rng.next(), toByteOffset: 0,  as: UInt64.self)
            buf.storeBytes(of: rng.next(), toByteOffset: 8,  as: UInt64.self)
            buf.storeBytes(of: rng.next(), toByteOffset: 16, as: UInt64.self)
            buf.storeBytes(of: rng.next(), toByteOffset: 24, as: UInt64.self)
        }

        let pbkdfRequest = PASEMessages.PBKDFParamRequest(
            initiatorRandom: initiatorRandom,
            initiatorSessionID: 100,
            passcodeID: 0,
            hasPBKDFParameters: false
        )

        let pbkdfRequestMsg = buildUnsecuredMessage(
            payload: pbkdfRequest.tlvEncode(),
            opcode: .pbkdfParamRequest,
            exchangeID: 1,
            isInitiator: true,
            counter: 1
        )

        transport.injectDatagram(pbkdfRequestMsg, from: sender)

        // Wait for server to process and send response
        try await waitForSentCount(transport, atLeast: 1)

        // Verify PBKDFParamResponse was sent
        let sentCount1 = transport.sentCount
        #expect(sentCount1 >= 1, "Expected PBKDFParamResponse to be sent")

        if sentCount1 >= 1 {
            let (responseData, responseAddr) = transport.sentMessages[0]
            #expect(responseAddr == sender)

            // Parse the response
            let (respHeader, respHeaderConsumed) = try MessageHeader.decode(from: responseData)
            #expect(respHeader.sessionID == 0, "Response should be unsecured")

            let afterHeader = Data(responseData.suffix(from: respHeaderConsumed))
            let (respExchHeader, respExchConsumed) = try ExchangeHeader.decode(from: afterHeader)
            #expect(respExchHeader.protocolOpcode == SecureChannelOpcode.pbkdfParamResponse.rawValue)

            let respBody = Data(afterHeader.suffix(from: respExchConsumed))
            let pbkdfResponse = try PASEMessages.PBKDFParamResponse.fromTLV(respBody)
            #expect(pbkdfResponse.initiatorRandom == initiatorRandom)
            #expect(pbkdfResponse.iterations == 1000)
            #expect(pbkdfResponse.salt == config.salt)

            // Step 2: Compute prover side and send Pake1
            let requestTLV = pbkdfRequest.tlvEncode()
            let responseTLV = pbkdfResponse.tlvEncode()

            let hashContext = Spake2p.computeHashContext(
                pbkdfParamRequest: requestTLV,
                pbkdfParamResponse: responseTLV
            )

            let (w0, w1) = Spake2p.deriveW0W1(
                passcode: config.passcode,
                salt: config.salt!,
                iterations: config.iterations
            )

            let (proverContext, pA) = try Spake2p.proverStep1(w0: w0)

            let pake1 = PASEMessages.Pake1Message(pA: pA)
            let pake1Msg = buildUnsecuredMessage(
                payload: pake1.tlvEncode(),
                opcode: .pasePake1,
                exchangeID: 1,
                isInitiator: true,
                counter: 2
            )

            transport.injectDatagram(pake1Msg, from: sender)
            try await waitForSentCount(transport, atLeast: 2)

            // Verify Pake2 was sent
            let sentCount2 = transport.sentCount
            #expect(sentCount2 >= 2, "Expected Pake2 to be sent")

            if sentCount2 >= 2 {
                let (pake2Data, _) = transport.sentMessages[1]
                let (_, p2HeaderConsumed) = try MessageHeader.decode(from: pake2Data)
                let p2After = Data(pake2Data.suffix(from: p2HeaderConsumed))
                let (p2Exch, p2ExchConsumed) = try ExchangeHeader.decode(from: p2After)
                #expect(p2Exch.protocolOpcode == SecureChannelOpcode.pasePake2.rawValue)

                let p2Body = Data(p2After.suffix(from: p2ExchConsumed))
                let pake2 = try PASEMessages.Pake2Message.fromTLV(p2Body)

                // Step 3: Prover step 2 and send Pake3
                let (cA, _) = try Spake2p.proverStep2(
                    context: proverContext,
                    pB: pake2.pB,
                    cB: pake2.cB,
                    hashContext: hashContext,
                    w1: w1
                )

                let pake3 = PASEMessages.Pake3Message(cA: cA)
                let pake3Msg = buildUnsecuredMessage(
                    payload: pake3.tlvEncode(),
                    opcode: .pasePake3,
                    exchangeID: 1,
                    isInitiator: true,
                    counter: 3
                )

                transport.injectDatagram(pake3Msg, from: sender)
                try await waitForSentCount(transport, atLeast: 3)

                // Verify Status Report (success) was sent
                let sentCount3 = transport.sentCount
                #expect(sentCount3 >= 3, "Expected StatusReport to be sent")

                if sentCount3 >= 3 {
                    let (statusData, _) = transport.sentMessages[2]
                    let (_, sHeaderConsumed) = try MessageHeader.decode(from: statusData)
                    let sAfter = Data(statusData.suffix(from: sHeaderConsumed))
                    let (sExch, sExchConsumed) = try ExchangeHeader.decode(from: sAfter)
                    #expect(sExch.protocolOpcode == SecureChannelOpcode.statusReport.rawValue)

                    let sBody = Data(sAfter.suffix(from: sExchConsumed))
                    let statusReport = try StatusReportMessage.decode(from: sBody)
                    #expect(statusReport.generalStatus == .success)
                }
            }
        }

        await server.stop()
    }

    @Test("Unknown session ID drops message")
    func unknownSessionDropped() async throws {
        let transport = MockServerUDPTransport()
        let discovery = MockServerDiscovery()
        let bridge = MatterBridge()

        let server = MatterDeviceServer(
            bridge: bridge,
            transport: transport,
            discovery: discovery
        )

        try await server.start()

        // Send a message with unknown session ID
        let header = MessageHeader(
            sessionID: 999,
            messageCounter: 1
        )
        var message = header.encode()
        message.append(Data([0x00, 0x01, 0x02])) // garbage payload

        let sender = MatterAddress(host: "127.0.0.1", port: 12345)
        transport.injectDatagram(message, from: sender)

        // Give server time to (not) process — use a reasonable fixed delay here
        // since we're checking the absence of a response
        try await Task.sleep(for: .milliseconds(500))

        // No response should be sent
        let sentCount = transport.sentCount
        #expect(sentCount == 0, "No response should be sent for unknown session")

        await server.stop()
    }

    // MARK: - Helpers

    /// Poll until the mock transport has sent at least `count` messages, or timeout.
    private func waitForSentCount(
        _ transport: MockServerUDPTransport,
        atLeast count: Int,
        timeout: Duration = .seconds(10)
    ) async throws {
        let deadline = ContinuousClock.now + timeout
        while transport.sentCount < count {
            guard ContinuousClock.now < deadline else { return }
            try await Task.sleep(for: .milliseconds(50))
        }
    }

    /// Poll until the mock discovery has at least `count` advertised services, or timeout.
    private func waitForAdvertisedCount(
        _ discovery: MockServerDiscovery,
        atLeast count: Int,
        timeout: Duration = .seconds(5)
    ) async throws {
        let deadline = ContinuousClock.now + timeout
        while await discovery.advertisedServices.count < count {
            guard ContinuousClock.now < deadline else { return }
            try await Task.sleep(for: .milliseconds(20))
        }
    }

    /// Build an unsecured message (same pattern as MatterController).
    private func buildUnsecuredMessage(
        payload: Data,
        opcode: SecureChannelOpcode,
        exchangeID: UInt16,
        isInitiator: Bool,
        counter: UInt32
    ) -> Data {
        let messageHeader = MessageHeader(
            sessionID: 0,
            messageCounter: counter,
            sourceNodeID: nil
        )

        let exchangeHeader = ExchangeHeader(
            flags: ExchangeFlags(
                initiator: isInitiator,
                reliableDelivery: true
            ),
            protocolOpcode: opcode.rawValue,
            exchangeID: exchangeID,
            protocolID: MatterProtocolID.secureChannel.rawValue
        )

        var message = messageHeader.encode()
        message.append(exchangeHeader.encode())
        message.append(payload)
        return message
    }
}
