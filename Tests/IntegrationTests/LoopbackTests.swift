// LoopbackTests.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(Network)
import Testing
import Foundation
import Crypto
import Network
import MatterTypes
import MatterModel
import MatterCrypto
import MatterProtocol
import MatterTransport
import MatterApple
import MatterController
import MatterDevice

@Suite("Loopback Integration", .serialized)
struct LoopbackTests {

    // MARK: - Shared Config

    static let serverPort: UInt16 = 5555
    static let passcode: UInt32 = 20202021
    static let discriminator: UInt16 = 3840
    static let salt = Data(repeating: 0xAB, count: 32)
    static let iterations = 1000

    // MARK: - Discovery

    @Test("mDNS advertise and browse on localhost")
    func discoveryLoopback() async throws {
        // Use AppleDiscovery directly (no MatterDeviceServer) to avoid
        // the port conflict between transport listener and discovery listener.
        let advertiser = AppleDiscovery()
        let browser = AppleDiscovery()

        let service = MatterServiceRecord(
            name: "SwiftMatter-\(Self.discriminator)",
            serviceType: .commissionable,
            host: "",
            port: 5556,  // Different port — no transport listener conflict
            txtRecords: ["D": "\(Self.discriminator)", "CM": "1"]
        )

        try await advertiser.advertise(service: service)

        // Give mDNS time to propagate
        try await Task.sleep(for: .milliseconds(500))

        let browseStream = browser.browse(type: .commissionable)

        let found = await withTaskGroup(of: MatterServiceRecord?.self) { group in
            group.addTask {
                for await record in browseStream {
                    if record.name.contains("SwiftMatter-\(Self.discriminator)") {
                        return record
                    }
                }
                return nil
            }
            group.addTask {
                try? await Task.sleep(for: .seconds(5))
                return nil
            }
            let result = await group.next()!
            group.cancelAll()
            return result
        }

        #expect(found != nil, "Should discover the service via mDNS")
        #expect(found?.name.contains("\(Self.discriminator)") == true)

        await advertiser.stopAdvertising()
    }

    // MARK: - PASE over Real UDP

    @Test("Full PASE handshake over real UDP on localhost")
    func paseOverRealUDP() async throws {
        let (server, _, config) = try await startServer()
        let channel = try TestUDPChannel()
        let serverAddress = MatterAddress(host: "127.0.0.1", port: Self.serverPort)

        defer {
            channel.close()
        }

        do {
            let pase = try await performPASE(
                channel: channel,
                config: config,
                serverAddress: serverAddress
            )

            // Verify session keys are non-empty
            #expect(pase.session.localSessionID > 0)
            #expect(pase.session.peerSessionID > 0)
        } catch {
            await server.stop()
            try await Task.sleep(for: .milliseconds(500))
            throw error
        }

        await server.stop()
        try await Task.sleep(for: .milliseconds(500))
    }

    // MARK: - Encrypted IM Read

    @Test("Read OnOff attribute over encrypted PASE session on real UDP")
    func encryptedIMRead() async throws {
        let (server, _, config) = try await startServer()
        let channel = try TestUDPChannel()
        let serverAddress = MatterAddress(host: "127.0.0.1", port: Self.serverPort)

        defer {
            channel.close()
        }

        do {
            let pase = try await performPASE(
                channel: channel,
                config: config,
                serverAddress: serverAddress
            )

            // Build encrypted ReadRequest for OnOff.onOff on endpoint 3 (first dimmable light)
            let opCtrl = OperationalController()
            let readMsg = try opCtrl.readAttribute(
                endpointID: EndpointID(rawValue: 3),
                clusterID: .onOff,
                attributeID: OnOffCluster.Attribute.onOff,
                session: pase.session,
                sourceNodeID: NodeID(rawValue: 0)
            )

            // Send encrypted read request
            try await channel.send(readMsg, to: serverAddress)

            // Receive encrypted response
            let (responseData, _) = try await channel.receiveOne()

            // Parse the encrypted response
            let value = try opCtrl.parseReadResponse(
                encryptedMessage: responseData,
                session: pase.session
            )

            // Default onOff value should be false
            #expect(value.boolValue == false, "Default OnOff should be false")
        } catch {
            await server.stop()
            try await Task.sleep(for: .milliseconds(500))
            throw error
        }

        await server.stop()
        try await Task.sleep(for: .milliseconds(500))
    }

    // MARK: - Encrypted IM Write + Invoke + Read-back

    @Test("Write, invoke toggle, and read-back OnOff over encrypted PASE session")
    func encryptedIMWriteInvokeRead() async throws {
        let (server, _, config) = try await startServer()
        let channel = try TestUDPChannel()
        let serverAddress = MatterAddress(host: "127.0.0.1", port: Self.serverPort)

        defer {
            channel.close()
        }

        do {
            let pase = try await performPASE(
                channel: channel,
                config: config,
                serverAddress: serverAddress
            )

            let opCtrl = OperationalController()
            let endpointID = EndpointID(rawValue: 3)

            // Step 1: Write OnOff = true
            let writeMsg = try opCtrl.writeAttribute(
                endpointID: endpointID,
                clusterID: .onOff,
                attributeID: OnOffCluster.Attribute.onOff,
                value: .bool(true),
                session: pase.session,
                sourceNodeID: NodeID(rawValue: 0)
            )

            try await channel.send(writeMsg, to: serverAddress)
            let (writeResp, _) = try await channel.receiveOne()
            let writeSuccess = try opCtrl.parseWriteResponse(
                encryptedMessage: writeResp,
                session: pase.session
            )
            #expect(writeSuccess == true, "Write should succeed")

            // Step 2: Read back — should be true
            let readMsg1 = try opCtrl.readAttribute(
                endpointID: endpointID,
                clusterID: .onOff,
                attributeID: OnOffCluster.Attribute.onOff,
                session: pase.session,
                sourceNodeID: NodeID(rawValue: 0)
            )

            try await channel.send(readMsg1, to: serverAddress)
            let (readResp1, _) = try await channel.receiveOne()
            let val1 = try opCtrl.parseReadResponse(
                encryptedMessage: readResp1,
                session: pase.session
            )
            #expect(val1.boolValue == true, "OnOff should be true after write")

            // Step 3: Invoke toggle
            let invokeMsg = try opCtrl.invokeCommand(
                endpointID: endpointID,
                clusterID: .onOff,
                commandID: OnOffCluster.Command.toggle,
                session: pase.session,
                sourceNodeID: NodeID(rawValue: 0)
            )

            try await channel.send(invokeMsg, to: serverAddress)
            let (invokeResp, _) = try await channel.receiveOne()
            let _ = try opCtrl.parseInvokeResponse(
                encryptedMessage: invokeResp,
                session: pase.session
            )

            // Step 4: Read back — should be false (toggled)
            let readMsg2 = try opCtrl.readAttribute(
                endpointID: endpointID,
                clusterID: .onOff,
                attributeID: OnOffCluster.Attribute.onOff,
                session: pase.session,
                sourceNodeID: NodeID(rawValue: 0)
            )

            try await channel.send(readMsg2, to: serverAddress)
            let (readResp2, _) = try await channel.receiveOne()
            let val2 = try opCtrl.parseReadResponse(
                encryptedMessage: readResp2,
                session: pase.session
            )
            #expect(val2.boolValue == false, "OnOff should be false after toggle")
        } catch {
            await server.stop()
            try await Task.sleep(for: .milliseconds(500))
            throw error
        }

        await server.stop()
        try await Task.sleep(for: .milliseconds(500))
    }

    // MARK: - Full Commissioning + CASE

    @Test("Full commissioning flow and CASE operational read")
    func fullCommissioningAndCASE() async throws {
        let (server, _, _) = try await startServer()
        let serverAddress = MatterAddress(host: "127.0.0.1", port: Self.serverPort)

        // Create controller with LoopbackTransport (POSIX socket — bidirectional on one port)
        let clientTransport = LoopbackTransport()
        try await clientTransport.bind(port: 0) // ephemeral port

        let controller = try MatterController(
            transport: clientTransport,
            discovery: StubDiscovery(),
            configuration: .init(
                fabricID: FabricID(rawValue: 1),
                rootKey: P256.Signing.PrivateKey()
            )
        )

        do {
            // Commission: PASE → ArmFailSafe → SetRegulatoryConfig → CSR → AddRootCert
            //           → AddNOC → ACL write → CommissioningComplete
            let device = try await controller.commission(
                address: serverAddress,
                setupCode: Self.passcode
            )

            #expect(device.nodeID.rawValue > 0, "Device should have a valid node ID")

            // Read OnOff attribute via automatic CASE session establishment
            let value = try await controller.readAttribute(
                nodeID: device.nodeID,
                endpointID: EndpointID(rawValue: 3),
                clusterID: .onOff,
                attributeID: OnOffCluster.Attribute.onOff
            )

            #expect(value.boolValue == false, "Default OnOff should be false")
        } catch {
            await server.stop()
            await clientTransport.close()
            try await Task.sleep(for: .milliseconds(500))
            throw error
        }

        await server.stop()
        await clientTransport.close()
        try await Task.sleep(for: .milliseconds(500))
    }

    // MARK: - Helpers

    /// Start a device server with a dimmable light on localhost.
    private func startServer() async throws -> (
        server: MatterDeviceServer,
        bridge: MatterBridge,
        config: MatterDeviceServer.Config
    ) {
        let bridge = MatterBridge()
        bridge.addDimmableLight(name: "Test Light")

        let transport = AppleUDPTransport()
        let discovery = StubDiscovery()

        let config = MatterDeviceServer.Config(
            discriminator: Self.discriminator,
            passcode: Self.passcode,
            port: Self.serverPort,
            salt: Self.salt,
            iterations: Self.iterations
        )

        let server = MatterDeviceServer(
            bridge: bridge,
            transport: transport,
            discovery: discovery,
            config: config
        )

        try await server.start()

        // Brief delay for receive loop to start
        try await Task.sleep(for: .milliseconds(100))

        return (server, bridge, config)
    }

    /// Perform a full PASE handshake as the client/prover over real UDP.
    private func performPASE(
        channel: TestUDPChannel,
        config: MatterDeviceServer.Config,
        serverAddress: MatterAddress
    ) async throws -> PASEResult {
        let initiatorSessionID: UInt16 = 200
        var counter: UInt32 = 1

        // Generate initiator random
        var initiatorRandom = Data(count: 32)
        initiatorRandom.withUnsafeMutableBytes {
            _ = SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
        }

        // Step 1: PBKDFParamRequest → PBKDFParamResponse
        let pbkdfRequest = PASEMessages.PBKDFParamRequest(
            initiatorRandom: initiatorRandom,
            initiatorSessionID: initiatorSessionID,
            passcodeID: 0,
            hasPBKDFParameters: false
        )

        let pbkdfReqMsg = buildUnsecuredMessage(
            payload: pbkdfRequest.tlvEncode(),
            opcode: .pbkdfParamRequest,
            exchangeID: 1,
            isInitiator: true,
            counter: counter
        )
        counter += 1

        try await channel.send(pbkdfReqMsg, to: serverAddress)
        let (respData, _) = try await channel.receiveOne()

        // Parse PBKDFParamResponse
        let (_, respHeaderConsumed) = try MessageHeader.decode(from: respData)
        let afterHeader = Data(respData.suffix(from: respHeaderConsumed))
        let (_, respExchConsumed) = try ExchangeHeader.decode(from: afterHeader)
        let respBody = Data(afterHeader.suffix(from: respExchConsumed))
        let pbkdfResponse = try PASEMessages.PBKDFParamResponse.fromTLV(respBody)

        #expect(pbkdfResponse.initiatorRandom == initiatorRandom)

        // Prepare crypto for Steps 2-3
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

        // Step 2: Pake1 → Pake2
        let (proverContext, pA) = try Spake2p.proverStep1(w0: w0)

        let pake1 = PASEMessages.Pake1Message(pA: pA)
        let pake1Msg = buildUnsecuredMessage(
            payload: pake1.tlvEncode(),
            opcode: .pasePake1,
            exchangeID: 1,
            isInitiator: true,
            counter: counter
        )
        counter += 1

        try await channel.send(pake1Msg, to: serverAddress)
        let (pake2Data, _) = try await channel.receiveOne()

        // Parse Pake2
        let (_, p2HeaderConsumed) = try MessageHeader.decode(from: pake2Data)
        let p2After = Data(pake2Data.suffix(from: p2HeaderConsumed))
        let (_, p2ExchConsumed) = try ExchangeHeader.decode(from: p2After)
        let p2Body = Data(p2After.suffix(from: p2ExchConsumed))
        let pake2 = try PASEMessages.Pake2Message.fromTLV(p2Body)

        // Step 3: Pake3 → StatusReport
        let (cA, ke) = try Spake2p.proverStep2(
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
            counter: counter
        )

        try await channel.send(pake3Msg, to: serverAddress)
        let (statusData, _) = try await channel.receiveOne()

        // Parse StatusReport
        let (_, sHeaderConsumed) = try MessageHeader.decode(from: statusData)
        let sAfter = Data(statusData.suffix(from: sHeaderConsumed))
        let (sExch, sExchConsumed) = try ExchangeHeader.decode(from: sAfter)
        #expect(sExch.protocolOpcode == SecureChannelOpcode.statusReport.rawValue)

        let sBody = Data(sAfter.suffix(from: sExchConsumed))
        let statusReport = try StatusReportMessage.decode(from: sBody)
        #expect(statusReport.generalStatus == .success)

        // Derive session keys — client is initiator
        let sessionKeys = KeyDerivation.deriveSessionKeys(sharedSecret: ke)

        let session = SecureSession(
            localSessionID: initiatorSessionID,
            peerSessionID: pbkdfResponse.responderSessionID,
            establishment: .pase,
            peerNodeID: NodeID(rawValue: 0),
            encryptKey: sessionKeys.i2rKey,
            decryptKey: sessionKeys.r2iKey,
            attestationKey: sessionKeys.attestationKey
        )

        return PASEResult(
            session: session,
            initiatorSessionID: initiatorSessionID,
            responderSessionID: pbkdfResponse.responderSessionID
        )
    }

    /// Build an unsecured message with session ID 0.
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

// MARK: - Supporting Types

struct PASEResult {
    let session: SecureSession
    let initiatorSessionID: UInt16
    let responderSessionID: UInt16
}

/// No-op discovery for integration tests that don't need mDNS.
/// Avoids the port conflict between AppleDiscovery's advertise listener
/// and AppleUDPTransport's listener.
final class StubDiscovery: MatterDiscovery, @unchecked Sendable {
    func advertise(service: MatterServiceRecord) async throws {}
    func browse(type: MatterServiceType) -> AsyncStream<MatterServiceRecord> {
        AsyncStream { $0.finish() }
    }
    func resolve(_ record: MatterServiceRecord) async throws -> MatterAddress {
        throw DiscoveryError.resolveFailed(record.name)
    }
    func stopAdvertising() async {}
}
#endif
