// DeviceServerPathTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Logging
import MatterTypes
import MatterTransport
import MatterProtocol
import MatterCrypto
import MatterTestSupport
@testable import MatterDevice

/// A device server on a dual-homed fake wrapping `link.b`: `en0` (`fd48::a`) and `en1`
/// (`fd48::b`) both reach the commissioner (`link.a`, 10.0.0.1); the route table picks
/// `routeTable`. The commissioner speaks from `link.a`.
private struct ServerPathRig {
    static let passcode: UInt32 = 20202021
    static let salt = Data(repeating: 0xAB, count: 32)
    static let iterations = 1000

    let logs = LogCapture()
    let link = FaultInjectingLink(seed: 7)
    let endpoint: MultiInterfaceEndpoint
    let server: MatterDeviceServer
    let light: BridgedEndpoint

    init(policy: InterfacePolicy = .automatic, routeTable: String? = "en0") {
        let peerHost = link.a.address.host
        endpoint = MultiInterfaceEndpoint(
            wrapping: link.b,
            interfaces: [
                .init(snapshot: InterfaceSnapshot(name: "en0", index: 7, isUp: true, addresses: ["fd48::a"]), reachable: [peerHost]),
                .init(snapshot: InterfaceSnapshot(name: "en1", index: 15, isUp: true, addresses: ["fd48::b"]), reachable: [peerHost]),
            ],
            routeTable: routeTable,
            logger: logs.logger(label: "test.transport")
        )
        let bridge = MatterBridge()
        light = bridge.addDimmableLight(name: "Path Light", uniqueID: "path-light")
        server = MatterDeviceServer(
            bridge: bridge,
            transport: endpoint,
            discovery: MockServerDiscovery(),
            config: .init(
                discriminator: 3840,
                passcode: Self.passcode,
                port: 5540,
                salt: Self.salt,
                iterations: Self.iterations,
                interfaces: policy
            ),
            logger: logs.logger(label: "test.server")
        )
    }

    /// Send `data` from the commissioner, arriving on `interface`, and wait for the server's
    /// next reply. Returns the index of that reply in ``MultiInterfaceEndpoint/sends``.
    @discardableResult
    func exchange(_ data: Data, arrivingOn interface: String) async throws -> Int {
        endpoint.setArrival(interface)
        let before = endpoint.sends.count
        try await link.a.send(data, to: link.b.address)
        try await pollUntil { endpoint.sends.count > before }
        return before
    }

    var sentInterfaces: [String] { endpoint.sends.map(\.path.interfaceName) }

    func logged(_ level: Logger.Level, containing text: String) -> Bool {
        logs.entries.contains { $0.level == level && $0.message.contains(text) }
    }

    /// Run PASE as the commissioner, each message arriving on `interface`, with message
    /// counters `firstCounter`, +1, +2. `afterPBKDF` runs once the PBKDFParamResponse is in.
    func performPASE(
        arrivingOn interface: String,
        firstCounter: UInt32 = 1,
        afterPBKDF: () async throws -> Void = {}
    ) async throws -> (session: SecureSession, pake3: Data) {
        let initiatorSessionID: UInt16 = 100
        let request = DuplicateHandlingTests.pbkdfRequest(initiatorSessionID: initiatorSessionID)
        let requestTLV = request.tlvEncode()

        let pbkdfIndex = try await exchange(
            DuplicateHandlingTests.unsecuredMessage(payload: requestTLV, opcode: .pbkdfParamRequest, counter: firstCounter),
            arrivingOn: interface
        )
        try await afterPBKDF()
        let responseTLV = try DuplicateHandlingTests.unsecuredBody(endpoint.sends[pbkdfIndex].data)
        let pbkdfResponse = try PASEMessages.PBKDFParamResponse.fromTLV(responseTLV)

        let hashContext = Spake2p.computeHashContext(pbkdfParamRequest: requestTLV, pbkdfParamResponse: responseTLV)
        let (w0, w1) = Spake2p.deriveW0W1(passcode: Self.passcode, salt: Self.salt, iterations: Self.iterations)
        let (proverContext, pA) = try Spake2p.proverStep1(w0: w0)

        let pake2Index = try await exchange(
            DuplicateHandlingTests.unsecuredMessage(payload: PASEMessages.Pake1Message(pA: pA).tlvEncode(), opcode: .pasePake1, counter: firstCounter + 1),
            arrivingOn: interface
        )
        let pake2 = try PASEMessages.Pake2Message.fromTLV(DuplicateHandlingTests.unsecuredBody(endpoint.sends[pake2Index].data))
        let (cA, ke) = try Spake2p.proverStep2(context: proverContext, pB: pake2.pB, cB: pake2.cB, hashContext: hashContext, w1: w1)

        let pake3 = DuplicateHandlingTests.unsecuredMessage(payload: PASEMessages.Pake3Message(cA: cA).tlvEncode(), opcode: .pasePake3, counter: firstCounter + 2)
        let statusIndex = try await exchange(pake3, arrivingOn: interface)
        let status = try StatusReportMessage.decode(from: DuplicateHandlingTests.unsecuredBody(endpoint.sends[statusIndex].data))
        try #require(status.generalStatus == .success)

        let keys = KeyDerivation.deriveSessionKeys(sharedSecret: ke)
        let session = SecureSession(
            localSessionID: initiatorSessionID,
            peerSessionID: pbkdfResponse.responderSessionID,
            establishment: .pase,
            peerNodeID: NodeID(rawValue: 0),
            encryptKey: keys.i2rKey,
            decryptKey: keys.r2iKey
        )
        return (session, pake3)
    }

    /// Send a Toggle on `session` arriving on `interface`; wait for its InvokeResponse and
    /// return the interface that response left by.
    func toggle(session: SecureSession, exchangeID: UInt16, arrivingOn interface: String) async throws -> String {
        let invoke = try DuplicateHandlingTests.toggleRequest(endpointID: light.endpointID, session: session, exchangeID: exchangeID)
        endpoint.setArrival(interface)
        let before = endpoint.sends.count
        try await link.a.send(invoke.message, to: link.b.address)
        var response: String?
        try await pollUntil {
            for send in endpoint.sends.dropFirst(before) {
                guard let frame = try? DuplicateHandlingTests.decodeFrames([(send.data, send.to)], session: session).first else { continue }
                if frame.exchange.exchangeID == exchangeID,
                   frame.exchange.protocolOpcode == InteractionModelOpcode.invokeResponse.rawValue {
                    response = send.path.interfaceName
                    return true
                }
            }
            return false
        }
        return try #require(response)
    }
}

/// Serialized: every test but two runs a real PASE handshake (SPAKE2+ on `BigUInt`, about
/// 6 CPU-seconds each in a debug build). Run in parallel they occupy the cooperative pool's
/// threads with synchronous arithmetic and starve every other suite's tasks; on a 2-CPU Linux
/// gate that pushed unrelated suites past their 60 s time limits.
@Suite("Device server interface paths", .serialized, .timeLimit(.minutes(5)))
struct DeviceServerPathTests {

    @Test("Config.interfaces reaches the transport")
    func policyReachesTransport() async throws {
        let policy = InterfacePolicy(preferred: ["en1"], excluded: ["utun3"])
        let rig = ServerPathRig(policy: policy)
        try await rig.server.start()
        #expect(rig.endpoint.policy == policy)
        await rig.server.stop()
    }

    @Test("A reply leaves by the interface the request arrived on")
    func replyLeavesByArrivalInterface() async throws {
        let rig = ServerPathRig(routeTable: "en0")
        try await rig.server.start()
        let index = try await rig.exchange(
            DuplicateHandlingTests.unsecuredMessage(
                payload: DuplicateHandlingTests.pbkdfRequest(initiatorSessionID: 100).tlvEncode(),
                opcode: .pbkdfParamRequest, counter: 1
            ),
            arrivingOn: "en1"
        )
        #expect(rig.endpoint.sends[index].path.interfaceName == "en1", "the route table says en0; the request came in on en1")
        await rig.server.stop()
    }

    @Test("Every PASE reply and the session's replies keep the handshake's arrival path")
    func sessionInheritsHandshakePath() async throws {
        let rig = ServerPathRig(routeTable: "en0")
        try await rig.server.start()
        let pase = try await rig.performPASE(arrivingOn: "en1")
        #expect(rig.sentInterfaces == ["en1", "en1", "en1"])
        // en1 stays the pin even with no arrival-path change: the route table still says en0.
        #expect(try await rig.toggle(session: pase.session, exchangeID: 0x0101, arrivingOn: "en1") == "en1")
        #expect(rig.sentInterfaces.allSatisfy { $0 == "en1" })
        await rig.server.stop()
    }

    @Test("An authenticated message on another interface re-pins the peer")
    func authenticatedArrivalRepins() async throws {
        let rig = ServerPathRig(routeTable: "en0")
        try await rig.server.start()
        let pase = try await rig.performPASE(arrivingOn: "en0")
        #expect(rig.sentInterfaces == ["en0", "en0", "en0"])

        #expect(try await rig.toggle(session: pase.session, exchangeID: 0x0201, arrivingOn: "en1") == "en1")
        #expect(rig.logged(.info, containing: "re-pinned en0/fd48::a → en1/fd48::b"))
        await rig.server.stop()
    }

    @Test("Unauthenticated traffic on another interface does not move an existing pin")
    func unauthenticatedArrivalKeepsPin() async throws {
        let rig = ServerPathRig(routeTable: "en0")
        try await rig.server.start()
        let pase = try await rig.performPASE(arrivingOn: "en0")
        // Were the pin dropped, a fresh selection would now pick en1.
        rig.endpoint.setRouteTable("en1")

        // A replayed Pake3 is answered (with the stored StatusReport) but proves nothing.
        let index = try await rig.exchange(pase.pake3, arrivingOn: "en1")
        #expect(rig.endpoint.sends[index].path.interfaceName == "en0")
        #expect(!rig.logged(.info, containing: "re-pinned"))
        await rig.server.stop()
    }

    @Test("A pinned path that lost its route is dropped and re-selected")
    func lostPathReselects() async throws {
        let rig = ServerPathRig(routeTable: "en0")
        try await rig.server.start()
        let pase = try await rig.performPASE(arrivingOn: "en1")
        rig.endpoint.setReachable("en1", [])

        // The request still arrives on en1 (the fake's arrival is independent of reachability)
        // but is the pin, so no re-pin happens; the reply's send by en1 fails and re-selects.
        #expect(try await rig.toggle(session: pase.session, exchangeID: 0x0301, arrivingOn: "en1") == "en0")
        #expect(rig.logged(.info, containing: "lost its route; re-selecting"))
        await rig.server.stop()
    }

    @Test("With no allowed route the reply is dropped with a warning naming the peer")
    func noAllowedRouteWarns() async throws {
        let rig = ServerPathRig(routeTable: "en0")
        try await rig.server.start()
        let pase = try await rig.performPASE(arrivingOn: "en0")
        rig.endpoint.setReachable("en0", [])
        rig.endpoint.setReachable("en1", [])
        let before = rig.endpoint.sends.count

        let invoke = try DuplicateHandlingTests.toggleRequest(endpointID: rig.light.endpointID, session: pase.session, exchangeID: 0x0401)
        try await rig.link.a.send(invoke.message, to: rig.link.b.address)
        try await pollUntil {
            rig.logs.entries.contains {
                $0.level == .warning && $0.message.contains("No allowed interface has a route to") && $0.message.contains("10.0.0.1")
            }
        }
        #expect(rig.endpoint.sends.count == before)
        await rig.server.stop()
    }

    @Test("A new handshake is answered by its own arrival path; the peer pin moves only when its session is established")
    func newHandshakeUsesItsOwnPath() async throws {
        let rig = ServerPathRig(routeTable: "en0")
        try await rig.server.start()
        let peer = rig.link.a.address.canonicalised
        _ = try await rig.performPASE(arrivingOn: "en0")
        #expect(await rig.server.peerPaths[peer]?.interfaceName == "en0")
        let before = rig.endpoint.sends.count

        let second = try await rig.performPASE(arrivingOn: "en1", firstCounter: 11) {
            #expect(rig.endpoint.sends.last?.path.interfaceName == "en1", "the PBKDFParamResponse leaves by the handshake's arrival path")
            #expect(await rig.server.peerPaths[peer]?.interfaceName == "en0", "unauthenticated traffic does not move the peer pin")
        }
        #expect(rig.sentInterfaces.dropFirst(before).allSatisfy { $0 == "en1" })
        #expect(await rig.server.peerPaths[peer]?.interfaceName == "en1", "the new session inherits its handshake's path")
        #expect(rig.logged(.info, containing: "re-pinned en0/fd48::a → en1/fd48::b (session"))

        // A secured reply on the new session (arriving on en1, already the pin) leaves by en1.
        #expect(try await rig.toggle(session: second.session, exchangeID: 0x0501, arrivingOn: "en1") == "en1")
        await rig.server.stop()
    }

    @Test("Unsecured traffic outside a handshake creates no peer pin")
    func strayUnsecuredCreatesNoPin() async throws {
        let rig = ServerPathRig(routeTable: "en0")
        try await rig.server.start()
        let peer = rig.link.a.address.canonicalised

        // An unknown opcode, then a handshake's first message: the server handles
        // datagrams in order, so once the reply is out the stray has been processed.
        let stray = MatterMessage.encodeUnsecured(
            messageHeader: MessageHeader(sessionID: 0, messageCounter: 9),
            exchangeHeader: ExchangeHeader(
                flags: ExchangeFlags(initiator: true, reliableDelivery: false),
                protocolOpcode: 0x7E,
                exchangeID: 9,
                protocolID: MatterProtocolID.secureChannel.rawValue
            ),
            payload: Data()
        )
        rig.endpoint.setArrival("en1")
        try await rig.link.a.send(stray, to: rig.link.b.address)
        _ = try await rig.performPASE(arrivingOn: "en1") {
            #expect(await rig.server.peerPaths.isEmpty, "neither the stray nor the handshake pins the peer")
        }
        #expect(await rig.server.peerPaths[peer]?.interfaceName == "en1")
        await rig.server.stop()
        #expect(await rig.server.peerPaths.isEmpty)
    }

    @Test("A pin outlives its peer's silence only while a session uses the address")
    func idlePinsArePruned() async throws {
        let rig = ServerPathRig(routeTable: "en0")
        try await rig.server.start()
        let sessionPeer = rig.link.a.address.canonicalised
        let pase = try await rig.performPASE(arrivingOn: "en1")

        // An authenticated message from another source address (the peer's port changed)
        // pins that address, which no session uses.
        let moved = MatterAddress(host: rig.link.a.address.host, port: 6000)
        let invoke = try DuplicateHandlingTests.toggleRequest(endpointID: rig.light.endpointID, session: pase.session, exchangeID: 0x0601)
        try await rig.link.a.send(invoke.message, to: rig.link.b.address, from: moved)
        try await pollUntil { await rig.server.peerPaths[moved.canonicalised] != nil }

        await rig.server.prunePeerPaths(now: .now + .seconds(60))
        #expect(await rig.server.peerPaths[moved.canonicalised] != nil, "still within the idle limit")
        await rig.server.prunePeerPaths(now: .now + MatterDeviceServer.peerPathIdleLimit + .seconds(1))
        #expect(await rig.server.peerPaths[moved.canonicalised] == nil)
        #expect(await rig.server.peerPaths[sessionPeer]?.interfaceName == "en1", "a session's address keeps its pin")
        await rig.server.stop()
    }
}
