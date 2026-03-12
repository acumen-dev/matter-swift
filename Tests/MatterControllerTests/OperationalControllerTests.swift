// OperationalControllerTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
@testable import MatterController
@testable import MatterCrypto
@testable import MatterProtocol
import MatterTypes

@Suite("OperationalController")
struct OperationalControllerTests {

    /// Create a session pair with matching keys for encrypt/decrypt round-trips.
    private func makeSessionPair() -> (initiator: SecureSession, responder: SecureSession) {
        let keys = KeyDerivation.deriveSessionKeys(
            sharedSecret: Data(repeating: 0xAB, count: 32)
        )

        let initiator = SecureSession(
            localSessionID: 1,
            peerSessionID: 2,
            establishment: .case,
            peerNodeID: NodeID(rawValue: 200),
            initialSendCounter: 100,
            encryptKey: keys.encryptKey(isInitiator: true),
            decryptKey: keys.decryptKey(isInitiator: true)
        )

        let responder = SecureSession(
            localSessionID: 2,
            peerSessionID: 1,
            establishment: .case,
            peerNodeID: NodeID(rawValue: 100),
            initialSendCounter: 200,
            encryptKey: keys.encryptKey(isInitiator: false),
            decryptKey: keys.decryptKey(isInitiator: false)
        )

        return (initiator, responder)
    }

    @Test("Read attribute produces encrypted message")
    func readAttributeProducesMessage() throws {
        let (initiator, _) = makeSessionPair()
        let opCtrl = OperationalController()

        let message = try opCtrl.readAttribute(
            endpointID: .root,
            clusterID: ClusterID(rawValue: 0x0006),
            attributeID: AttributeID(rawValue: 0x0000),
            session: initiator,
            sourceNodeID: NodeID(rawValue: 100)
        )

        #expect(message.count > 0)
    }

    @Test("Read attribute encrypt/decrypt round-trip")
    func readAttributeRoundTrip() throws {
        let (initiator, responder) = makeSessionPair()
        let opCtrl = OperationalController()

        // Encrypt a read request
        let encrypted = try opCtrl.readAttribute(
            endpointID: .root,
            clusterID: ClusterID(rawValue: 0x0006),
            attributeID: AttributeID(rawValue: 0x0000),
            session: initiator,
            sourceNodeID: NodeID(rawValue: 100)
        )

        // Decrypt with the responder session
        let (msgHeader, exchHeader, payload) = try SecureMessageCodec.decode(
            data: encrypted,
            session: responder
        )

        #expect(msgHeader.sessionID == 2) // peer session ID
        #expect(exchHeader.protocolOpcode == InteractionModelOpcode.readRequest.rawValue)
        #expect(payload.count > 0)
    }

    @Test("Write attribute produces encrypted message")
    func writeAttributeProducesMessage() throws {
        let (initiator, _) = makeSessionPair()
        let opCtrl = OperationalController()

        let message = try opCtrl.writeAttribute(
            endpointID: .root,
            clusterID: ClusterID(rawValue: 0x0006),
            attributeID: AttributeID(rawValue: 0x0000),
            value: .bool(true),
            session: initiator,
            sourceNodeID: NodeID(rawValue: 100)
        )

        #expect(message.count > 0)
    }

    @Test("Write attribute encrypt/decrypt round-trip")
    func writeAttributeRoundTrip() throws {
        let (initiator, responder) = makeSessionPair()
        let opCtrl = OperationalController()

        let encrypted = try opCtrl.writeAttribute(
            endpointID: .root,
            clusterID: ClusterID(rawValue: 0x0006),
            attributeID: AttributeID(rawValue: 0x0000),
            value: .bool(true),
            session: initiator,
            sourceNodeID: NodeID(rawValue: 100)
        )

        let (_, exchHeader, payload) = try SecureMessageCodec.decode(
            data: encrypted,
            session: responder
        )

        #expect(exchHeader.protocolOpcode == InteractionModelOpcode.writeRequest.rawValue)
        #expect(payload.count > 0)
    }

    @Test("Invoke command produces encrypted message")
    func invokeCommandProducesMessage() throws {
        let (initiator, _) = makeSessionPair()
        let opCtrl = OperationalController()

        let message = try opCtrl.invokeCommand(
            endpointID: .root,
            clusterID: ClusterID(rawValue: 0x0006),
            commandID: CommandID(rawValue: 0x0002),
            commandFields: .structure([
                .init(tag: .contextSpecific(0), value: .bool(true))
            ]),
            session: initiator,
            sourceNodeID: NodeID(rawValue: 100)
        )

        #expect(message.count > 0)
    }

    @Test("Invoke command encrypt/decrypt round-trip")
    func invokeCommandRoundTrip() throws {
        let (initiator, responder) = makeSessionPair()
        let opCtrl = OperationalController()

        let encrypted = try opCtrl.invokeCommand(
            endpointID: .root,
            clusterID: ClusterID(rawValue: 0x0006),
            commandID: CommandID(rawValue: 0x0002),
            session: initiator,
            sourceNodeID: NodeID(rawValue: 100)
        )

        let (_, exchHeader, payload) = try SecureMessageCodec.decode(
            data: encrypted,
            session: responder
        )

        #expect(exchHeader.protocolOpcode == InteractionModelOpcode.invokeRequest.rawValue)
        #expect(payload.count > 0)
    }

    @Test("Invoke command without fields")
    func invokeCommandWithoutFields() throws {
        let (initiator, _) = makeSessionPair()
        let opCtrl = OperationalController()

        let message = try opCtrl.invokeCommand(
            endpointID: .root,
            clusterID: ClusterID(rawValue: 0x0030),
            commandID: CommandID(rawValue: 0x0004),
            session: initiator,
            sourceNodeID: NodeID(rawValue: 100)
        )

        #expect(message.count > 0)
    }

    @Test("Exchange header has initiator and reliable flags")
    func exchangeHeaderFlags() throws {
        let (initiator, responder) = makeSessionPair()
        let opCtrl = OperationalController()

        let encrypted = try opCtrl.readAttribute(
            endpointID: .root,
            clusterID: ClusterID(rawValue: 0x0006),
            attributeID: AttributeID(rawValue: 0x0000),
            session: initiator,
            sourceNodeID: NodeID(rawValue: 100)
        )

        let (_, exchHeader, _) = try SecureMessageCodec.decode(
            data: encrypted,
            session: responder
        )

        #expect(exchHeader.flags.initiator == true)
        #expect(exchHeader.flags.reliableDelivery == true)
    }

    @Test("Exchange header has IM protocol ID")
    func exchangeHeaderProtocol() throws {
        let (initiator, responder) = makeSessionPair()
        let opCtrl = OperationalController()

        let encrypted = try opCtrl.writeAttribute(
            endpointID: .root,
            clusterID: ClusterID(rawValue: 0x0006),
            attributeID: AttributeID(rawValue: 0x0000),
            value: .unsignedInt(100),
            session: initiator,
            sourceNodeID: NodeID(rawValue: 100)
        )

        let (_, exchHeader, _) = try SecureMessageCodec.decode(
            data: encrypted,
            session: responder
        )

        #expect(exchHeader.protocolID == MatterProtocolID.interactionModel.rawValue)
    }

    @Test("Message counter increments across operations")
    func messageCounterIncrements() throws {
        let (initiator, responder) = makeSessionPair()
        let opCtrl = OperationalController()

        let enc1 = try opCtrl.readAttribute(
            endpointID: .root,
            clusterID: ClusterID(rawValue: 0x0006),
            attributeID: AttributeID(rawValue: 0x0000),
            session: initiator,
            sourceNodeID: NodeID(rawValue: 100)
        )

        let enc2 = try opCtrl.readAttribute(
            endpointID: .root,
            clusterID: ClusterID(rawValue: 0x0006),
            attributeID: AttributeID(rawValue: 0x0000),
            session: initiator,
            sourceNodeID: NodeID(rawValue: 100)
        )

        let (hdr1, _, _) = try SecureMessageCodec.decode(data: enc1, session: responder)
        let (hdr2, _, _) = try SecureMessageCodec.decode(data: enc2, session: responder)

        #expect(hdr2.messageCounter > hdr1.messageCounter)
    }
}
