// ScriptedPeer.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import MatterTypes
import MatterProtocol

/// One decoded datagram, as a scripted peer sees it.
public struct PeerFrame: Sendable, Equatable {
    public let messageHeader: MessageHeader
    public let exchangeHeader: ExchangeHeader
    public let payload: Data

    public init(messageHeader: MessageHeader, exchangeHeader: ExchangeHeader, payload: Data) {
        self.messageHeader = messageHeader
        self.exchangeHeader = exchangeHeader
        self.payload = payload
    }

    public var counter: UInt32 { messageHeader.messageCounter }

    public var isStandaloneAck: Bool {
        exchangeHeader.protocolID == MatterProtocolID.secureChannel.rawValue
            && exchangeHeader.protocolOpcode == SecureChannelOpcode.standaloneAck.rawValue
    }
}

/// Frame helpers for a test acting as the peer of a controller: decode what
/// the controller sent, build replies, acks and unsolicited messages.
public enum ScriptedPeer {

    // MARK: Decode

    public static func decodeUnsecured(_ data: Data) throws -> PeerFrame {
        let message = try MatterMessage.decodeUnsecured(from: data)
        guard let exchangeHeader = message.exchangeHeader else {
            throw ScriptedPeerError.missingExchangeHeader
        }
        return PeerFrame(messageHeader: message.messageHeader, exchangeHeader: exchangeHeader, payload: message.payload)
    }

    /// Decrypt with the peer's side of the session.
    public static func decodeSecured(_ data: Data, session: SecureSession) throws -> PeerFrame {
        let (messageHeader, exchangeHeader, payload) = try SecureMessageCodec.decode(data: data, session: session)
        return PeerFrame(messageHeader: messageHeader, exchangeHeader: exchangeHeader, payload: payload)
    }

    // MARK: Unsecured

    public static func unsecured(
        exchangeID: UInt16,
        initiator: Bool,
        protocolID: MatterProtocolID,
        opcode: UInt8,
        payload: Data = Data(),
        counter: UInt32,
        ack: UInt32? = nil,
        reliable: Bool = true
    ) -> Data {
        MatterMessage.encodeUnsecured(
            messageHeader: MessageHeader(sessionID: 0, messageCounter: counter),
            exchangeHeader: ExchangeHeader(
                flags: ExchangeFlags(initiator: initiator, reliableDelivery: reliable),
                protocolOpcode: opcode,
                exchangeID: exchangeID,
                protocolID: protocolID.rawValue,
                acknowledgedMessageCounter: ack
            ),
            payload: payload
        )
    }

    /// A message on `frame`'s exchange from the other side, piggybacking an
    /// ack of `frame` if it asked for one.
    public static func unsecuredReply(
        to frame: PeerFrame,
        protocolID: MatterProtocolID,
        opcode: UInt8,
        payload: Data = Data(),
        counter: UInt32,
        reliable: Bool = true
    ) -> Data {
        unsecured(
            exchangeID: frame.exchangeHeader.exchangeID,
            initiator: !frame.exchangeHeader.flags.initiator,
            protocolID: protocolID,
            opcode: opcode,
            payload: payload,
            counter: counter,
            ack: frame.exchangeHeader.flags.reliableDelivery ? frame.counter : nil,
            reliable: reliable
        )
    }

    /// A standalone ack of `frame`.
    public static func unsecuredAck(for frame: PeerFrame, counter: UInt32) -> Data {
        unsecured(
            exchangeID: frame.exchangeHeader.exchangeID,
            initiator: !frame.exchangeHeader.flags.initiator,
            protocolID: .secureChannel,
            opcode: SecureChannelOpcode.standaloneAck.rawValue,
            counter: counter,
            ack: frame.counter,
            reliable: false
        )
    }

    // MARK: Secured

    /// Encrypt with `session` (its next send counter).
    public static func secured(
        session: SecureSession,
        exchangeID: UInt16,
        initiator: Bool,
        protocolID: MatterProtocolID,
        opcode: UInt8,
        payload: Data = Data(),
        ack: UInt32? = nil,
        reliable: Bool = true
    ) throws -> Data {
        try SecureMessageCodec.encode(
            exchangeHeader: ExchangeHeader(
                flags: ExchangeFlags(initiator: initiator, reliableDelivery: reliable),
                protocolOpcode: opcode,
                exchangeID: exchangeID,
                protocolID: protocolID.rawValue,
                acknowledgedMessageCounter: ack
            ),
            payload: payload,
            session: session,
            sourceNodeID: NodeID(rawValue: 0)
        )
    }

    public static func securedReply(
        to frame: PeerFrame,
        session: SecureSession,
        protocolID: MatterProtocolID,
        opcode: UInt8,
        payload: Data = Data(),
        reliable: Bool = true
    ) throws -> Data {
        try secured(
            session: session,
            exchangeID: frame.exchangeHeader.exchangeID,
            initiator: !frame.exchangeHeader.flags.initiator,
            protocolID: protocolID,
            opcode: opcode,
            payload: payload,
            ack: frame.exchangeHeader.flags.reliableDelivery ? frame.counter : nil,
            reliable: reliable
        )
    }

    /// Two ends of one PASE-style session with fresh random keys: what one
    /// encrypts the other decrypts. Each side's header carries the other's
    /// local session ID.
    public static func mirroredSessions(
        controllerSessionID: UInt16,
        peerSessionID: UInt16
    ) -> (controller: SecureSession, peer: SecureSession) {
        let controllerToPeer = SymmetricKey(size: .bits128)
        let peerToController = SymmetricKey(size: .bits128)
        let controller = SecureSession(
            localSessionID: controllerSessionID,
            peerSessionID: peerSessionID,
            establishment: .pase,
            peerNodeID: NodeID(rawValue: 0),
            encryptKey: controllerToPeer,
            decryptKey: peerToController
        )
        let peer = SecureSession(
            localSessionID: peerSessionID,
            peerSessionID: controllerSessionID,
            establishment: .pase,
            peerNodeID: NodeID(rawValue: 0),
            encryptKey: peerToController,
            decryptKey: controllerToPeer
        )
        return (controller, peer)
    }
}

public enum ScriptedPeerError: Error, Sendable {
    case missingExchangeHeader
}
