// SecureMessageCodecTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
@testable import MatterProtocol
import MatterTypes
import MatterCrypto

@Suite("Secure Message Codec")
struct SecureMessageCodecTests {

    /// Create a pair of sessions with matching keys (initiator and responder).
    private func makeSessionPair() -> (initiator: SecureSession, responder: SecureSession) {
        // Derive keys from a test shared secret
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

    @Test("Encrypt/decrypt round-trip")
    func encryptDecryptRoundTrip() throws {
        let (initiator, responder) = makeSessionPair()

        let exchangeHeader = ExchangeHeader(
            flags: ExchangeFlags(initiator: true),
            protocolOpcode: 0x01,
            exchangeID: 42,
            protocolID: MatterProtocolID.interactionModel.rawValue
        )
        let payload = Data("Hello Matter".utf8)

        // Initiator encrypts
        let encoded = try SecureMessageCodec.encode(
            exchangeHeader: exchangeHeader,
            payload: payload,
            session: initiator,
            sourceNodeID: NodeID(rawValue: 100)
        )

        // Responder decrypts
        let (msgHeader, decodedExch, decodedPayload) = try SecureMessageCodec.decode(
            data: encoded,
            session: responder
        )

        #expect(msgHeader.sessionID == 2) // peer session ID
        #expect(msgHeader.messageCounter == 101) // initial 100 + increment
        #expect(decodedExch.exchangeID == 42)
        #expect(decodedExch.protocolID == MatterProtocolID.interactionModel.rawValue)
        #expect(decodedPayload == payload)
    }

    @Test("Wrong key fails decryption")
    func wrongKeyFails() throws {
        let (initiator, _) = makeSessionPair()

        // Different keys for the "wrong" responder
        let wrongKeys = KeyDerivation.deriveSessionKeys(
            sharedSecret: Data(repeating: 0xCD, count: 32)
        )
        let wrongSession = SecureSession(
            localSessionID: 2,
            peerSessionID: 1,
            establishment: .case,
            peerNodeID: NodeID(rawValue: 100),
            decryptKey: wrongKeys.decryptKey(isInitiator: false)
        )

        let exchangeHeader = ExchangeHeader(
            flags: ExchangeFlags(initiator: true),
            protocolOpcode: 0x01,
            exchangeID: 1,
            protocolID: MatterProtocolID.secureChannel.rawValue
        )

        let encoded = try SecureMessageCodec.encode(
            exchangeHeader: exchangeHeader,
            payload: Data("test".utf8),
            session: initiator,
            sourceNodeID: NodeID(rawValue: 100)
        )

        #expect(throws: Error.self) {
            _ = try SecureMessageCodec.decode(data: encoded, session: wrongSession)
        }
    }

    @Test("Tampered ciphertext fails decryption")
    func tamperedCiphertextFails() throws {
        let (initiator, responder) = makeSessionPair()

        let exchangeHeader = ExchangeHeader(
            flags: ExchangeFlags(initiator: true),
            protocolOpcode: 0x01,
            exchangeID: 1,
            protocolID: MatterProtocolID.secureChannel.rawValue
        )

        var encoded = try SecureMessageCodec.encode(
            exchangeHeader: exchangeHeader,
            payload: Data("test".utf8),
            session: initiator,
            sourceNodeID: NodeID(rawValue: 100)
        )

        // Flip a byte in the ciphertext portion
        encoded[encoded.count - 5] ^= 0xFF

        #expect(throws: Error.self) {
            _ = try SecureMessageCodec.decode(data: encoded, session: responder)
        }
    }

    @Test("Missing encryption keys throws")
    func missingKeysFails() throws {
        let noKeySession = SecureSession(
            localSessionID: 1,
            peerSessionID: 2,
            establishment: .pase,
            peerNodeID: NodeID(rawValue: 1)
        )

        let exchangeHeader = ExchangeHeader(
            flags: ExchangeFlags(initiator: true),
            protocolOpcode: 0x01,
            exchangeID: 1,
            protocolID: MatterProtocolID.secureChannel.rawValue
        )

        #expect(throws: SecureCodecError.missingEncryptionKeys) {
            _ = try SecureMessageCodec.encode(
                exchangeHeader: exchangeHeader,
                payload: Data(),
                session: noKeySession,
                sourceNodeID: NodeID(rawValue: 1)
            )
        }
    }
}
