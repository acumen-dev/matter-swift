// CASEMessageTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
@testable import MatterCrypto
import MatterTypes

@Suite("CASE Messages")
struct CASEMessageTests {

    // MARK: - Sigma1 Round-Trip

    @Test("Sigma1 TLV round-trip")
    func sigma1RoundTrip() throws {
        let random = Data(repeating: 0xAA, count: 32)
        let destID = Data(repeating: 0xBB, count: 32)
        let ephKey = P256.KeyAgreement.PrivateKey()
        let ephPubKey = Data(ephKey.publicKey.x963Representation)

        let msg = Sigma1Message(
            initiatorRandom: random,
            initiatorSessionID: 0x1234,
            destinationID: destID,
            initiatorEphPubKey: ephPubKey
        )

        let encoded = msg.tlvEncode()
        let decoded = try Sigma1Message.fromTLV(encoded)

        #expect(decoded.initiatorRandom == random)
        #expect(decoded.initiatorSessionID == 0x1234)
        #expect(decoded.destinationID == destID)
        #expect(decoded.initiatorEphPubKey == ephPubKey)
        #expect(decoded.resumptionID == nil)
        #expect(decoded.initiatorResumeMIC == nil)
        #expect(decoded.initiatorSessionParams == nil)
    }

    @Test("Sigma1 with session parameters round-trip")
    func sigma1WithParams() throws {
        let msg = Sigma1Message(
            initiatorRandom: Data(repeating: 0x01, count: 32),
            initiatorSessionID: 42,
            destinationID: Data(repeating: 0x02, count: 32),
            initiatorEphPubKey: Data(P256.KeyAgreement.PrivateKey().publicKey.x963Representation),
            initiatorSessionParams: SessionParameters(
                sessionIdleInterval: 500,
                sessionActiveInterval: 300,
                sessionActiveThreshold: 4000
            )
        )

        let decoded = try Sigma1Message.fromTLV(msg.tlvEncode())
        #expect(decoded.initiatorSessionParams?.sessionIdleInterval == 500)
        #expect(decoded.initiatorSessionParams?.sessionActiveInterval == 300)
        #expect(decoded.initiatorSessionParams?.sessionActiveThreshold == 4000)
    }

    @Test("Sigma1 with resumption round-trip")
    func sigma1WithResumption() throws {
        let resumptionID = Data(repeating: 0xCC, count: 16)
        let resumeMIC = Data(repeating: 0xDD, count: 16)

        let msg = Sigma1Message(
            initiatorRandom: Data(repeating: 0x01, count: 32),
            initiatorSessionID: 1,
            destinationID: Data(repeating: 0x02, count: 32),
            initiatorEphPubKey: Data(P256.KeyAgreement.PrivateKey().publicKey.x963Representation),
            resumptionID: resumptionID,
            initiatorResumeMIC: resumeMIC
        )

        let decoded = try Sigma1Message.fromTLV(msg.tlvEncode())
        #expect(decoded.resumptionID == resumptionID)
        #expect(decoded.initiatorResumeMIC == resumeMIC)
    }

    // MARK: - Sigma2 Round-Trip

    @Test("Sigma2 TLV round-trip")
    func sigma2RoundTrip() throws {
        let random = Data(repeating: 0x11, count: 32)
        let ephKey = P256.KeyAgreement.PrivateKey()
        let encrypted = Data(repeating: 0xEE, count: 100)

        let msg = Sigma2Message(
            responderRandom: random,
            responderSessionID: 0x5678,
            responderEphPubKey: Data(ephKey.publicKey.x963Representation),
            encrypted2: encrypted
        )

        let decoded = try Sigma2Message.fromTLV(msg.tlvEncode())

        #expect(decoded.responderRandom == random)
        #expect(decoded.responderSessionID == 0x5678)
        #expect(decoded.responderEphPubKey == Data(ephKey.publicKey.x963Representation))
        #expect(decoded.encrypted2 == encrypted)
        #expect(decoded.responderSessionParams == nil)
    }

    // MARK: - Sigma3 Round-Trip

    @Test("Sigma3 TLV round-trip")
    func sigma3RoundTrip() throws {
        let encrypted = Data(repeating: 0xFF, count: 200)

        let msg = Sigma3Message(encrypted3: encrypted)
        let decoded = try Sigma3Message.fromTLV(msg.tlvEncode())

        #expect(decoded.encrypted3 == encrypted)
    }

    // MARK: - TBS Data

    @Test("TBSData2 encodes correctly")
    func tbsData2Encode() throws {
        let tbs = TBSData2(
            responderNOC: Data(repeating: 0x01, count: 50),
            responderEphPubKey: Data(repeating: 0x02, count: 65),
            initiatorEphPubKey: Data(repeating: 0x03, count: 65)
        )

        let encoded = tbs.tlvEncode()
        #expect(encoded.count > 0)

        // Should decode as a structure with 3 fields (no ICAC)
        let (_, element) = try TLVDecoder.decode(encoded)
        if case .structure(let fields) = element {
            #expect(fields.count == 3)
        } else {
            Issue.record("Expected structure")
        }
    }

    @Test("TBSData3 encodes with optional ICAC")
    func tbsData3WithICAC() throws {
        let tbs = TBSData3(
            initiatorNOC: Data(repeating: 0x01, count: 50),
            initiatorICAC: Data(repeating: 0x04, count: 40),
            initiatorEphPubKey: Data(repeating: 0x02, count: 65),
            responderEphPubKey: Data(repeating: 0x03, count: 65)
        )

        let encoded = tbs.tlvEncode()
        let (_, element) = try TLVDecoder.decode(encoded)
        if case .structure(let fields) = element {
            #expect(fields.count == 4) // includes ICAC
        } else {
            Issue.record("Expected structure")
        }
    }

    // MARK: - Decrypted Payloads

    @Test("Sigma2Decrypted round-trip")
    func sigma2DecryptedRoundTrip() throws {
        let payload = Sigma2Decrypted(
            responderNOC: Data(repeating: 0x01, count: 100),
            responderICAC: Data(repeating: 0x02, count: 80),
            signature: Data(repeating: 0x03, count: 64),
            resumptionID: Data(repeating: 0x04, count: 16)
        )

        let decoded = try Sigma2Decrypted.fromTLV(payload.tlvEncode())

        #expect(decoded.responderNOC == payload.responderNOC)
        #expect(decoded.responderICAC == payload.responderICAC)
        #expect(decoded.signature == payload.signature)
        #expect(decoded.resumptionID == payload.resumptionID)
    }

    @Test("Sigma3Decrypted round-trip without ICAC")
    func sigma3DecryptedRoundTrip() throws {
        let payload = Sigma3Decrypted(
            initiatorNOC: Data(repeating: 0x05, count: 100),
            signature: Data(repeating: 0x06, count: 64)
        )

        let decoded = try Sigma3Decrypted.fromTLV(payload.tlvEncode())

        #expect(decoded.initiatorNOC == payload.initiatorNOC)
        #expect(decoded.initiatorICAC == nil)
        #expect(decoded.signature == payload.signature)
    }
}

// MARK: - CASE Key Derivation Tests

@Suite("CASE Key Derivation")
struct CASEKeyDerivationTests {

    @Test("Destination ID is deterministic")
    func destinationIDDeterministic() {
        let random = Data(repeating: 0x42, count: 32)
        let rootPubKey = Data(P256.Signing.PrivateKey().publicKey.x963Representation)
        let fabricID = FabricID(rawValue: 1)
        let nodeID = NodeID(rawValue: 1)
        let ipk = Data(repeating: 0, count: 16)

        let id1 = CASEKeyDerivation.computeDestinationID(
            initiatorRandom: random, rootPublicKey: rootPubKey,
            fabricID: fabricID, nodeID: nodeID, ipk: ipk
        )
        let id2 = CASEKeyDerivation.computeDestinationID(
            initiatorRandom: random, rootPublicKey: rootPubKey,
            fabricID: fabricID, nodeID: nodeID, ipk: ipk
        )

        #expect(id1 == id2)
        #expect(id1.count == 32)
    }

    @Test("Destination ID changes with different random")
    func destinationIDDiffersWithRandom() {
        let rootPubKey = Data(P256.Signing.PrivateKey().publicKey.x963Representation)
        let fabricID = FabricID(rawValue: 1)
        let nodeID = NodeID(rawValue: 1)
        let ipk = Data(repeating: 0, count: 16)

        let id1 = CASEKeyDerivation.computeDestinationID(
            initiatorRandom: Data(repeating: 0x01, count: 32),
            rootPublicKey: rootPubKey, fabricID: fabricID, nodeID: nodeID, ipk: ipk
        )
        let id2 = CASEKeyDerivation.computeDestinationID(
            initiatorRandom: Data(repeating: 0x02, count: 32),
            rootPublicKey: rootPubKey, fabricID: fabricID, nodeID: nodeID, ipk: ipk
        )

        #expect(id1 != id2)
    }

    @Test("Sigma keys are 16 bytes each")
    func sigmaKeySizes() {
        let sharedSecret = Data(repeating: 0xAB, count: 32)
        let ipk = Data(repeating: 0, count: 16)
        let random = Data(repeating: 0x01, count: 32)
        let ephPub1 = Data(P256.KeyAgreement.PrivateKey().publicKey.x963Representation)
        let ephPub2 = Data(P256.KeyAgreement.PrivateKey().publicKey.x963Representation)

        let (s2k, s3k) = CASEKeyDerivation.deriveSigmaKeys(
            sharedSecret: sharedSecret, ipk: ipk,
            responderRandom: random,
            responderEphPubKey: ephPub1,
            initiatorEphPubKey: ephPub2
        )

        #expect(s2k.bitCount == 128)
        #expect(s3k.bitCount == 128)
    }

    @Test("Session keys from CASE derivation are 16 bytes each")
    func caseSessionKeySizes() {
        let sharedSecret = Data(repeating: 0xCD, count: 32)
        let ipk = Data(repeating: 0, count: 16)
        let random = Data(repeating: 0x01, count: 32)
        let ephPub1 = Data(P256.KeyAgreement.PrivateKey().publicKey.x963Representation)
        let ephPub2 = Data(P256.KeyAgreement.PrivateKey().publicKey.x963Representation)

        let keys = CASEKeyDerivation.deriveSessionKeys(
            sharedSecret: sharedSecret, ipk: ipk,
            responderRandom: random,
            responderEphPubKey: ephPub1,
            initiatorEphPubKey: ephPub2
        )

        #expect(keys.i2rKey.bitCount == 128)
        #expect(keys.r2iKey.bitCount == 128)
        #expect(keys.attestationKey.bitCount == 128)
    }
}
