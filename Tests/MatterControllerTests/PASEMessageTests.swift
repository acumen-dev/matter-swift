// PASEMessageTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
@testable import MatterController
import MatterProtocol
import MatterTypes

@Suite("PASE Messages")
struct PASEMessageTests {

    @Test("PBKDFParamRequest TLV round-trip")
    func pbkdfParamRequestRoundTrip() throws {
        let random = Data(repeating: 0xAB, count: 32)
        let request = PASEMessages.PBKDFParamRequest(
            initiatorRandom: random,
            initiatorSessionID: 42,
            passcodeID: 0,
            hasPBKDFParameters: false
        )

        let encoded = request.tlvEncode()
        let parsed = try PASEMessages.PBKDFParamRequest.fromTLV(encoded)

        #expect(parsed.initiatorRandom == random)
        #expect(parsed.initiatorSessionID == 42)
        #expect(parsed.passcodeID == 0)
        #expect(parsed.hasPBKDFParameters == false)
    }

    @Test("PBKDFParamResponse TLV round-trip")
    func pbkdfParamResponseRoundTrip() throws {
        let iRandom = Data(repeating: 0x11, count: 32)
        let rRandom = Data(repeating: 0x22, count: 32)
        let salt = Data(repeating: 0x33, count: 16)

        let response = PASEMessages.PBKDFParamResponse(
            initiatorRandom: iRandom,
            responderRandom: rRandom,
            responderSessionID: 100,
            iterations: 1000,
            salt: salt
        )

        let encoded = response.tlvEncode()
        let parsed = try PASEMessages.PBKDFParamResponse.fromTLV(encoded)

        #expect(parsed.initiatorRandom == iRandom)
        #expect(parsed.responderRandom == rRandom)
        #expect(parsed.responderSessionID == 100)
        #expect(parsed.iterations == 1000)
        #expect(parsed.salt == salt)
    }

    @Test("Pake1Message TLV round-trip")
    func pake1MessageRoundTrip() throws {
        let pA = Data(repeating: 0x04, count: 65)
        let msg = PASEMessages.Pake1Message(pA: pA)

        let encoded = msg.tlvEncode()
        let parsed = try PASEMessages.Pake1Message.fromTLV(encoded)

        #expect(parsed.pA == pA)
    }

    @Test("Pake2Message TLV round-trip")
    func pake2MessageRoundTrip() throws {
        let pB = Data(repeating: 0x04, count: 65)
        let cB = Data(repeating: 0xCC, count: 32)
        let msg = PASEMessages.Pake2Message(pB: pB, cB: cB)

        let encoded = msg.tlvEncode()
        let parsed = try PASEMessages.Pake2Message.fromTLV(encoded)

        #expect(parsed.pB == pB)
        #expect(parsed.cB == cB)
    }

    @Test("Pake3Message TLV round-trip")
    func pake3MessageRoundTrip() throws {
        let cA = Data(repeating: 0xDD, count: 32)
        let msg = PASEMessages.Pake3Message(cA: cA)

        let encoded = msg.tlvEncode()
        let parsed = try PASEMessages.Pake3Message.fromTLV(encoded)

        #expect(parsed.cA == cA)
    }
}
