// CASEResumptionTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
@testable import MatterCrypto
import MatterTypes

@Suite("CASEResumption")
struct CASEResumptionTests {

    // MARK: - ResumptionTicketStore

    @Test("ResumptionTicketStore stores and consumes ticket")
    func storeAndConsume() async {
        let store = ResumptionTicketStore()
        let id = Data(repeating: 0xAB, count: 16)
        let ticket = ResumptionTicket(
            resumptionID: id,
            sharedSecret: Data(repeating: 0x42, count: 32),
            peerNodeID: NodeID(rawValue: 1),
            peerFabricID: FabricID(rawValue: 1),
            fabricIndex: FabricIndex(rawValue: 1),
            expiryDate: Date().addingTimeInterval(3600)
        )
        await store.store(ticket: ticket)
        let count = await store.count
        #expect(count == 1)
        let consumed = await store.consume(resumptionID: id)
        #expect(consumed != nil)
        #expect(consumed?.resumptionID == id)
        let countAfter = await store.count
        #expect(countAfter == 0)
    }

    @Test("consuming same ticket twice returns nil on second attempt")
    func doubleConsume() async {
        let store = ResumptionTicketStore()
        let id = Data(repeating: 0xCD, count: 16)
        let ticket = ResumptionTicket(
            resumptionID: id,
            sharedSecret: Data(repeating: 0x01, count: 32),
            peerNodeID: NodeID(rawValue: 2),
            peerFabricID: FabricID(rawValue: 1),
            fabricIndex: FabricIndex(rawValue: 1),
            expiryDate: Date().addingTimeInterval(3600)
        )
        await store.store(ticket: ticket)
        let first = await store.consume(resumptionID: id)
        let second = await store.consume(resumptionID: id)
        #expect(first != nil)
        #expect(second == nil)
    }

    @Test("purgeExpired removes expired tickets")
    func purgeExpired() async {
        let store = ResumptionTicketStore()
        let id = Data(repeating: 0xEF, count: 16)
        let ticket = ResumptionTicket(
            resumptionID: id,
            sharedSecret: Data(repeating: 0x02, count: 32),
            peerNodeID: NodeID(rawValue: 3),
            peerFabricID: FabricID(rawValue: 1),
            fabricIndex: FabricIndex(rawValue: 1),
            expiryDate: Date().addingTimeInterval(-1) // already expired
        )
        await store.store(ticket: ticket)
        await store.purgeExpired()
        let count = await store.count
        #expect(count == 0)
    }

    @Test("expired ticket returns nil on consume")
    func expiredTicketConsumeReturnsNil() async {
        let store = ResumptionTicketStore()
        let id = Data(repeating: 0x11, count: 16)
        let ticket = ResumptionTicket(
            resumptionID: id,
            sharedSecret: Data(repeating: 0x03, count: 32),
            peerNodeID: NodeID(rawValue: 4),
            peerFabricID: FabricID(rawValue: 1),
            fabricIndex: FabricIndex(rawValue: 1),
            expiryDate: Date().addingTimeInterval(-60) // expired 60 seconds ago
        )
        await store.store(ticket: ticket)
        let result = await store.consume(resumptionID: id)
        #expect(result == nil)
    }

    @Test("maxTickets eviction removes oldest ticket by expiry")
    func maxTicketsEviction() async {
        let store = ResumptionTicketStore(maxTickets: 2)

        let id1 = Data(repeating: 0xA1, count: 16)
        let id2 = Data(repeating: 0xA2, count: 16)
        let id3 = Data(repeating: 0xA3, count: 16)

        // Store two tickets — first one expires sooner
        let ticket1 = ResumptionTicket(
            resumptionID: id1,
            sharedSecret: Data(count: 32),
            peerNodeID: NodeID(rawValue: 1),
            peerFabricID: FabricID(rawValue: 1),
            fabricIndex: FabricIndex(rawValue: 1),
            expiryDate: Date().addingTimeInterval(100) // expires first
        )
        let ticket2 = ResumptionTicket(
            resumptionID: id2,
            sharedSecret: Data(count: 32),
            peerNodeID: NodeID(rawValue: 2),
            peerFabricID: FabricID(rawValue: 1),
            fabricIndex: FabricIndex(rawValue: 1),
            expiryDate: Date().addingTimeInterval(200)
        )
        let ticket3 = ResumptionTicket(
            resumptionID: id3,
            sharedSecret: Data(count: 32),
            peerNodeID: NodeID(rawValue: 3),
            peerFabricID: FabricID(rawValue: 1),
            fabricIndex: FabricIndex(rawValue: 1),
            expiryDate: Date().addingTimeInterval(300)
        )

        await store.store(ticket: ticket1)
        await store.store(ticket: ticket2)
        // Adding a 3rd should evict ticket1 (earliest expiry)
        await store.store(ticket: ticket3)

        let count = await store.count
        #expect(count == 2)

        // ticket1 should have been evicted
        let consumed1 = await store.consume(resumptionID: id1)
        #expect(consumed1 == nil)

        // ticket2 and ticket3 should still be present
        let consumed2 = await store.consume(resumptionID: id2)
        #expect(consumed2 != nil)
        let consumed3 = await store.consume(resumptionID: id3)
        #expect(consumed3 != nil)
    }

    // MARK: - Sigma2ResumeMessage

    @Test("Sigma2ResumeMessage round-trips through TLV")
    func sigma2ResumeTLVRoundTrip() throws {
        let msg = Sigma2ResumeMessage(
            resumptionID: Data(repeating: 0x01, count: 16),
            sigma2ResumeMIC: Data(repeating: 0x02, count: 16),
            responderSessionID: 0x1234
        )
        let decoded = try Sigma2ResumeMessage.fromTLVElement(msg.toTLVElement())
        #expect(decoded == msg)
    }

    // MARK: - CASEResumption Key Derivation

    @Test("resume key derivation produces 128-bit key")
    func resumeKeyLength() throws {
        let sharedSecret = Data(repeating: 0xAA, count: 32)
        let resumptionID = Data(repeating: 0xBB, count: 16)
        let key = try CASEResumption.deriveResumeKey(sharedSecret: sharedSecret, resumptionID: resumptionID)
        #expect(key.bitCount == 128)
    }

    @Test("resumed session keys derivation produces 128-bit i2r and r2i keys")
    func resumedSessionKeysLength() throws {
        let sharedSecret = Data(repeating: 0xCC, count: 32)
        let resumptionID = Data(repeating: 0xDD, count: 16)
        let keys = try CASEResumption.deriveResumedSessionKeys(sharedSecret: sharedSecret, resumptionID: resumptionID)
        #expect(keys.i2rKey.bitCount == 128)
        #expect(keys.r2iKey.bitCount == 128)
        #expect(keys.attestationKey.bitCount == 128)
    }
}
