// SessionTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
@testable import MatterProtocol
@testable import MatterTypes

// MARK: - Counter Deduplication Tests

@Suite("Counter Deduplication")
struct CounterDeduplicationTests {

    @Test("First message always accepted")
    func firstMessage() {
        var dedup = CounterDeduplication(encrypted: true)
        #expect(dedup.accept(100) == true)
    }

    @Test("Exact duplicate rejected")
    func exactDuplicate() {
        var dedup = CounterDeduplication(encrypted: true)
        #expect(dedup.accept(100) == true)
        #expect(dedup.accept(100) == false)
    }

    @Test("Increasing counters accepted")
    func increasing() {
        var dedup = CounterDeduplication(encrypted: true)
        #expect(dedup.accept(1) == true)
        #expect(dedup.accept(2) == true)
        #expect(dedup.accept(3) == true)
        #expect(dedup.accept(100) == true)
    }

    @Test("Within-window counter tracked in bitmap")
    func windowBitmap() {
        var dedup = CounterDeduplication(encrypted: true)
        #expect(dedup.accept(10) == true)
        #expect(dedup.accept(20) == true) // max=20, counter 10 marked in bitmap
        #expect(dedup.accept(10) == false) // already received — bitmap catches it
        #expect(dedup.accept(15) == true) // within window, never seen
        #expect(dedup.accept(15) == false) // duplicate within window
    }

    @Test("Below window rejected for encrypted")
    func belowWindowEncrypted() {
        var dedup = CounterDeduplication(encrypted: true)
        #expect(dedup.accept(100) == true)
        // Counter 50 is 50 below max — outside 32-entry window
        #expect(dedup.accept(50) == false)
    }

    @Test("Below window accepted for unencrypted (device reboot)")
    func belowWindowUnencrypted() {
        var dedup = CounterDeduplication(encrypted: false)
        #expect(dedup.accept(100) == true)
        // Counter 50 is outside window — unencrypted accepts (possible reboot)
        #expect(dedup.accept(50) == true)
    }

    @Test("Large gap forward resets bitmap")
    func largeGapForward() {
        var dedup = CounterDeduplication(encrypted: true)
        #expect(dedup.accept(1) == true)
        #expect(dedup.accept(1000) == true) // Large gap, bitmap reset
        #expect(dedup.accept(1) == false)   // Way below window
    }

    @Test("Out-of-order within window accepted")
    func outOfOrderWindow() {
        var dedup = CounterDeduplication(encrypted: true)
        #expect(dedup.accept(10) == true)
        #expect(dedup.accept(8) == true)  // Within window, first time
        #expect(dedup.accept(9) == true)  // Within window, first time
        #expect(dedup.accept(8) == false) // Already received
    }

    @Test("Reset clears state")
    func resetState() {
        var dedup = CounterDeduplication(encrypted: true)
        #expect(dedup.accept(100) == true)
        #expect(dedup.accept(100) == false) // duplicate

        dedup.reset()
        #expect(dedup.accept(100) == true) // accepted after reset
    }
}

// MARK: - Message Counter Tests

@Suite("Message Counter")
struct MessageCounterTests {

    @Test("Random initial value within 28-bit range")
    func randomInitRange() {
        for _ in 0..<100 {
            let value = MessageCounter.randomInitialValue()
            #expect(value <= MessageCounter.randomInitMask)
        }
    }

    @Test("Global counter increments")
    func globalIncrement() async {
        let counter = GlobalMessageCounter(initialValue: 0)
        #expect(counter.next() == 1)
        #expect(counter.next() == 2)
        #expect(counter.next() == 3)
    }
}

// MARK: - Session Table Tests

@Suite("Session Table")
struct SessionTableTests {

    @Test("Add and retrieve session")
    func addAndRetrieve() async {
        let table = SessionTable()
        let session = SecureSession(
            localSessionID: 1,
            peerSessionID: 100,
            establishment: .pase,
            peerNodeID: NodeID(rawValue: 42),
            initialSendCounter: 0
        )

        await table.add(session)
        let found = await table.session(for: 1)
        #expect(found != nil)
        #expect(found?.peerSessionID == 100)
        #expect(found?.peerNodeID.rawValue == 42)
    }

    @Test("Session not found returns nil")
    func notFound() async {
        let table = SessionTable()
        let found = await table.session(for: 999)
        #expect(found == nil)
    }

    @Test("Remove session")
    func removeSession() async {
        let table = SessionTable()
        let session = SecureSession(
            localSessionID: 5,
            peerSessionID: 50,
            establishment: .case,
            peerNodeID: NodeID(rawValue: 1),
            initialSendCounter: 0
        )

        await table.add(session)
        #expect(await table.count == 1)

        let removed = await table.remove(sessionID: 5)
        #expect(removed != nil)
        #expect(await table.count == 0)
    }

    @Test("Allocate session IDs skips zero")
    func allocateIDs() async {
        let table = SessionTable()
        let id1 = await table.allocateSessionID()
        let id2 = await table.allocateSessionID()

        #expect(id1 != 0)
        #expect(id2 != 0)
        #expect(id1 != id2)
    }

    @Test("Eviction when table is full")
    func eviction() async {
        let table = SessionTable(maxSessions: 2)

        for i: UInt16 in 1...3 {
            let session = SecureSession(
                localSessionID: i,
                peerSessionID: i + 100,
                establishment: .case,
                peerNodeID: NodeID(rawValue: UInt64(i)),
                initialSendCounter: 0
            )
            await table.add(session)
        }

        // Should have evicted the oldest, keeping only 2
        #expect(await table.count == 2)
    }

    @Test("Find sessions by peer node ID")
    func findByPeer() async {
        let table = SessionTable()
        let peer = NodeID(rawValue: 42)

        for i: UInt16 in 1...3 {
            let session = SecureSession(
                localSessionID: i,
                peerSessionID: i + 100,
                establishment: .case,
                peerNodeID: i <= 2 ? peer : NodeID(rawValue: 99),
                initialSendCounter: 0
            )
            await table.add(session)
        }

        let found = await table.sessions(for: peer)
        #expect(found.count == 2)
    }

    @Test("Counter deduplication through session table")
    func counterDedup() async {
        let table = SessionTable()
        let session = SecureSession(
            localSessionID: 1,
            peerSessionID: 100,
            establishment: .pase,
            peerNodeID: NodeID(rawValue: 1),
            initialSendCounter: 0
        )
        await table.add(session)

        #expect(await table.acceptCounter(1, for: 1) == true)
        #expect(await table.acceptCounter(1, for: 1) == false) // duplicate
        #expect(await table.acceptCounter(2, for: 1) == true)
    }
}

// MARK: - Secure Session Tests

@Suite("Secure Session")
struct SecureSessionTests {

    @Test("Session counter increments")
    func counterIncrement() {
        let session = SecureSession(
            localSessionID: 1,
            peerSessionID: 2,
            establishment: .pase,
            peerNodeID: NodeID(rawValue: 1),
            initialSendCounter: 10
        )

        let c1 = session.nextSendCounter()
        let c2 = session.nextSendCounter()
        #expect(c2 == c1 + 1)
    }

    @Test("PASE session properties")
    func paseSession() {
        let session = SecureSession(
            localSessionID: 1,
            peerSessionID: 2,
            establishment: .pase,
            peerNodeID: NodeID(rawValue: 0),
            initialSendCounter: 0
        )

        #expect(session.establishment == .pase)
        #expect(session.fabricIndex == nil)
        #expect(session.isResumption == false)
    }

    @Test("CASE session with fabric")
    func caseSession() {
        let session = SecureSession(
            localSessionID: 100,
            peerSessionID: 200,
            establishment: .case,
            peerNodeID: NodeID(rawValue: 0x1234567890),
            fabricIndex: FabricIndex(rawValue: 1),
            initialSendCounter: 0
        )

        #expect(session.establishment == .case)
        #expect(session.fabricIndex?.rawValue == 1)
    }
}
