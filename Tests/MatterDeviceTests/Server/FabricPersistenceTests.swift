// FabricPersistenceTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
import MatterTypes
import MatterTestSupport
@testable import MatterDevice

/// Fabric-store write failures and the server's admin surface for fabrics.
///
/// No wall clock: the retry delay is injected.
@Suite("Fabric Persistence", .timeLimit(.minutes(1)))
struct FabricPersistenceTests {

    // MARK: - Helpers

    /// A fabric store that fails its next `failuresLeft` saves.
    private actor FlakyFabricStore: MatterFabricStore {
        struct WriteFailed: Error {}
        var failuresLeft: Int
        private(set) var attempts = 0
        private(set) var state: StoredDeviceState?

        init(failures: Int, state: StoredDeviceState? = nil) {
            self.failuresLeft = failures
            self.state = state
        }

        func setFailures(_ count: Int) { failuresLeft = count }

        func load() async throws -> StoredDeviceState? { state }

        func save(_ state: StoredDeviceState) async throws {
            attempts += 1
            if failuresLeft > 0 {
                failuresLeft -= 1
                throw WriteFailed()
            }
            self.state = state
        }
    }

    private func storedFabric(index: UInt8) -> StoredFabric {
        StoredFabric(
            fabricIndex: index,
            nocTLV: Data(repeating: 0xBB, count: 64),
            icacTLV: nil,
            rcacTLV: Data(repeating: 0xAA, count: 64),
            operationalKeyRaw: P256.Signing.PrivateKey().rawRepresentation,
            ipkEpochKey: Data(repeating: 0x11, count: 16),
            caseAdminSubject: 0x1234,
            adminVendorId: 0xFFF1
        )
    }

    // MARK: - Write Failures

    @Test("A failed fabric-store write is retried and the latest state lands")
    func failedWriteIsRetried() async throws {
        let store = FlakyFabricStore(failures: 2)
        let delays = LockedValue<[Int]>([])
        let state = CommissioningState(fabricStore: store) { attempt in
            delays.withLock { $0.append(attempt) }
        }
        try await state.loadFromStore()

        let salt = Data(repeating: 0xAB, count: 16)
        state.setPBKDFParameters(salt: salt, iterations: 2000)
        await state.flush()

        #expect(await store.attempts == 3)
        #expect(await store.state?.pbkdfSalt == salt)
        #expect(delays.value == [1, 2])
    }

    @Test("A write that keeps failing is given up after the attempt limit; a later change writes again")
    func persistentFailureGivesUp() async throws {
        let store = FlakyFabricStore(failures: 100)
        let state = CommissioningState(fabricStore: store) { _ in }
        try await state.loadFromStore()

        state.setPBKDFParameters(salt: Data(repeating: 1, count: 16), iterations: 1000)
        await state.flush()
        #expect(await store.attempts == CommissioningState.maxSaveAttempts)
        #expect(await store.state == nil)

        await store.setFailures(0)
        let salt = Data(repeating: 2, count: 16)
        state.setPBKDFParameters(salt: salt, iterations: 1000)
        await state.flush()
        #expect(await store.state?.pbkdfSalt == salt)
    }

    // MARK: - Server Admin Surface

    @Test("The server reports and removes fabrics, and the removal is saved")
    func serverRemovesFabric() async throws {
        let fabricStore = InMemoryFabricStore(state: StoredDeviceState(
            fabrics: [storedFabric(index: 1), storedFabric(index: 2)],
            nextFabricIndex: 3
        ))
        let bridge = try await MatterBridge(fabricStore: fabricStore)
        let server = MatterDeviceServer(
            bridge: bridge,
            transport: MockServerUDPTransport(),
            discovery: MockServerDiscovery()
        )

        #expect(await server.fabricCount == 2)
        #expect(await server.fabrics.map(\.fabricIndex.rawValue) == [1, 2])
        #expect(await server.fabrics.first?.adminVendorId == 0xFFF1)

        #expect(await server.removeFabric(FabricIndex(rawValue: 1)))
        #expect(await !server.removeFabric(FabricIndex(rawValue: 9)))

        #expect(await server.fabricCount == 1)
        let saved = try #require(try await fabricStore.load())
        #expect(saved.fabrics.map(\.fabricIndex) == [2])
    }
}
