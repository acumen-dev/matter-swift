// MockTransports.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Synchronization
import MatterTransport
@testable import MatterDevice

/// Mock UDP transport for device server tests.
///
/// Captures sent messages and allows injecting received datagrams.
/// Uses `Mutex` for thread-safe state access from both sync and async contexts.
final class MockServerUDPTransport: MatterUDPTransport, @unchecked Sendable {

    private let state = Mutex(TransportState())
    private var continuation: AsyncStream<(Data, MatterAddress)>.Continuation?
    private let stream: AsyncStream<(Data, MatterAddress)>

    struct TransportState {
        var sentMessages: [(Data, MatterAddress)] = []
        var boundPort: UInt16?
        var isClosed = false
    }

    init() {
        let (stream, continuation) = AsyncStream<(Data, MatterAddress)>.makeStream()
        self.stream = stream
        self.continuation = continuation
    }

    // MARK: - Test Helpers

    /// Inject a datagram as if received from the network.
    func injectDatagram(_ data: Data, from address: MatterAddress) {
        continuation?.yield((data, address))
    }

    var sentMessages: [(Data, MatterAddress)] {
        state.withLock { $0.sentMessages }
    }

    var sentCount: Int {
        state.withLock { $0.sentMessages.count }
    }

    var boundPort: UInt16? {
        state.withLock { $0.boundPort }
    }

    var isClosed: Bool {
        state.withLock { $0.isClosed }
    }

    // MARK: - MatterUDPTransport

    func send(_ data: Data, to address: MatterAddress) async throws {
        state.withLock { $0.sentMessages.append((data, address)) }
    }

    func receive() -> AsyncStream<(Data, MatterAddress)> {
        stream
    }

    func bind(port: UInt16) async throws {
        state.withLock { $0.boundPort = port }
    }

    func close() async {
        state.withLock { $0.isClosed = true }
        continuation?.finish()
        continuation = nil
    }
}

/// Mock discovery for device server tests.
actor MockServerDiscovery: MatterDiscovery {

    private(set) var advertisedServices: [MatterServiceRecord] = []
    private(set) var isAdvertising = false
    private var browseRecords: [MatterServiceType: [MatterServiceRecord]] = [:]
    private var resolveResults: [String: MatterAddress] = [:]

    // MARK: - Test Helpers

    func addBrowseRecord(_ record: MatterServiceRecord) {
        browseRecords[record.serviceType, default: []].append(record)
    }

    func setResolveResult(name: String, address: MatterAddress) {
        resolveResults[name] = address
    }

    // MARK: - MatterDiscovery

    nonisolated func advertise(service: MatterServiceRecord) async throws {
        await recordAdvertise(service)
    }

    nonisolated func browse(type: MatterServiceType) -> AsyncStream<MatterServiceRecord> {
        AsyncStream { continuation in
            Task {
                let records = await self.recordsForType(type)
                for record in records {
                    continuation.yield(record)
                }
                continuation.finish()
            }
        }
    }

    nonisolated func resolve(_ record: MatterServiceRecord) async throws -> MatterAddress {
        guard let address = await addressForName(record.name) else {
            throw ServerTestError.resolveFailed
        }
        return address
    }

    nonisolated func stopAdvertising() async {
        await recordStopAdvertising()
    }

    nonisolated func stopAdvertising(name: String) async {
        await recordStopAdvertisingByName(name)
    }

    /// Services currently advertised (filtered to only active ones).
    var activeServices: [MatterServiceRecord] {
        advertisedServices
    }

    /// Services advertised with a specific service type.
    func services(ofType type: MatterServiceType) -> [MatterServiceRecord] {
        advertisedServices.filter { $0.serviceType == type }
    }

    // MARK: - Internal

    private func recordAdvertise(_ service: MatterServiceRecord) {
        advertisedServices.append(service)
        isAdvertising = true
    }

    private func recordsForType(_ type: MatterServiceType) -> [MatterServiceRecord] {
        browseRecords[type] ?? []
    }

    private func addressForName(_ name: String) -> MatterAddress? {
        resolveResults[name]
    }

    private func recordStopAdvertising() {
        advertisedServices.removeAll()
        isAdvertising = false
    }

    private func recordStopAdvertisingByName(_ name: String) {
        advertisedServices.removeAll { $0.name == name }
        if advertisedServices.isEmpty {
            isAdvertising = false
        }
    }
}

enum ServerTestError: Error {
    case resolveFailed
}
