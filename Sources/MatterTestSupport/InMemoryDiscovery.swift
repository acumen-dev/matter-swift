// InMemoryDiscovery.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTransport

/// An in-process DNS-SD registry shared by a device server and a controller
/// in one test: what one side advertises, the other browses and resolves.
///
/// Addresses come from the `address` closure, so a test maps a record to the
/// in-memory link endpoint it should reach.
public final class InMemoryDiscovery: ServiceDiscovery, Sendable {

    /// Thrown by `resolve` / `resolveService` for a name that is not
    /// advertised, or that the address closure does not map.
    public enum ResolveError: Error, Sendable, Equatable {
        case notFound(String)
    }

    // MARK: - State

    private struct Browser: Sendable {
        let serviceType: ServiceType
        let continuation: AsyncStream<ServiceRecord>.Continuation
    }

    private struct State: Sendable {
        /// In advertisement order, so browse yields deterministically.
        var records: [ServiceRecord] = []
        var browsers: [UUID: Browser] = [:]
        var resolveCounts: [String: Int] = [:]
        var browseTXTHidden = false
    }

    private let state = LockedValue(State())
    private let address: @Sendable (ServiceRecord) -> MatterAddress?

    public init(address: @escaping @Sendable (ServiceRecord) -> MatterAddress?) {
        self.address = address
    }

    // MARK: - Test Hooks

    /// How many times `resolveService` (or `resolve`) was called for `name`.
    public func resolveCount(name: String) -> Int {
        state.withLock { $0.resolveCounts[name, default: 0] }
    }

    /// Simulate a browser that yields records without their TXT, so the
    /// consumer must resolve to see it.
    public func setBrowseTXTHidden(_ hidden: Bool) {
        state.withLock { $0.browseTXTHidden = hidden }
    }

    /// Number of browse streams currently open.
    public var activeBrowseCount: Int {
        state.withLock { $0.browsers.count }
    }

    // MARK: - ServiceDiscovery

    public func advertise(service: ServiceRecord) async throws {
        state.withLock { state in
            if let index = state.records.firstIndex(where: { $0.name == service.name }) {
                state.records[index] = service
            } else {
                state.records.append(service)
            }
            let yielded = Self.browsed(service, txtHidden: state.browseTXTHidden)
            for browser in state.browsers.values where browser.serviceType == service.serviceType {
                browser.continuation.yield(yielded)
            }
        }
    }

    public func browse(serviceType: ServiceType) -> AsyncStream<ServiceRecord> {
        let (stream, continuation) = AsyncStream<ServiceRecord>.makeStream()
        let id = UUID()
        state.withLock { state in
            state.browsers[id] = Browser(serviceType: serviceType, continuation: continuation)
            for record in state.records where record.serviceType == serviceType {
                continuation.yield(Self.browsed(record, txtHidden: state.browseTXTHidden))
            }
        }
        continuation.onTermination = { [state] _ in
            state.withLock { _ = $0.browsers.removeValue(forKey: id) }
        }
        return stream
    }

    public func resolve(_ record: ServiceRecord) async throws -> NetworkAddress {
        try await resolveService(record).address
    }

    public func resolveService(_ record: ServiceRecord) async throws -> ResolvedService {
        let stored = state.withLock { state in
            state.resolveCounts[record.name, default: 0] += 1
            return state.records.first { $0.name == record.name }
        }
        guard let stored, let resolved = address(stored) else {
            throw ResolveError.notFound(record.name)
        }
        return ResolvedService(address: resolved, txtRecords: stored.txtRecords)
    }

    public func stopAdvertising() async {
        state.withLock { $0.records.removeAll() }
    }

    public func stopAdvertising(name: String) async {
        state.withLock { $0.records.removeAll { $0.name == name } }
    }

    // MARK: - Private

    private static func browsed(_ record: ServiceRecord, txtHidden: Bool) -> ServiceRecord {
        guard txtHidden else { return record }
        return ServiceRecord(
            name: record.name,
            serviceType: record.serviceType,
            host: record.host,
            port: record.port,
            txtRecords: [:],
            subtypes: record.subtypes,
            preferredInterface: record.preferredInterface,
            advertiseOnAllInterfaces: record.advertiseOnAllInterfaces
        )
    }
}
