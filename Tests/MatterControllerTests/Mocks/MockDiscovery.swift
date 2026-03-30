// MockDiscovery.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTransport
@testable import MatterController

/// Mock mDNS/DNS-SD discovery for testing.
///
/// Supports scripted browse results and resolve responses.
actor MockDiscovery: MatterDiscovery {

    // MARK: - State

    private var browseRecords: [ServiceType: [MatterServiceRecord]] = [:]
    private var resolveResults: [String: MatterAddress] = [:]
    private var advertisedServices: [MatterServiceRecord] = []

    // MARK: - Test Helpers

    /// Add a service record to be returned from `browse()`.
    func addBrowseRecord(_ record: MatterServiceRecord) {
        browseRecords[record.serviceType, default: []].append(record)
    }

    /// Set the resolve result for a service name.
    func setResolveResult(name: String, address: MatterAddress) {
        resolveResults[name] = address
    }

    // MARK: - MatterDiscovery

    nonisolated func advertise(service: MatterServiceRecord) async throws {
        await recordAdvertise(service)
    }

    nonisolated func browse(serviceType: ServiceType) -> AsyncStream<MatterServiceRecord> {
        AsyncStream { continuation in
            Task {
                let records = await self.recordsForType(serviceType)
                for record in records {
                    continuation.yield(record)
                }
                continuation.finish()
            }
        }
    }

    nonisolated func resolve(_ record: MatterServiceRecord) async throws -> MatterAddress {
        guard let address = await addressForName(record.name) else {
            throw ControllerError.discoveryFailed("No resolve result for \(record.name)")
        }
        return address
    }

    nonisolated func stopAdvertising() async {
        await clearAdvertised()
    }

    nonisolated func stopAdvertising(name: String) async {
        await removeAdvertised(name: name)
    }

    /// All services currently advertised.
    var currentAdvertisements: [MatterServiceRecord] {
        advertisedServices
    }

    // MARK: - Internal

    private func recordAdvertise(_ service: MatterServiceRecord) {
        advertisedServices.append(service)
    }

    private func recordsForType(_ serviceType: ServiceType) -> [MatterServiceRecord] {
        browseRecords[serviceType] ?? []
    }

    private func addressForName(_ name: String) -> MatterAddress? {
        resolveResults[name]
    }

    private func clearAdvertised() {
        advertisedServices.removeAll()
    }

    private func removeAdvertised(name: String) {
        advertisedServices.removeAll { $0.name == name }
    }
}
