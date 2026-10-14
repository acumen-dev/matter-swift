// DeviceRegistry.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterTransport
import MatterProtocol
import MatterCrypto

/// How a commissioned device passed device attestation. Mirrors ``StoredAttestationRecord``.
public enum DeviceAttestationRecord: Sendable, Codable, Equatable {

    /// The attestation chain verified against a trusted PAA.
    case verified(paaSubject: String, vendorID: UInt16, productID: UInt16)

    /// Attestation failed with `reason` and the caller approved commissioning the device
    /// whose DAC has `dacFingerprint` (SHA-256 of the DAC DER) at `approvedAt`.
    case overridden(dacFingerprint: Data, reason: AttestationFailureReason, approvedAt: Date)

    /// The stored form.
    var stored: StoredAttestationRecord {
        switch self {
        case .verified(let paaSubject, let vendorID, let productID):
            return .verified(paaSubject: paaSubject, vendorID: vendorID, productID: productID)
        case .overridden(let fingerprint, let reason, let approvedAt):
            return .overridden(dacFingerprint: fingerprint, reason: reason.rawValue, approvedAt: approvedAt)
        }
    }

    /// - Throws: ``ControllerError/corruptStoredState(_:)`` if an override's reason is not an
    ///   `AttestationFailureReason`. It is never mapped to another reason.
    init(stored: StoredAttestationRecord, nodeID: UInt64) throws {
        switch stored {
        case .verified(let paaSubject, let vendorID, let productID):
            self = .verified(paaSubject: paaSubject, vendorID: vendorID, productID: productID)
        case .overridden(let fingerprint, let reason, let approvedAt):
            guard let parsed = AttestationFailureReason(rawValue: reason) else {
                throw ControllerError.corruptStoredState(
                    "stored attestation override for node \(nodeID) has unknown reason \"\(reason)\"; "
                    + "the state was written by a newer library or is corrupt")
            }
            self = .overridden(dacFingerprint: fingerprint, reason: parsed, approvedAt: approvedAt)
        }
    }
}

/// A commissioned Matter device known to the controller.
///
/// Tracks the device's identity, address, and commissioning metadata.
/// The operational address is stored as separate host/port fields because
/// `MatterAddress` does not conform to `Codable`.
public struct CommissionedDevice: Sendable, Codable, Equatable {

    /// The device's operational node ID.
    public let nodeID: NodeID

    /// The fabric index the device belongs to.
    public let fabricIndex: FabricIndex

    /// The product's vendor ID, as the device reports it in Basic Information. When
    /// ``attestation`` is ``DeviceAttestationRecord/verified(paaSubject:vendorID:productID:)``
    /// the verified Certification Declaration lists it; on the override path it is the device's
    /// unverified claim, so consult ``attestation``. A white-label product's DAC may name a
    /// different vendor (the OEM's); the DAC's identifiers are the ones in the verified record.
    public let vendorID: VendorID?

    /// The product's product ID, from Basic Information; verified or not as ``vendorID``.
    public let productID: ProductID?

    /// Operational address — host (stored for Codable compatibility).
    public var operationalHost: String?

    /// Operational address — port (stored for Codable compatibility).
    public var operationalPort: UInt16?

    /// Human-readable label for the device.
    public var label: String?

    /// When this device was commissioned.
    public let commissionedAt: Date

    /// The device's advertised MRP parameters (SII/SAI/SAT), if known.
    /// Spaces retransmissions toward sleepy devices; `nil` uses the
    /// controller's `Configuration.mrp.peer`.
    public var mrpParameters: MRPParameters?

    /// How the device passed attestation at commissioning; `nil` for a device commissioned
    /// before attestation was recorded.
    public var attestation: DeviceAttestationRecord?

    public init(
        nodeID: NodeID,
        fabricIndex: FabricIndex,
        vendorID: VendorID? = nil,
        productID: ProductID? = nil,
        operationalHost: String? = nil,
        operationalPort: UInt16? = nil,
        label: String? = nil,
        commissionedAt: Date = Date(),
        mrpParameters: MRPParameters? = nil,
        attestation: DeviceAttestationRecord? = nil
    ) {
        self.nodeID = nodeID
        self.fabricIndex = fabricIndex
        self.vendorID = vendorID
        self.productID = productID
        self.operationalHost = operationalHost
        self.operationalPort = operationalPort
        self.label = label
        self.commissionedAt = commissionedAt
        self.mrpParameters = mrpParameters
        self.attestation = attestation
    }

    // MARK: - Address Convenience

    /// The operational address as a `MatterAddress`, if both host and port are set.
    public var operationalAddress: MatterAddress? {
        guard let host = operationalHost, let port = operationalPort else {
            return nil
        }
        return MatterAddress(host: host, port: port)
    }

    /// Set the operational address from a `MatterAddress`.
    public mutating func setOperationalAddress(_ address: MatterAddress) {
        self.operationalHost = address.host
        self.operationalPort = address.port
    }
}

/// Thread-safe registry of commissioned devices.
///
/// Tracks devices by their node IDs and provides lookup,
/// update, and removal operations.
///
/// ```swift
/// let registry = DeviceRegistry()
/// registry.register(device)
/// let device = registry.device(for: nodeID)
/// ```
public actor DeviceRegistry {

    // MARK: - Storage

    private var devices: [NodeID: CommissionedDevice] = [:]

    public init() {}

    /// Restore a registry from persisted device list.
    ///
    /// - Throws: ``ControllerError/corruptStoredState(_:)`` if a stored attestation override
    ///   names a reason this library does not know.
    public init(storedDevices: [StoredCommissionedDevice]) throws {
        for sd in storedDevices {
            let device = CommissionedDevice(
                nodeID: NodeID(rawValue: sd.nodeID),
                fabricIndex: FabricIndex(rawValue: sd.fabricIndex),
                vendorID: sd.vendorID.map { VendorID(rawValue: $0) },
                productID: sd.productID.map { ProductID(rawValue: $0) },
                operationalHost: sd.operationalHost,
                operationalPort: sd.operationalPort,
                label: sd.label,
                commissionedAt: sd.commissionedAt,
                mrpParameters: Self.mrpParameters(from: sd),
                attestation: try sd.attestation.map { try DeviceAttestationRecord(stored: $0, nodeID: sd.nodeID) }
            )
            devices[device.nodeID] = device
        }
    }

    // MARK: - Registration

    /// Register a newly commissioned device.
    ///
    /// If a device with the same node ID already exists, it is replaced.
    public func register(_ device: CommissionedDevice) {
        devices[device.nodeID] = device
    }

    // MARK: - Lookup

    /// Find a device by its node ID.
    public func device(for nodeID: NodeID) -> CommissionedDevice? {
        devices[nodeID]
    }

    // MARK: - Update

    /// Update the operational address for a device.
    public func updateAddress(for nodeID: NodeID, address: MatterAddress) {
        guard var device = devices[nodeID] else { return }
        device.setOperationalAddress(address)
        devices[nodeID] = device
    }

    /// Update the label for a device.
    public func updateLabel(for nodeID: NodeID, label: String) {
        guard var device = devices[nodeID] else { return }
        device.label = label
        devices[nodeID] = device
    }

    /// Set or clear a device's advertised MRP parameters.
    public func updateMRPParameters(for nodeID: NodeID, parameters: MRPParameters?) {
        guard var device = devices[nodeID] else { return }
        device.mrpParameters = parameters
        devices[nodeID] = device
    }

    // MARK: - Removal

    /// Remove a device from the registry.
    @discardableResult
    public func remove(nodeID: NodeID) -> CommissionedDevice? {
        devices.removeValue(forKey: nodeID)
    }

    // MARK: - Queries

    /// All registered devices.
    public var allDevices: [CommissionedDevice] {
        Array(devices.values)
    }

    /// The number of registered devices.
    public var count: Int {
        devices.count
    }

    /// Snapshot of all devices, sorted by node ID for deterministic ordering.
    public func snapshot() -> [CommissionedDevice] {
        devices.values.sorted { $0.nodeID.rawValue < $1.nodeID.rawValue }
    }

    // MARK: - Persistence

    /// Export all devices as `StoredCommissionedDevice` for persistence.
    public func toStoredDevices() -> [StoredCommissionedDevice] {
        devices.values.map { d in
            StoredCommissionedDevice(
                nodeID: d.nodeID.rawValue,
                fabricIndex: d.fabricIndex.rawValue,
                vendorID: d.vendorID?.rawValue,
                productID: d.productID?.rawValue,
                operationalHost: d.operationalHost,
                operationalPort: d.operationalPort,
                label: d.label,
                commissionedAt: d.commissionedAt,
                mrpIdleIntervalMs: d.mrpParameters.map { Self.milliseconds($0.sessionIdleInterval) },
                mrpActiveIntervalMs: d.mrpParameters.map { Self.milliseconds($0.sessionActiveInterval) },
                mrpActiveThresholdMs: d.mrpParameters.map { Self.milliseconds($0.sessionActiveThreshold) },
                attestation: d.attestation?.stored
            )
        }
    }

    // MARK: - MRP parameter persistence

    /// Parameters from a stored record; a missing field takes the spec default.
    static func mrpParameters(from stored: StoredCommissionedDevice) -> MRPParameters? {
        guard stored.mrpIdleIntervalMs != nil || stored.mrpActiveIntervalMs != nil || stored.mrpActiveThresholdMs != nil else {
            return nil
        }
        let defaults = MRPParameters.default
        return MRPParameters(
            sessionIdleInterval: stored.mrpIdleIntervalMs.map { .milliseconds(Int64($0)) } ?? defaults.sessionIdleInterval,
            sessionActiveInterval: stored.mrpActiveIntervalMs.map { .milliseconds(Int64($0)) } ?? defaults.sessionActiveInterval,
            sessionActiveThreshold: stored.mrpActiveThresholdMs.map { .milliseconds(Int64($0)) } ?? defaults.sessionActiveThreshold
        )
    }

    static func milliseconds(_ duration: Duration) -> UInt32 {
        let (seconds, attoseconds) = duration.components
        return UInt32(clamping: seconds * 1_000 + attoseconds / 1_000_000_000_000_000)
    }
}
