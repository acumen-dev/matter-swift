// DeviceRegistry.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterTransport

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

    /// The device's vendor ID (from Basic Information cluster).
    public let vendorID: VendorID?

    /// The device's product ID (from Basic Information cluster).
    public let productID: ProductID?

    /// Operational address — host (stored for Codable compatibility).
    public var operationalHost: String?

    /// Operational address — port (stored for Codable compatibility).
    public var operationalPort: UInt16?

    /// Human-readable label for the device.
    public var label: String?

    /// When this device was commissioned.
    public let commissionedAt: Date

    public init(
        nodeID: NodeID,
        fabricIndex: FabricIndex,
        vendorID: VendorID? = nil,
        productID: ProductID? = nil,
        operationalHost: String? = nil,
        operationalPort: UInt16? = nil,
        label: String? = nil,
        commissionedAt: Date = Date()
    ) {
        self.nodeID = nodeID
        self.fabricIndex = fabricIndex
        self.vendorID = vendorID
        self.productID = productID
        self.operationalHost = operationalHost
        self.operationalPort = operationalPort
        self.label = label
        self.commissionedAt = commissionedAt
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
}
