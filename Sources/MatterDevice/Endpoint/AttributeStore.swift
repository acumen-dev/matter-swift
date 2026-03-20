// AttributeStore.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterProtocol

/// Per-endpoint, per-cluster attribute storage with data versioning and dirty tracking.
///
/// `AttributeStore` stores TLV attribute values keyed by endpoint, cluster, and attribute ID.
/// Each cluster instance maintains an independent `DataVersion` that auto-increments when any
/// attribute value changes. Dirty tracking enables efficient subscription reports — only changed
/// attributes are reported.
///
/// This class is NOT an actor — it is serialized by its caller (typically the device/bridge actor).
public final class AttributeStore: @unchecked Sendable {

    // MARK: - Per-Cluster Storage

    struct ClusterStorage {
        var dataVersion: DataVersion
        var attributes: [AttributeID: TLVElement]
        var dirtyAttributes: Set<AttributeID>

        init() {
            self.dataVersion = DataVersion(rawValue: UInt32.random(in: 0...UInt32.max))
            self.attributes = [:]
            self.dirtyAttributes = []
        }
    }

    // MARK: - State

    private var storage: [EndpointID: [ClusterID: ClusterStorage]]

    // MARK: - Persistence

    private let attributeStore: (any MatterAttributeStore)?

    // MARK: - Init

    public init(attributeStore: (any MatterAttributeStore)? = nil) {
        self.storage = [:]
        self.attributeStore = attributeStore
    }

    // MARK: - Read

    /// Get an attribute value, or `nil` if not stored.
    public func get(endpoint: EndpointID, cluster: ClusterID, attribute: AttributeID) -> TLVElement? {
        storage[endpoint]?[cluster]?.attributes[attribute]
    }

    /// Get the current `DataVersion` for a cluster instance.
    ///
    /// Returns a zero-valued `DataVersion` if the cluster has no storage yet.
    public func dataVersion(endpoint: EndpointID, cluster: ClusterID) -> DataVersion {
        storage[endpoint]?[cluster]?.dataVersion ?? DataVersion(rawValue: 0)
    }

    /// Get all attributes stored for a cluster instance.
    public func allAttributes(endpoint: EndpointID, cluster: ClusterID) -> [(AttributeID, TLVElement)] {
        guard let clusterStorage = storage[endpoint]?[cluster] else { return [] }
        return clusterStorage.attributes.map { ($0.key, $0.value) }
    }

    /// Check if any data exists for the given endpoint.
    public func hasEndpoint(_ endpoint: EndpointID) -> Bool {
        storage[endpoint] != nil
    }

    /// Check if any data exists for the given cluster on the given endpoint.
    public func hasCluster(endpoint: EndpointID, cluster: ClusterID) -> Bool {
        storage[endpoint]?[cluster] != nil
    }

    /// All endpoint IDs that have data.
    public func allEndpointIDs() -> [EndpointID] {
        Array(storage.keys)
    }

    /// All cluster IDs on an endpoint.
    public func allClusterIDs(endpoint: EndpointID) -> [ClusterID] {
        guard let clusters = storage[endpoint] else { return [] }
        return Array(clusters.keys)
    }

    // MARK: - Write

    /// Set an attribute value. Returns `true` if the value actually changed.
    ///
    /// When the value changes, the cluster's `DataVersion` is incremented and the attribute
    /// is marked dirty for subscription reporting. No-op writes (same value) are detected
    /// via `Equatable` conformance and skip versioning/dirty marking.
    @discardableResult
    public func set(
        endpoint: EndpointID,
        cluster: ClusterID,
        attribute: AttributeID,
        value: TLVElement
    ) -> Bool {
        var endpointStorage = storage[endpoint] ?? [:]
        var clusterStorage = endpointStorage[cluster] ?? ClusterStorage()

        // No-op detection: skip if value is identical
        if let existing = clusterStorage.attributes[attribute], existing == value {
            return false
        }

        clusterStorage.attributes[attribute] = value
        clusterStorage.dataVersion = DataVersion(rawValue: clusterStorage.dataVersion.rawValue &+ 1)
        clusterStorage.dirtyAttributes.insert(attribute)

        endpointStorage[cluster] = clusterStorage
        storage[endpoint] = endpointStorage
        return true
    }

    /// Mark an attribute as dirty without changing its value.
    ///
    /// Used after command handling to ensure subscription reports are sent even when
    /// the command sets the same value that's already stored (e.g., "On" when already on).
    /// The controller expects a subscription report to confirm every command.
    public func markDirty(endpoint: EndpointID, cluster: ClusterID, attribute: AttributeID) {
        guard var endpointStorage = storage[endpoint],
              var clusterStorage = endpointStorage[cluster] else {
            #if DEBUG
            print("[ATTR-STORE] markDirty GUARD FAILED: ep=\(endpoint.rawValue) cluster=0x\(String(format: "%04X", cluster.rawValue)) attr=0x\(String(format: "%04X", attribute.rawValue)) — endpoint/cluster not in storage")
            #endif
            return
        }
        clusterStorage.dirtyAttributes.insert(attribute)
        endpointStorage[cluster] = clusterStorage
        storage[endpoint] = endpointStorage
    }

    /// Remove all data for an endpoint.
    public func removeEndpoint(_ endpoint: EndpointID) {
        storage.removeValue(forKey: endpoint)
    }

    // MARK: - Dirty Tracking

    /// Get all dirty attribute paths (for subscription reports).
    ///
    /// Returns an `AttributePath` for each attribute that has been modified since the last
    /// call to `clearDirty()`.
    public func dirtyPaths() -> [AttributePath] {
        var paths: [AttributePath] = []
        for (endpointID, clusters) in storage {
            for (clusterID, clusterStorage) in clusters {
                for attributeID in clusterStorage.dirtyAttributes {
                    paths.append(AttributePath(
                        endpointID: endpointID,
                        clusterID: clusterID,
                        attributeID: attributeID
                    ))
                }
            }
        }
        return paths
    }

    /// Clear all dirty flags across all endpoints and clusters.
    public func clearDirty() {
        for endpointID in storage.keys {
            for clusterID in storage[endpointID]!.keys {
                storage[endpointID]![clusterID]!.dirtyAttributes.removeAll()
            }
        }
    }

    /// Clear dirty flags for a specific cluster instance.
    public func clearDirty(endpoint: EndpointID, cluster: ClusterID) {
        storage[endpoint]?[cluster]?.dirtyAttributes.removeAll()
    }

    // MARK: - Persistence

    /// Load attribute values from the attribute store.
    ///
    /// Restores TLV attribute values and data versions from persisted state.
    /// Called during server startup before cluster handlers initialize.
    public func loadFromStore() async throws {
        guard let store = attributeStore else { return }
        guard let stored = try await store.load() else { return }

        for (key, clusterData) in stored.clusters {
            let endpointID = EndpointID(rawValue: key.endpointID)
            let clusterID = ClusterID(rawValue: key.clusterID)

            var clusterStorage = ClusterStorage()
            clusterStorage.dataVersion = DataVersion(rawValue: clusterData.dataVersion)

            for (attrRaw, tlvData) in clusterData.attributes {
                let attrID = AttributeID(rawValue: attrRaw)
                if let decoded = try? TLVDecoder.decode(tlvData) {
                    clusterStorage.attributes[attrID] = decoded.element
                }
            }

            var endpointStorage = storage[endpointID] ?? [:]
            endpointStorage[clusterID] = clusterStorage
            storage[endpointID] = endpointStorage
        }
    }

    /// Save all attribute values to the attribute store.
    ///
    /// Persists TLV attribute values and data versions for all clusters.
    /// Dirty tracking state is NOT persisted (ephemeral).
    public func saveToStore() async {
        guard let store = attributeStore else { return }

        var clusters: [StoredClusterKey: StoredClusterData] = [:]

        for (endpointID, endpointStorage) in storage {
            for (clusterID, clusterStorage) in endpointStorage {
                let key = StoredClusterKey(
                    endpointID: endpointID.rawValue,
                    clusterID: clusterID.rawValue
                )

                var attributes: [UInt32: Data] = [:]
                for (attrID, element) in clusterStorage.attributes {
                    attributes[attrID.rawValue] = TLVEncoder.encode(element)
                }

                clusters[key] = StoredClusterData(
                    dataVersion: clusterStorage.dataVersion.rawValue,
                    attributes: attributes
                )
            }
        }

        let data = StoredAttributeData(clusters: clusters)
        try? await store.save(data)
    }
}
