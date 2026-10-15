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
/// Thread-safe: all access to `storage` is serialized by `lock`. The store is shared between
/// the `MatterDeviceServer` actor (IM request handling) and `BridgedEndpoint` callers
/// (bridge-side attribute updates from different actor contexts).
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

    private let lock = NSLock()
    private var storage: [EndpointID: [ClusterID: ClusterStorage]]

    // MARK: - Persistence

    private let attributeStore: (any MatterAttributeStore)?

    /// Serializes cache writes so an older snapshot never lands after a newer one.
    private var persistTail: Task<Void, Never>?

    // MARK: - Init

    public init(attributeStore: (any MatterAttributeStore)? = nil) {
        self.storage = [:]
        self.attributeStore = attributeStore
    }

    // MARK: - Locking

    private func withLock<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }

    // MARK: - Read

    /// Get an attribute value, or `nil` if not stored.
    public func get(endpoint: EndpointID, cluster: ClusterID, attribute: AttributeID) -> TLVElement? {
        withLock { storage[endpoint]?[cluster]?.attributes[attribute] }
    }

    /// Get the current `DataVersion` for a cluster instance.
    ///
    /// Returns a zero-valued `DataVersion` if the cluster has no storage yet.
    public func dataVersion(endpoint: EndpointID, cluster: ClusterID) -> DataVersion {
        withLock { storage[endpoint]?[cluster]?.dataVersion ?? DataVersion(rawValue: 0) }
    }

    /// Get all attributes stored for a cluster instance.
    public func allAttributes(endpoint: EndpointID, cluster: ClusterID) -> [(AttributeID, TLVElement)] {
        withLock {
            guard let clusterStorage = storage[endpoint]?[cluster] else { return [] }
            return clusterStorage.attributes.map { ($0.key, $0.value) }
        }
    }

    /// Check if any data exists for the given endpoint.
    public func hasEndpoint(_ endpoint: EndpointID) -> Bool {
        withLock { storage[endpoint] != nil }
    }

    /// Check if any data exists for the given cluster on the given endpoint.
    public func hasCluster(endpoint: EndpointID, cluster: ClusterID) -> Bool {
        withLock { storage[endpoint]?[cluster] != nil }
    }

    /// All endpoint IDs that have data.
    public func allEndpointIDs() -> [EndpointID] {
        withLock { Array(storage.keys) }
    }

    /// All cluster IDs on an endpoint.
    public func allClusterIDs(endpoint: EndpointID) -> [ClusterID] {
        withLock {
            guard let clusters = storage[endpoint] else { return [] }
            return Array(clusters.keys)
        }
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
        withLock {
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
    }

    /// Mark an attribute as dirty without changing its value.
    ///
    /// Used after command handling to ensure subscription reports are sent even when
    /// the command sets the same value that's already stored (e.g., "On" when already on).
    /// The controller expects a subscription report to confirm every command.
    public func markDirty(endpoint: EndpointID, cluster: ClusterID, attribute: AttributeID) {
        withLock {
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
    }

    /// Remove all data for an endpoint.
    public func removeEndpoint(_ endpoint: EndpointID) {
        withLock { storage.removeValue(forKey: endpoint) }
    }

    // MARK: - Dirty Tracking

    /// Get all dirty attribute paths (for subscription reports).
    ///
    /// Returns an `AttributePath` for each attribute that has been modified since the last
    /// call to `clearDirty()`.
    public func dirtyPaths() -> [AttributePath] {
        withLock {
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
    }

    /// Clear all dirty flags across all endpoints and clusters.
    public func clearDirty() {
        withLock {
            for endpointID in storage.keys {
                for clusterID in storage[endpointID]!.keys {
                    storage[endpointID]![clusterID]!.dirtyAttributes.removeAll()
                }
            }
        }
    }

    /// Clear dirty flags for a specific cluster instance.
    public func clearDirty(endpoint: EndpointID, cluster: ClusterID) {
        withLock { storage[endpoint]?[cluster]?.dirtyAttributes.removeAll() }
    }

    // MARK: - Persistence

    /// Load attribute values from the attribute store.
    ///
    /// Restores every cached cluster's values and data version as saved, whether or
    /// not its endpoint is registered now. `MatterDeviceServer.start()` does not use
    /// this: it restores the cache under the live endpoint set instead.
    public func loadFromStore() async throws {
        guard let store = attributeStore else { return }
        guard let stored = try await store.load() else { return }

        withLock {
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
    }

    /// Read the persisted attribute data without applying it.
    func loadCachedData() async throws -> StoredAttributeData? {
        guard let store = attributeStore else { return nil }
        return try await store.load()
    }

    /// Restore one cluster from the cache, under the live registration.
    ///
    /// The cluster must already be registered. Only attributes the live cluster has are
    /// restored, and those in `liveWins` keep their live values. The cluster takes the
    /// cached `DataVersion`, bumped if its resulting contents differ from what was
    /// cached — a controller holding the cached version must re-read it.
    func restoreCluster(
        endpoint: EndpointID,
        cluster: ClusterID,
        from cached: StoredClusterData,
        liveWins: (AttributeID) -> Bool
    ) {
        var cachedAttributes: [AttributeID: TLVElement] = [:]
        for (raw, tlv) in cached.attributes {
            if let decoded = try? TLVDecoder.decode(tlv) {
                cachedAttributes[AttributeID(rawValue: raw)] = decoded.element
            }
        }

        withLock {
            guard var clusterStorage = storage[endpoint]?[cluster] else { return }
            var restored = clusterStorage.attributes
            for (id, value) in cachedAttributes where restored[id] != nil && !liveWins(id) {
                restored[id] = value
            }

            clusterStorage.dataVersion = DataVersion(rawValue: cached.dataVersion)
            if restored != cachedAttributes {
                clusterStorage.dataVersion = DataVersion(rawValue: cached.dataVersion &+ 1)
                for (id, value) in restored where cachedAttributes[id] != value {
                    clusterStorage.dirtyAttributes.insert(id)
                }
            }
            clusterStorage.attributes = restored
            storage[endpoint]?[cluster] = clusterStorage
        }
    }

    /// Save all attribute values to the attribute store.
    ///
    /// Persists TLV attribute values and data versions for all clusters.
    /// Dirty tracking state is NOT persisted (ephemeral).
    public func saveToStore() async {
        await enqueueSave()?.value
    }

    /// Snapshot the values now and queue their write behind any earlier save.
    ///
    /// For synchronous callers (endpoint-set changes) that cannot await the write.
    @discardableResult
    func enqueueSave() -> Task<Void, Never>? {
        guard let store = attributeStore else { return nil }

        return withLock {
            let data = StoredAttributeData(clusters: snapshotClusters())
            let previous = persistTail
            let write = Task {
                await previous?.value
                try? await store.save(data)
            }
            persistTail = write
            return write
        }
    }

    /// Must be called with `lock` held.
    private func snapshotClusters() -> [StoredClusterKey: StoredClusterData] {
        var result: [StoredClusterKey: StoredClusterData] = [:]
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

                result[key] = StoredClusterData(
                    dataVersion: clusterStorage.dataVersion.rawValue,
                    attributes: attributes
                )
            }
        }
        return result
    }
}
