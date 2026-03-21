// EndpointManager.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Logging
import MatterTypes
import MatterModel
import MatterProtocol

/// Manages dynamic endpoints for a Matter node.
///
/// Handles endpoint registration, removal, and PartsList maintenance.
/// Routes incoming IM read/write/invoke requests to the appropriate cluster handlers.
///
/// This class is NOT an actor — it is serialized by its caller (typically the device/bridge actor).
public final class EndpointManager: @unchecked Sendable {

    private var endpoints: [EndpointID: EndpointConfig] = [:]
    private let store: AttributeStore
    private var nextDynamicEndpointRaw: UInt16 = 3  // 0=root, 1=aggregator, 2=reserved
    private let logger = Logger(label: "matter.endpoint-manager")

    /// The aggregator endpoint ID (manages PartsList of dynamic endpoints).
    public static let aggregatorEndpoint = EndpointID(rawValue: 1)

    /// Optional event store for recording cluster events.
    ///
    /// Set this after initialisation to enable event recording when commands are handled.
    public var eventStore: EventStore?

    public init(store: AttributeStore) {
        self.store = store
    }

    // MARK: - Endpoint Registration

    /// Register an endpoint. Writes initial attributes from all cluster handlers to the store.
    ///
    /// After writing initial attributes, the mandatory global attributes (§7.13) are
    /// auto-populated for each cluster:
    /// - `AttributeList` (0xFFFB) — all stored attribute IDs including globals
    /// - `AcceptedCommandList` (0xFFF9) — from handler's `acceptedCommands()`
    /// - `GeneratedCommandList` (0xFFF8) — from handler's `generatedCommands()`
    /// - `FeatureMap` (0xFFFC) — from handler's `featureMap`
    /// - `ClusterRevision` (0xFFFD) — from handler's `clusterRevision`
    ///
    /// The Descriptor cluster's `serverList` attribute is then updated to reflect the
    /// actual registered handler cluster IDs (sorted ascending).
    ///
    /// If this is a dynamic endpoint (not root or aggregator), the aggregator's
    /// Descriptor PartsList is updated to include the new endpoint.
    public func addEndpoint(_ config: EndpointConfig) {
        endpoints[config.endpointID] = config

        // Write initial attributes from each cluster handler
        for handler in config.clusterHandlers {
            for (attrID, value) in handler.initialAttributes() {
                store.set(
                    endpoint: config.endpointID,
                    cluster: handler.clusterID,
                    attribute: attrID,
                    value: value
                )
            }

            // Auto-populate mandatory global attributes (Matter Core Spec §7.13)
            populateGlobalAttributes(for: handler, on: config.endpointID)
        }

        // Validate handlers against cluster specs
        for handler in config.clusterHandlers {
            let result = ClusterValidator.validate(handler: handler)
            for error in result.errors {
                logger.warning("\(error)")
            }
        }

        // Auto-populate the Descriptor serverList from the registered handler cluster IDs.
        // This overwrites any static serverList set by DescriptorHandler.initialAttributes()
        // so that the list always reflects the actual cluster handlers present.
        updateServerClusterList(for: config)

        // Update aggregator PartsList if this isn't the root or aggregator itself
        if config.endpointID != EndpointID(rawValue: 0) && config.endpointID != Self.aggregatorEndpoint {
            updateAggregatorPartsList()
        }
    }

    /// Remove an endpoint and update the aggregator's PartsList.
    public func removeEndpoint(_ endpointID: EndpointID) {
        endpoints.removeValue(forKey: endpointID)
        store.removeEndpoint(endpointID)
        updateAggregatorPartsList()
    }

    /// Allocate the next available dynamic endpoint ID.
    public func nextEndpointID() -> EndpointID {
        let id = EndpointID(rawValue: nextDynamicEndpointRaw)
        nextDynamicEndpointRaw += 1
        return id
    }

    /// Get an endpoint config by ID.
    public func endpoint(for id: EndpointID) -> EndpointConfig? {
        endpoints[id]
    }

    /// All registered endpoint IDs, sorted ascending.
    public func allEndpointIDs() -> [EndpointID] {
        Array(endpoints.keys).sorted { $0.rawValue < $1.rawValue }
    }

    /// Find the cluster handler for a specific (endpoint, cluster) pair.
    ///
    /// Returns `nil` if the endpoint does not exist or the cluster is not registered.
    public func clusterHandler(endpointID: EndpointID, clusterID: ClusterID) -> (any ClusterHandler)? {
        endpoints[endpointID]?.clusterHandlers.first(where: { $0.clusterID == clusterID })
    }

    // MARK: - IM Operations

    /// Read attributes matching the given paths.
    ///
    /// Supports wildcards on all three path components:
    /// - `endpointID: nil` → all endpoints
    /// - `clusterID: nil` → all clusters on the endpoint
    /// - `attributeID: nil` → all attributes in the cluster
    ///
    /// Per the Matter spec, error statuses (unsupportedEndpoint, unsupportedCluster,
    /// unsupportedAttribute) are only returned for targeted (non-wildcard) paths.
    /// Wildcard reads silently skip non-matching entries.
    ///
    /// When `fabricFiltered` is `true` and `fabricIndex` is non-nil, fabric-scoped
    /// attributes (as reported by each cluster's `isFabricScoped(attributeID:)`) are
    /// filtered through `filterFabricScopedAttribute(attributeID:value:fabricIndex:)`.
    ///
    /// When `dataVersionFilters` is non-empty, clusters whose server-side `dataVersion`
    /// matches the client's cached version are silently omitted from the response
    /// (per Matter spec §8.5.1).
    public func readAttributes(
        _ paths: [AttributePath],
        fabricFiltered: Bool = true,
        fabricIndex: FabricIndex? = nil,
        dataVersionFilters: [DataVersionFilter] = []
    ) -> [AttributeReportIB] {
        var reports: [AttributeReportIB] = []

        // Track whether the original path contains any wildcard component.
        // Per the Matter spec, error statuses are only emitted for fully-targeted
        // paths — if any component is a wildcard, non-matching entries are silently skipped.
        for path in paths {
            let isWildcard = path.endpointID == nil || path.clusterID == nil || path.attributeID == nil

            let targetEndpoints: [EndpointID]
            if let ep = path.endpointID {
                targetEndpoints = [ep]
            } else {
                targetEndpoints = allEndpointIDs()
            }

            for endpointID in targetEndpoints {
                guard endpoints[endpointID] != nil else {
                    if !isWildcard {
                        reports.append(AttributeReportIB(attributeStatus: AttributeStatusIB(
                            path: AttributePath(endpointID: endpointID, clusterID: path.clusterID, attributeID: path.attributeID),
                            status: .unsupportedEndpoint
                        )))
                    }
                    continue
                }

                // Determine target clusters
                let targetClusters: [ClusterID]
                if let clusterID = path.clusterID {
                    targetClusters = [clusterID]
                } else {
                    targetClusters = store.allClusterIDs(endpoint: endpointID)
                }

                for clusterID in targetClusters {
                    guard store.hasCluster(endpoint: endpointID, cluster: clusterID) else {
                        if !isWildcard {
                            reports.append(AttributeReportIB(attributeStatus: AttributeStatusIB(
                                path: AttributePath(endpointID: endpointID, clusterID: clusterID, attributeID: path.attributeID),
                                status: .unsupportedCluster
                            )))
                        }
                        continue
                    }

                    // Data version filtering (§8.5.1): if the client's cached dataVersion matches
                    // the server's current dataVersion, skip all attributes for this cluster.
                    if let filter = dataVersionFilters.first(where: { $0.endpointID == endpointID && $0.clusterID == clusterID }) {
                        let currentVersion = store.dataVersion(endpoint: endpointID, cluster: clusterID)
                        if filter.dataVersion == currentVersion.rawValue {
                            continue
                        }
                    }

                    // Resolve the cluster handler once for this (endpoint, cluster) pair — used for fabric filtering.
                    let clusterHandler = endpoints[endpointID]?.clusterHandlers.first(where: { $0.clusterID == clusterID })

                    // Determine target attributes
                    if let attributeID = path.attributeID {
                        // Specific attribute
                        if var value = store.get(endpoint: endpointID, cluster: clusterID, attribute: attributeID) {
                            // Apply fabric-scoped filtering when requested
                            if fabricFiltered, let fi = fabricIndex, let handler = clusterHandler,
                               handler.isFabricScoped(attributeID: attributeID) {
                                value = handler.filterFabricScopedAttribute(attributeID: attributeID, value: value, fabricIndex: fi)
                            }
                            reports.append(AttributeReportIB(attributeData: AttributeDataIB(
                                dataVersion: store.dataVersion(endpoint: endpointID, cluster: clusterID),
                                path: AttributePath(endpointID: endpointID, clusterID: clusterID, attributeID: attributeID),
                                data: value
                            )))
                        } else if !isWildcard {
                            reports.append(AttributeReportIB(attributeStatus: AttributeStatusIB(
                                path: AttributePath(endpointID: endpointID, clusterID: clusterID, attributeID: attributeID),
                                status: .unsupportedAttribute
                            )))
                        }
                    } else {
                        // Wildcard attribute: all attributes in this cluster
                        var allAttrs = store.allAttributes(endpoint: endpointID, cluster: clusterID)
                        // Debug: apply BasicInfo binary search filter at read time
                        if clusterID == ClusterID.basicInformation,
                           let filter = BasicInformationHandler.debugAttributeFilter {
                            allAttrs = allAttrs.filter { attrID, _ in
                                let raw = attrID.rawValue
                                return raw >= 0xFFF8 || filter.contains(raw)
                            }
                        }
                        let dataVersion = store.dataVersion(endpoint: endpointID, cluster: clusterID)
                        for (attributeID, rawValue) in allAttrs {
                            var value = rawValue
                            // Apply fabric-scoped filtering when requested
                            if fabricFiltered, let fi = fabricIndex, let handler = clusterHandler,
                               handler.isFabricScoped(attributeID: attributeID) {
                                value = handler.filterFabricScopedAttribute(attributeID: attributeID, value: value, fabricIndex: fi)
                            }
                            reports.append(AttributeReportIB(attributeData: AttributeDataIB(
                                dataVersion: dataVersion,
                                path: AttributePath(endpointID: endpointID, clusterID: clusterID, attributeID: attributeID),
                                data: value
                            )))
                        }
                    }
                }
            }
        }

        return reports
    }

    /// Process write requests. Returns per-attribute status.
    public func writeAttributes(_ writes: [AttributeDataIB]) -> [AttributeStatusIB] {
        var statuses: [AttributeStatusIB] = []

        for write in writes {
            guard let ep = write.path.endpointID else {
                statuses.append(AttributeStatusIB(path: write.path, status: .invalidAction))
                continue
            }

            guard let clusterID = write.path.clusterID, let attributeID = write.path.attributeID else {
                statuses.append(AttributeStatusIB(path: write.path, status: .invalidAction))
                continue
            }

            guard let config = endpoints[ep] else {
                statuses.append(AttributeStatusIB(path: write.path, status: .unsupportedEndpoint))
                continue
            }

            // Find the cluster handler
            guard let handler = config.clusterHandlers.first(where: { $0.clusterID == clusterID }) else {
                statuses.append(AttributeStatusIB(path: write.path, status: .unsupportedCluster))
                continue
            }

            // Type pre-check against spec metadata (before calling the handler)
            if let spec = ClusterSpecRegistry.spec(for: clusterID),
               let attrSpec = spec.attributes.first(where: { $0.id == attributeID }),
               attrSpec.type != .unknown {
                if case .null = write.data {
                    if !attrSpec.isNullable {
                        statuses.append(AttributeStatusIB(path: write.path, status: StatusIB(status: 0x87)))
                        continue
                    }
                } else if !attrSpec.type.isCompatible(with: write.data) {
                    statuses.append(AttributeStatusIB(path: write.path, status: StatusIB(status: 0x87)))
                    continue
                }
            }

            // Validate the write
            let validation = handler.validateWrite(attributeID: attributeID, value: write.data)
            switch validation {
            case .allowed:
                store.set(endpoint: ep, cluster: clusterID, attribute: attributeID, value: write.data)
                statuses.append(AttributeStatusIB(path: write.path, status: .success))
            case .rejected(let statusCode):
                statuses.append(AttributeStatusIB(path: write.path, status: StatusIB(status: statusCode)))
            }
        }

        return statuses
    }

    /// Handle a command invocation. Routes to the appropriate cluster handler.
    ///
    /// After the command is handled, any events returned by `generatedEvents` are
    /// recorded in `eventStore` (if set). Returns recorded events so the caller can
    /// notify subscriptions.
    ///
    /// Returns `nil` response payload if the endpoint or cluster doesn't exist — the
    /// caller should return an unsupported-endpoint or unsupported-cluster status.
    public func handleCommand(path: CommandPath, fields: TLVElement?) async throws -> (response: TLVElement?, recordedEvents: [StoredEvent]) {
        guard let config = endpoints[path.endpointID] else {
            return (nil, [])
        }

        guard let handler = config.clusterHandlers.first(where: { $0.clusterID == path.clusterID }) else {
            return (nil, [])
        }

        let response = try handler.handleCommand(
            commandID: path.commandID,
            fields: fields,
            store: store,
            endpointID: path.endpointID
        )

        // Collect and record generated events
        let clusterEvents = handler.generatedEvents(
            commandID: path.commandID,
            endpointID: path.endpointID,
            store: store
        )

        var recorded: [StoredEvent] = []
        if let evStore = eventStore, !clusterEvents.isEmpty {
            let timestampMs = UInt64(Date().timeIntervalSince1970 * 1000)
            for clusterEvent in clusterEvents {
                let number = await evStore.record(
                    endpointID: path.endpointID,
                    clusterID: path.clusterID,
                    eventID: clusterEvent.eventID,
                    priority: clusterEvent.priority,
                    timestampMs: timestampMs,
                    data: clusterEvent.data,
                    isUrgent: clusterEvent.isUrgent
                )
                recorded.append(StoredEvent(
                    endpointID: path.endpointID,
                    clusterID: path.clusterID,
                    eventID: clusterEvent.eventID,
                    eventNumber: number,
                    priority: clusterEvent.priority,
                    timestampMs: timestampMs,
                    data: clusterEvent.data,
                    isUrgent: clusterEvent.isUrgent
                ))
            }
        }

        return (response, recorded)
    }

    /// Read events matching the given paths and optional minimum event number.
    ///
    /// Returns an array of `EventReportIB` suitable for inclusion in a `ReportData` message.
    /// If no `eventStore` is configured, returns an empty array.
    ///
    /// - Parameters:
    ///   - paths: Event paths to match (nil fields are wildcards).
    ///   - eventMin: If set, only return events with event number >= this value.
    public func readEvents(_ paths: [EventPath], eventMin: EventNumber? = nil) async -> [EventReportIB] {
        guard let evStore = eventStore else { return [] }
        let events = await evStore.query(paths: paths, eventMin: eventMin)
        return events.map { stored in
            let eventPath = EventPath(
                endpointID: stored.endpointID,
                clusterID: stored.clusterID,
                eventID: stored.eventID
            )
            let data = EventDataIB(
                path: eventPath,
                eventNumber: stored.eventNumber,
                priority: stored.priority,
                epochTimestampMs: stored.timestampMs > 0 ? stored.timestampMs : nil,
                data: stored.data
            )
            return EventReportIB(eventData: data)
        }
    }

    // MARK: - Global Attribute Population

    /// Auto-populate the 5 mandatory global attributes for a cluster handler.
    ///
    /// Per Matter Core Spec §7.13, every cluster instance MUST expose:
    /// - `ClusterRevision` (0xFFFD) — handler's `clusterRevision` (default 1)
    /// - `FeatureMap` (0xFFFC) — handler's `featureMap` (default 0)
    /// - `AcceptedCommandList` (0xFFF9) — handler's `acceptedCommands()`
    /// - `GeneratedCommandList` (0xFFF8) — handler's `generatedCommands()`
    /// - `AttributeList` (0xFFFB) — computed from all stored attribute IDs + globals
    ///
    /// These are written to the store only if NOT already present from `initialAttributes()`,
    /// except `AttributeList` which is always recomputed to include all attributes.
    private func populateGlobalAttributes(for handler: any ClusterHandler, on endpointID: EndpointID) {
        let clusterID = handler.clusterID

        // ClusterRevision — only set if not already provided by initialAttributes()
        if store.get(endpoint: endpointID, cluster: clusterID, attribute: .clusterRevision) == nil {
            store.set(
                endpoint: endpointID,
                cluster: clusterID,
                attribute: .clusterRevision,
                value: .unsignedInt(UInt64(handler.clusterRevision))
            )
        }

        // FeatureMap — only set if not already provided by initialAttributes()
        if store.get(endpoint: endpointID, cluster: clusterID, attribute: .featureMap) == nil {
            store.set(
                endpoint: endpointID,
                cluster: clusterID,
                attribute: .featureMap,
                value: .unsignedInt(UInt64(handler.featureMap))
            )
        }

        // AcceptedCommandList
        let accepted = handler.acceptedCommands()
        store.set(
            endpoint: endpointID,
            cluster: clusterID,
            attribute: .acceptedCommandList,
            value: .array(accepted.map { .unsignedInt(UInt64($0.rawValue)) })
        )

        // GeneratedCommandList
        let generated = handler.generatedCommands()
        store.set(
            endpoint: endpointID,
            cluster: clusterID,
            attribute: .generatedCommandList,
            value: .array(generated.map { .unsignedInt(UInt64($0.rawValue)) })
        )

        // AttributeList — always recomputed. Includes all stored attributes + the globals themselves.
        // Must be computed AFTER the other globals are written.
        let allAttrIDs = store.allAttributes(endpoint: endpointID, cluster: clusterID)
            .map { $0.0 }  // AttributeID

        // Ensure AttributeList itself is included in the list
        var attrIDSet = Set(allAttrIDs)
        attrIDSet.insert(.attributeList)

        let sortedIDs = attrIDSet.sorted { $0.rawValue < $1.rawValue }
        store.set(
            endpoint: endpointID,
            cluster: clusterID,
            attribute: .attributeList,
            value: .array(sortedIDs.map { .unsignedInt(UInt64($0.rawValue)) })
        )
    }

    // MARK: - Internal

    /// Update the aggregator's Descriptor PartsList to reflect current dynamic endpoints.
    private func updateAggregatorPartsList() {
        let dynamicEndpoints = allEndpointIDs().filter {
            $0 != EndpointID(rawValue: 0) && $0 != Self.aggregatorEndpoint
        }
        let partsListValue = TLVElement.array(dynamicEndpoints.map { .unsignedInt(UInt64($0.rawValue)) })
        store.set(
            endpoint: Self.aggregatorEndpoint,
            cluster: .descriptor,
            attribute: DescriptorCluster.Attribute.partsList,
            value: partsListValue
        )
    }

    /// Update the Descriptor cluster's `serverList` attribute for an endpoint to reflect
    /// the actual registered cluster handler IDs (sorted ascending).
    ///
    /// This is called after `addEndpoint` so that the server list is always in sync with
    /// the registered handlers, overriding any static list passed to `DescriptorHandler`.
    private func updateServerClusterList(for config: EndpointConfig) {
        let clusterIDs = config.clusterHandlers
            .map { $0.clusterID.rawValue }
            .sorted()
            .map { TLVElement.unsignedInt(UInt64($0)) }
        store.set(
            endpoint: config.endpointID,
            cluster: .descriptor,
            attribute: DescriptorCluster.Attribute.serverList,
            value: .array(clusterIDs)
        )
    }
}
