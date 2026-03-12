// EndpointManager.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
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

    /// The aggregator endpoint ID (manages PartsList of dynamic endpoints).
    public static let aggregatorEndpoint = EndpointID(rawValue: 1)

    public init(store: AttributeStore) {
        self.store = store
    }

    // MARK: - Endpoint Registration

    /// Register an endpoint. Writes initial attributes from all cluster handlers to the store.
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
        }

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

    // MARK: - IM Operations

    /// Read attributes matching the given paths.
    ///
    /// Supports wildcard `endpointID` (nil = all endpoints). When a specific endpoint
    /// is requested but doesn't exist, an unsupported-endpoint status is returned.
    /// Wildcard reads silently skip non-matching endpoints (per Matter spec).
    public func readAttributes(_ paths: [AttributePath], fabricFiltered: Bool = true) -> [AttributeReportIB] {
        var reports: [AttributeReportIB] = []

        for path in paths {
            let targetEndpoints: [EndpointID]
            if let ep = path.endpointID {
                targetEndpoints = [ep]
            } else {
                // Wildcard: all endpoints
                targetEndpoints = allEndpointIDs()
            }

            for endpointID in targetEndpoints {
                guard let clusterID = path.clusterID, let attributeID = path.attributeID else {
                    // Wildcard cluster/attribute not yet supported — skip
                    continue
                }

                guard endpoints[endpointID] != nil else {
                    if path.endpointID != nil {
                        // Specific endpoint requested but doesn't exist
                        reports.append(AttributeReportIB(attributeStatus: AttributeStatusIB(
                            path: AttributePath(endpointID: endpointID, clusterID: clusterID, attributeID: attributeID),
                            status: .unsupportedEndpoint
                        )))
                    }
                    continue
                }

                // Check if the cluster exists on this endpoint
                guard store.hasCluster(endpoint: endpointID, cluster: clusterID) else {
                    if path.endpointID != nil {
                        reports.append(AttributeReportIB(attributeStatus: AttributeStatusIB(
                            path: AttributePath(endpointID: endpointID, clusterID: clusterID, attributeID: attributeID),
                            status: .unsupportedCluster
                        )))
                    }
                    continue
                }

                if let value = store.get(endpoint: endpointID, cluster: clusterID, attribute: attributeID) {
                    reports.append(AttributeReportIB(attributeData: AttributeDataIB(
                        dataVersion: store.dataVersion(endpoint: endpointID, cluster: clusterID),
                        path: AttributePath(endpointID: endpointID, clusterID: clusterID, attributeID: attributeID),
                        data: value
                    )))
                } else if path.endpointID != nil {
                    reports.append(AttributeReportIB(attributeStatus: AttributeStatusIB(
                        path: AttributePath(endpointID: endpointID, clusterID: clusterID, attributeID: attributeID),
                        status: .unsupportedAttribute
                    )))
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
    /// Returns `nil` if the endpoint or cluster doesn't exist — the caller should
    /// return an unsupported-endpoint or unsupported-cluster status.
    public func handleCommand(path: CommandPath, fields: TLVElement?) throws -> TLVElement? {
        guard let config = endpoints[path.endpointID] else {
            return nil
        }

        guard let handler = config.clusterHandlers.first(where: { $0.clusterID == path.clusterID }) else {
            return nil
        }

        return try handler.handleCommand(
            commandID: path.commandID,
            fields: fields,
            store: store,
            endpointID: path.endpointID
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
}
