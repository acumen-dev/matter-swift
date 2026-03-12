// MatterBridge.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel
import MatterProtocol

/// High-level API for a Matter bridge device.
///
/// `MatterBridge` creates a root endpoint (0) and aggregator endpoint (1) at init,
/// then allows dynamic addition/removal of bridged device endpoints. It wraps
/// `EndpointManager`, `AttributeStore`, `SubscriptionManager`, and
/// `InteractionModelHandler` into a single facade.
///
/// ```swift
/// let bridge = MatterBridge(config: .init(
///     vendorName: "Acumen", productName: "Hub",
///     vendorId: 0xFFF1, productId: 0x8000
/// ))
///
/// let light = bridge.addDimmableLight(name: "Kitchen Pendant")
/// await light.setOnOff(true)
/// await light.setLevel(200)
///
/// let responses = try await bridge.handleIM(
///     opcode: .readRequest,
///     payload: requestData,
///     sessionID: 1,
///     fabricIndex: FabricIndex(rawValue: 1)
/// )
/// ```
public final class MatterBridge: @unchecked Sendable {

    // MARK: - Config

    /// Bridge configuration.
    public struct Config: Sendable {
        public let vendorName: String
        public let productName: String
        public let vendorId: UInt16
        public let productId: UInt16

        public init(
            vendorName: String = "SwiftMatter",
            productName: String = "Bridge",
            vendorId: UInt16 = 0xFFF1,
            productId: UInt16 = 0x8000
        ) {
            self.vendorName = vendorName
            self.productName = productName
            self.vendorId = vendorId
            self.productId = productId
        }
    }

    // MARK: - State

    public let config: Config
    public let store: AttributeStore
    public let endpoints: EndpointManager
    public let subscriptions: SubscriptionManager
    private let imHandler: InteractionModelHandler
    private var bridgedEndpoints: [EndpointID: BridgedEndpoint] = [:]

    // MARK: - Init

    public init(config: Config = Config()) {
        self.config = config
        self.store = AttributeStore()
        self.endpoints = EndpointManager(store: store)
        self.subscriptions = SubscriptionManager()
        self.imHandler = InteractionModelHandler(
            endpoints: endpoints,
            subscriptions: subscriptions,
            store: store
        )

        setupRootEndpoint()
        setupAggregatorEndpoint()
    }

    // MARK: - Root + Aggregator Setup

    private func setupRootEndpoint() {
        let rootClusters: [ClusterID] = [.descriptor]
        let root = EndpointConfig(
            endpointID: EndpointID(rawValue: 0),
            deviceTypes: [(.rootNode, 1)],
            clusterHandlers: [
                DescriptorHandler(
                    deviceTypes: [(.rootNode, 1)],
                    serverClusters: rootClusters
                )
            ]
        )
        endpoints.addEndpoint(root)
    }

    private func setupAggregatorEndpoint() {
        let aggClusters: [ClusterID] = [.descriptor]
        let aggregator = EndpointConfig(
            endpointID: EndpointManager.aggregatorEndpoint,
            deviceTypes: [(.aggregator, 1)],
            clusterHandlers: [
                DescriptorHandler(
                    deviceTypes: [(.aggregator, 1)],
                    serverClusters: aggClusters
                )
            ]
        )
        endpoints.addEndpoint(aggregator)
    }

    // MARK: - Add Endpoints

    /// Add a bridged dimmable light (OnOff + LevelControl + BridgedDeviceBasicInfo + Descriptor).
    @discardableResult
    public func addDimmableLight(name: String) -> BridgedEndpoint {
        let epID = endpoints.nextEndpointID()
        let serverClusters: [ClusterID] = [.onOff, .levelControl, .bridgedDeviceBasicInformation, .descriptor]

        let config = EndpointConfig(
            endpointID: epID,
            deviceTypes: [(.bridgedNode, 1), (.dimmableLight, 1)],
            clusterHandlers: [
                OnOffHandler(),
                LevelControlHandler(),
                BridgedDeviceBasicInfoHandler(nodeLabel: name),
                DescriptorHandler(
                    deviceTypes: [(.bridgedNode, 1), (.dimmableLight, 1)],
                    serverClusters: serverClusters
                )
            ]
        )
        endpoints.addEndpoint(config)

        let bridged = BridgedEndpoint(
            endpointID: epID,
            name: name,
            store: store,
            subscriptions: subscriptions
        )
        bridgedEndpoints[epID] = bridged
        return bridged
    }

    /// Add a bridged on/off light (OnOff + BridgedDeviceBasicInfo + Descriptor).
    @discardableResult
    public func addOnOffLight(name: String) -> BridgedEndpoint {
        let epID = endpoints.nextEndpointID()
        let serverClusters: [ClusterID] = [.onOff, .bridgedDeviceBasicInformation, .descriptor]

        let config = EndpointConfig(
            endpointID: epID,
            deviceTypes: [(.bridgedNode, 1), (.onOffLight, 1)],
            clusterHandlers: [
                OnOffHandler(),
                BridgedDeviceBasicInfoHandler(nodeLabel: name),
                DescriptorHandler(
                    deviceTypes: [(.bridgedNode, 1), (.onOffLight, 1)],
                    serverClusters: serverClusters
                )
            ]
        )
        endpoints.addEndpoint(config)

        let bridged = BridgedEndpoint(
            endpointID: epID,
            name: name,
            store: store,
            subscriptions: subscriptions
        )
        bridgedEndpoints[epID] = bridged
        return bridged
    }

    // MARK: - Remove Endpoints

    /// Remove a bridged endpoint.
    public func removeEndpoint(_ endpointID: EndpointID) {
        endpoints.removeEndpoint(endpointID)
        bridgedEndpoints.removeValue(forKey: endpointID)
    }

    /// Remove a bridged endpoint by handle.
    public func removeEndpoint(_ endpoint: BridgedEndpoint) {
        removeEndpoint(endpoint.endpointID)
    }

    // MARK: - IM Handling

    /// Handle an incoming Interaction Model message.
    ///
    /// This is the primary entry point for IM processing. It delegates to the
    /// `InteractionModelHandler` which routes to `EndpointManager` and
    /// `SubscriptionManager` as appropriate.
    public func handleIM(
        opcode: InteractionModelOpcode,
        payload: Data,
        sessionID: UInt16,
        fabricIndex: FabricIndex
    ) async throws -> [(InteractionModelOpcode, Data)] {
        try await imHandler.handleMessage(
            opcode: opcode,
            payload: payload,
            sessionID: sessionID,
            fabricIndex: fabricIndex
        )
    }

    // MARK: - Subscription Reports

    /// Get pending subscription reports.
    public func pendingReports(now: Date = Date()) async -> [PendingReport] {
        await subscriptions.pendingReports(now: now)
    }

    /// Build a ReportData message for a pending subscription report.
    ///
    /// Reads the current values of all subscribed attributes and encodes them
    /// as a ReportData with the subscription ID set.
    public func buildReport(for report: PendingReport) async -> Data? {
        guard let paths = await subscriptions.attributePaths(for: report.subscriptionID) else {
            return nil
        }

        let attributeReports = endpoints.readAttributes(paths, fabricFiltered: true)
        let reportData = ReportData(
            subscriptionID: report.subscriptionID,
            attributeReports: attributeReports,
            suppressResponse: false
        )
        return reportData.tlvEncode()
    }

    /// Mark a report as sent (resets timers).
    public func reportSent(subscriptionID: SubscriptionID, now: Date = Date()) async {
        await subscriptions.reportSent(subscriptionID: subscriptionID, now: now)
    }

    /// Expire stale subscriptions.
    public func expireStale(now: Date = Date()) async -> [SubscriptionID] {
        await subscriptions.expireStale(now: now)
    }

    // MARK: - Accessors

    /// All currently registered bridged endpoints.
    public var allBridgedEndpoints: [BridgedEndpoint] {
        Array(bridgedEndpoints.values)
    }

    /// Get a bridged endpoint by ID.
    public func bridgedEndpoint(for id: EndpointID) -> BridgedEndpoint? {
        bridgedEndpoints[id]
    }
}
