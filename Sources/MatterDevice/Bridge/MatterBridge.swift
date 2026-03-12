// MatterBridge.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel
import MatterCrypto
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
    public let commissioningState: CommissioningState
    private let imHandler: InteractionModelHandler
    private var bridgedEndpoints: [EndpointID: BridgedEndpoint] = [:]

    // MARK: - Init

    public init(config: Config = Config(), commissioningState: CommissioningState? = nil) {
        self.config = config
        self.commissioningState = commissioningState ?? CommissioningState()
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
        let rootClusters: [ClusterID] = [
            .descriptor,
            .basicInformation,
            .generalCommissioning,
            .operationalCredentials,
            .accessControl,
            .adminCommissioning,
        ]
        let root = EndpointConfig(
            endpointID: EndpointID(rawValue: 0),
            deviceTypes: [(.rootNode, 1)],
            clusterHandlers: [
                DescriptorHandler(
                    deviceTypes: [(.rootNode, 1)],
                    serverClusters: rootClusters
                ),
                BasicInformationHandler(
                    vendorName: config.vendorName,
                    vendorID: config.vendorId,
                    productName: config.productName,
                    productID: config.productId
                ),
                GeneralCommissioningHandler(commissioningState: commissioningState),
                OperationalCredentialsHandler(commissioningState: commissioningState),
                AccessControlHandler(commissioningState: commissioningState),
                AdminCommissioningHandler(),
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
        return registerBridgedEndpoint(epID: epID, name: name)
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
        return registerBridgedEndpoint(epID: epID, name: name)
    }

    /// Add a bridged color temperature light (OnOff + LevelControl + ColorControl + BridgedDeviceBasicInfo + Descriptor).
    @discardableResult
    public func addColorTemperatureLight(name: String) -> BridgedEndpoint {
        let epID = endpoints.nextEndpointID()
        let serverClusters: [ClusterID] = [.onOff, .levelControl, .colorControl, .bridgedDeviceBasicInformation, .descriptor]

        let config = EndpointConfig(
            endpointID: epID,
            deviceTypes: [(.bridgedNode, 1), (.colorTemperatureLight, 1)],
            clusterHandlers: [
                OnOffHandler(),
                LevelControlHandler(),
                ColorControlHandler(),
                BridgedDeviceBasicInfoHandler(nodeLabel: name),
                DescriptorHandler(
                    deviceTypes: [(.bridgedNode, 1), (.colorTemperatureLight, 1)],
                    serverClusters: serverClusters
                )
            ]
        )
        endpoints.addEndpoint(config)
        return registerBridgedEndpoint(epID: epID, name: name)
    }

    /// Add a bridged extended color light (OnOff + LevelControl + ColorControl + BridgedDeviceBasicInfo + Descriptor).
    @discardableResult
    public func addExtendedColorLight(name: String) -> BridgedEndpoint {
        let epID = endpoints.nextEndpointID()
        let serverClusters: [ClusterID] = [.onOff, .levelControl, .colorControl, .bridgedDeviceBasicInformation, .descriptor]

        let config = EndpointConfig(
            endpointID: epID,
            deviceTypes: [(.bridgedNode, 1), (.extendedColorLight, 1)],
            clusterHandlers: [
                OnOffHandler(),
                LevelControlHandler(),
                ColorControlHandler(),
                BridgedDeviceBasicInfoHandler(nodeLabel: name),
                DescriptorHandler(
                    deviceTypes: [(.bridgedNode, 1), (.extendedColorLight, 1)],
                    serverClusters: serverClusters
                )
            ]
        )
        endpoints.addEndpoint(config)
        return registerBridgedEndpoint(epID: epID, name: name)
    }

    /// Add a bridged on/off plug-in unit (OnOff + BridgedDeviceBasicInfo + Descriptor).
    @discardableResult
    public func addOnOffPlugInUnit(name: String) -> BridgedEndpoint {
        let epID = endpoints.nextEndpointID()
        let serverClusters: [ClusterID] = [.onOff, .bridgedDeviceBasicInformation, .descriptor]

        let config = EndpointConfig(
            endpointID: epID,
            deviceTypes: [(.bridgedNode, 1), (.onOffPlugInUnit, 1)],
            clusterHandlers: [
                OnOffHandler(),
                BridgedDeviceBasicInfoHandler(nodeLabel: name),
                DescriptorHandler(
                    deviceTypes: [(.bridgedNode, 1), (.onOffPlugInUnit, 1)],
                    serverClusters: serverClusters
                )
            ]
        )
        endpoints.addEndpoint(config)
        return registerBridgedEndpoint(epID: epID, name: name)
    }

    /// Add a bridged thermostat (Thermostat + BridgedDeviceBasicInfo + Descriptor).
    @discardableResult
    public func addThermostat(name: String) -> BridgedEndpoint {
        let epID = endpoints.nextEndpointID()
        let serverClusters: [ClusterID] = [.thermostat, .bridgedDeviceBasicInformation, .descriptor]

        let config = EndpointConfig(
            endpointID: epID,
            deviceTypes: [(.bridgedNode, 1), (.thermostat, 1)],
            clusterHandlers: [
                ThermostatHandler(),
                BridgedDeviceBasicInfoHandler(nodeLabel: name),
                DescriptorHandler(
                    deviceTypes: [(.bridgedNode, 1), (.thermostat, 1)],
                    serverClusters: serverClusters
                )
            ]
        )
        endpoints.addEndpoint(config)
        return registerBridgedEndpoint(epID: epID, name: name)
    }

    /// Add a bridged door lock (DoorLock + BridgedDeviceBasicInfo + Descriptor).
    @discardableResult
    public func addDoorLock(name: String) -> BridgedEndpoint {
        let epID = endpoints.nextEndpointID()
        let serverClusters: [ClusterID] = [.doorLock, .bridgedDeviceBasicInformation, .descriptor]

        let config = EndpointConfig(
            endpointID: epID,
            deviceTypes: [(.bridgedNode, 1), (.doorLock, 1)],
            clusterHandlers: [
                DoorLockHandler(),
                BridgedDeviceBasicInfoHandler(nodeLabel: name),
                DescriptorHandler(
                    deviceTypes: [(.bridgedNode, 1), (.doorLock, 1)],
                    serverClusters: serverClusters
                )
            ]
        )
        endpoints.addEndpoint(config)
        return registerBridgedEndpoint(epID: epID, name: name)
    }

    /// Add a bridged window covering (WindowCovering + BridgedDeviceBasicInfo + Descriptor).
    @discardableResult
    public func addWindowCovering(name: String) -> BridgedEndpoint {
        let epID = endpoints.nextEndpointID()
        let serverClusters: [ClusterID] = [.windowCovering, .bridgedDeviceBasicInformation, .descriptor]

        let config = EndpointConfig(
            endpointID: epID,
            deviceTypes: [(.bridgedNode, 1), (.windowCovering, 1)],
            clusterHandlers: [
                WindowCoveringHandler(),
                BridgedDeviceBasicInfoHandler(nodeLabel: name),
                DescriptorHandler(
                    deviceTypes: [(.bridgedNode, 1), (.windowCovering, 1)],
                    serverClusters: serverClusters
                )
            ]
        )
        endpoints.addEndpoint(config)
        return registerBridgedEndpoint(epID: epID, name: name)
    }

    /// Add a bridged fan (FanControl + BridgedDeviceBasicInfo + Descriptor).
    @discardableResult
    public func addFan(name: String) -> BridgedEndpoint {
        let epID = endpoints.nextEndpointID()
        let serverClusters: [ClusterID] = [.fanControl, .bridgedDeviceBasicInformation, .descriptor]

        let config = EndpointConfig(
            endpointID: epID,
            deviceTypes: [(.bridgedNode, 1), (.fan, 1)],
            clusterHandlers: [
                FanControlHandler(),
                BridgedDeviceBasicInfoHandler(nodeLabel: name),
                DescriptorHandler(
                    deviceTypes: [(.bridgedNode, 1), (.fan, 1)],
                    serverClusters: serverClusters
                )
            ]
        )
        endpoints.addEndpoint(config)
        return registerBridgedEndpoint(epID: epID, name: name)
    }

    /// Add a bridged contact sensor (BooleanState + BridgedDeviceBasicInfo + Descriptor).
    @discardableResult
    public func addContactSensor(name: String) -> BridgedEndpoint {
        let epID = endpoints.nextEndpointID()
        let serverClusters: [ClusterID] = [.booleanState, .bridgedDeviceBasicInformation, .descriptor]

        let config = EndpointConfig(
            endpointID: epID,
            deviceTypes: [(.bridgedNode, 1), (.contactSensor, 1)],
            clusterHandlers: [
                BooleanStateHandler(),
                BridgedDeviceBasicInfoHandler(nodeLabel: name),
                DescriptorHandler(
                    deviceTypes: [(.bridgedNode, 1), (.contactSensor, 1)],
                    serverClusters: serverClusters
                )
            ]
        )
        endpoints.addEndpoint(config)
        return registerBridgedEndpoint(epID: epID, name: name)
    }

    /// Add a bridged occupancy sensor (OccupancySensing + BridgedDeviceBasicInfo + Descriptor).
    @discardableResult
    public func addOccupancySensor(name: String) -> BridgedEndpoint {
        let epID = endpoints.nextEndpointID()
        let serverClusters: [ClusterID] = [.occupancySensing, .bridgedDeviceBasicInformation, .descriptor]

        let config = EndpointConfig(
            endpointID: epID,
            deviceTypes: [(.bridgedNode, 1), (.occupancySensor, 1)],
            clusterHandlers: [
                OccupancySensingHandler(),
                BridgedDeviceBasicInfoHandler(nodeLabel: name),
                DescriptorHandler(
                    deviceTypes: [(.bridgedNode, 1), (.occupancySensor, 1)],
                    serverClusters: serverClusters
                )
            ]
        )
        endpoints.addEndpoint(config)
        return registerBridgedEndpoint(epID: epID, name: name)
    }

    /// Add a bridged temperature sensor (TemperatureMeasurement + BridgedDeviceBasicInfo + Descriptor).
    @discardableResult
    public func addTemperatureSensor(name: String) -> BridgedEndpoint {
        let epID = endpoints.nextEndpointID()
        let serverClusters: [ClusterID] = [.temperatureMeasurement, .bridgedDeviceBasicInformation, .descriptor]

        let config = EndpointConfig(
            endpointID: epID,
            deviceTypes: [(.bridgedNode, 1), (.temperatureSensor, 1)],
            clusterHandlers: [
                TemperatureMeasurementHandler(),
                BridgedDeviceBasicInfoHandler(nodeLabel: name),
                DescriptorHandler(
                    deviceTypes: [(.bridgedNode, 1), (.temperatureSensor, 1)],
                    serverClusters: serverClusters
                )
            ]
        )
        endpoints.addEndpoint(config)
        return registerBridgedEndpoint(epID: epID, name: name)
    }

    /// Add a bridged humidity sensor (RelativeHumidityMeasurement + BridgedDeviceBasicInfo + Descriptor).
    @discardableResult
    public func addHumiditySensor(name: String) -> BridgedEndpoint {
        let epID = endpoints.nextEndpointID()
        let serverClusters: [ClusterID] = [.relativeHumidityMeasurement, .bridgedDeviceBasicInformation, .descriptor]

        let config = EndpointConfig(
            endpointID: epID,
            deviceTypes: [(.bridgedNode, 1), (.humiditySensor, 1)],
            clusterHandlers: [
                RelativeHumidityMeasurementHandler(),
                BridgedDeviceBasicInfoHandler(nodeLabel: name),
                DescriptorHandler(
                    deviceTypes: [(.bridgedNode, 1), (.humiditySensor, 1)],
                    serverClusters: serverClusters
                )
            ]
        )
        endpoints.addEndpoint(config)
        return registerBridgedEndpoint(epID: epID, name: name)
    }

    /// Add a bridged light sensor (IlluminanceMeasurement + BridgedDeviceBasicInfo + Descriptor).
    @discardableResult
    public func addLightSensor(name: String) -> BridgedEndpoint {
        let epID = endpoints.nextEndpointID()
        let serverClusters: [ClusterID] = [.illuminanceMeasurement, .bridgedDeviceBasicInformation, .descriptor]

        let config = EndpointConfig(
            endpointID: epID,
            deviceTypes: [(.bridgedNode, 1), (.lightSensor, 1)],
            clusterHandlers: [
                IlluminanceMeasurementHandler(),
                BridgedDeviceBasicInfoHandler(nodeLabel: name),
                DescriptorHandler(
                    deviceTypes: [(.bridgedNode, 1), (.lightSensor, 1)],
                    serverClusters: serverClusters
                )
            ]
        )
        endpoints.addEndpoint(config)
        return registerBridgedEndpoint(epID: epID, name: name)
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

    // MARK: - Internal

    private func registerBridgedEndpoint(epID: EndpointID, name: String) -> BridgedEndpoint {
        let bridged = BridgedEndpoint(
            endpointID: epID,
            name: name,
            store: store,
            subscriptions: subscriptions
        )
        bridgedEndpoints[epID] = bridged
        return bridged
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
