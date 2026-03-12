// BridgedEndpoint.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel
import MatterProtocol

/// A handle to a bridged endpoint within a `MatterBridge`.
///
/// Provides bridge-side setters for common attributes (on/off, level, reachable).
/// Writes via this handle update the `AttributeStore` and notify the
/// `SubscriptionManager` of dirty paths so active subscriptions get reports.
///
/// ```swift
/// let light = bridge.addDimmableLight(name: "Kitchen Pendant")
/// light.setOnOff(true)
/// light.setLevel(200)
/// light.setReachable(false)
/// ```
public final class BridgedEndpoint: @unchecked Sendable {

    /// The endpoint ID of this bridged device.
    public let endpointID: EndpointID

    /// The display name of this bridged device.
    public let name: String

    private let store: AttributeStore
    private let subscriptions: SubscriptionManager

    init(
        endpointID: EndpointID,
        name: String,
        store: AttributeStore,
        subscriptions: SubscriptionManager
    ) {
        self.endpointID = endpointID
        self.name = name
        self.store = store
        self.subscriptions = subscriptions
    }

    // MARK: - OnOff

    /// Set the on/off state from the bridge side.
    public func setOnOff(_ value: Bool) async {
        let changed = store.set(
            endpoint: endpointID,
            cluster: .onOff,
            attribute: OnOffCluster.Attribute.onOff,
            value: .bool(value)
        )
        if changed {
            await notifyChange(cluster: .onOff, attribute: OnOffCluster.Attribute.onOff)
        }
    }

    // MARK: - Level Control

    /// Set the current level from the bridge side.
    public func setLevel(_ value: UInt8) async {
        let changed = store.set(
            endpoint: endpointID,
            cluster: .levelControl,
            attribute: LevelControlCluster.Attribute.currentLevel,
            value: .unsignedInt(UInt64(value))
        )
        if changed {
            await notifyChange(cluster: .levelControl, attribute: LevelControlCluster.Attribute.currentLevel)
        }
    }

    // MARK: - Bridged Device Basic Information

    /// Set the reachable state from the bridge side.
    public func setReachable(_ value: Bool) async {
        let changed = store.set(
            endpoint: endpointID,
            cluster: .bridgedDeviceBasicInformation,
            attribute: BridgedDeviceBasicInfoCluster.Attribute.reachable,
            value: .bool(value)
        )
        if changed {
            await notifyChange(cluster: .bridgedDeviceBasicInformation, attribute: BridgedDeviceBasicInfoCluster.Attribute.reachable)
        }
    }

    // MARK: - Generic

    /// Set an arbitrary attribute value from the bridge side.
    public func set(cluster: ClusterID, attribute: AttributeID, value: TLVElement) async {
        let changed = store.set(
            endpoint: endpointID,
            cluster: cluster,
            attribute: attribute,
            value: value
        )
        if changed {
            await notifyChange(cluster: cluster, attribute: attribute)
        }
    }

    // MARK: - Internal

    private func notifyChange(cluster: ClusterID, attribute: AttributeID) async {
        await subscriptions.attributesChanged([
            AttributePath(endpointID: endpointID, clusterID: cluster, attributeID: attribute)
        ])
    }
}
