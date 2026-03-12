// GeneralCommissioningHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Cluster handler for the General Commissioning cluster (0x0030).
///
/// Manages the commissioning lifecycle on the device side. Handles ArmFailSafe,
/// SetRegulatoryConfig, and CommissioningComplete commands. The fail-safe timer
/// is tracked in `CommissioningState` (shared with `OperationalCredentialsHandler`).
public struct GeneralCommissioningHandler: ClusterHandler, @unchecked Sendable {

    public let clusterID = GeneralCommissioningCluster.id

    /// Shared commissioning state for fail-safe tracking and credential staging.
    public let commissioningState: CommissioningState

    public init(commissioningState: CommissioningState) {
        self.commissioningState = commissioningState
    }

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        [
            (GeneralCommissioningCluster.Attribute.breadcrumb, .unsignedInt(0)),
            (GeneralCommissioningCluster.Attribute.regulatoryConfig, .unsignedInt(0)),  // Indoor
            (GeneralCommissioningCluster.Attribute.locationCapability, .unsignedInt(2)), // IndoorOutdoor
            (GeneralCommissioningCluster.Attribute.supportsConcurrentConnection, .bool(true)),
        ]
    }

    public func handleCommand(
        commandID: CommandID,
        fields: TLVElement?,
        store: AttributeStore,
        endpointID: EndpointID
    ) throws -> TLVElement? {
        switch commandID {
        case GeneralCommissioningCluster.Command.armFailSafe:
            return try handleArmFailSafe(fields: fields, store: store, endpointID: endpointID)

        case GeneralCommissioningCluster.Command.setRegulatoryConfig:
            return try handleSetRegulatoryConfig(fields: fields, store: store, endpointID: endpointID)

        case GeneralCommissioningCluster.Command.commissioningComplete:
            return handleCommissioningComplete(store: store, endpointID: endpointID)

        default:
            return nil
        }
    }

    // MARK: - ArmFailSafe

    private func handleArmFailSafe(
        fields: TLVElement?,
        store: AttributeStore,
        endpointID: EndpointID
    ) throws -> TLVElement {
        guard let fields else {
            return GeneralCommissioningCluster.ArmFailSafeResponse(
                errorCode: .valueOutsideRange, debugText: "Missing fields"
            ).toTLVElement()
        }

        let request = try GeneralCommissioningCluster.ArmFailSafeRequest.fromTLVElement(fields)

        if request.expiryLengthSeconds == 0 {
            // Disarm: revert any staged state
            commissioningState.disarmFailSafe()
        } else {
            // Arm with expiry
            let expiresAt = Date().addingTimeInterval(TimeInterval(request.expiryLengthSeconds))
            commissioningState.armFailSafe(expiresAt: expiresAt)
        }

        // Update breadcrumb
        store.set(
            endpoint: endpointID,
            cluster: clusterID,
            attribute: GeneralCommissioningCluster.Attribute.breadcrumb,
            value: .unsignedInt(request.breadcrumb)
        )

        return GeneralCommissioningCluster.ArmFailSafeResponse(errorCode: .ok).toTLVElement()
    }

    // MARK: - SetRegulatoryConfig

    private func handleSetRegulatoryConfig(
        fields: TLVElement?,
        store: AttributeStore,
        endpointID: EndpointID
    ) throws -> TLVElement {
        guard let fields else {
            return GeneralCommissioningCluster.SetRegulatoryConfigResponse(
                errorCode: .valueOutsideRange, debugText: "Missing fields"
            ).toTLVElement()
        }

        guard commissioningState.isFailSafeArmed else {
            return GeneralCommissioningCluster.SetRegulatoryConfigResponse(
                errorCode: .noFailSafe, debugText: "Fail-safe not armed"
            ).toTLVElement()
        }

        let request = try GeneralCommissioningCluster.SetRegulatoryConfigRequest.fromTLVElement(fields)

        // Accept the regulatory config
        store.set(
            endpoint: endpointID,
            cluster: clusterID,
            attribute: GeneralCommissioningCluster.Attribute.regulatoryConfig,
            value: .unsignedInt(UInt64(request.newRegulatoryConfig.rawValue))
        )

        // Update breadcrumb
        store.set(
            endpoint: endpointID,
            cluster: clusterID,
            attribute: GeneralCommissioningCluster.Attribute.breadcrumb,
            value: .unsignedInt(request.breadcrumb)
        )

        return GeneralCommissioningCluster.SetRegulatoryConfigResponse(errorCode: .ok).toTLVElement()
    }

    // MARK: - CommissioningComplete

    private func handleCommissioningComplete(
        store: AttributeStore,
        endpointID: EndpointID
    ) -> TLVElement {
        guard commissioningState.isFailSafeArmed else {
            return GeneralCommissioningCluster.CommissioningCompleteResponse(
                errorCode: .noFailSafe, debugText: "Fail-safe not armed"
            ).toTLVElement()
        }

        // Commit all staged state (NOC, RCAC, ACLs)
        commissioningState.commitCommissioning()

        return GeneralCommissioningCluster.CommissioningCompleteResponse(errorCode: .ok).toTLVElement()
    }
}
