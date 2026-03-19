// GeneralCommissioningHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Logging
import MatterTypes
import MatterModel

private let logger = Logger(label: "matter.device.commissioning")

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
        // BasicCommissioningInfoStruct: { 0: failSafeExpiryLengthSeconds, 1: maxCumulativeFailsafeSeconds }
        // Apple Home reads this to choose the ArmFailSafe expiryLengthSeconds.
        // A missing BasicCommissioningInfo causes Apple Home to use expiryLengthSeconds=0, which
        // our handler interprets as a disarm — leaving the fail-safe unarmed for all subsequent steps.
        let basicCommissioningInfo = TLVElement.structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(60)),   // failSafeExpiryLengthSeconds
            .init(tag: .contextSpecific(1), value: .unsignedInt(900)),  // maxCumulativeFailsafeSeconds
        ])

        return [
            (GeneralCommissioningCluster.Attribute.breadcrumb,                .unsignedInt(0)),
            (GeneralCommissioningCluster.Attribute.basicCommissioningInfo,    basicCommissioningInfo),
            (GeneralCommissioningCluster.Attribute.regulatoryConfig,          .unsignedInt(0)),  // Indoor
            (GeneralCommissioningCluster.Attribute.locationCapability,        .unsignedInt(2)),  // IndoorOutdoor
            // true = Concurrent Commissioning Flow (Matter spec §5.5.2).
            //
            // Ethernet bridges are always-on and support concurrent PASE + CASE sessions. With true,
            // Apple Home establishes a CASE session after AddNOC (using the staged fabric) and sends
            // CommissioningComplete over that CASE session. This is the correct mode for bridges.
            //
            // With false (Non-Concurrent Flow), Apple treats the device like a Thread/WiFi node that
            // goes offline after AddNOC. Apple waits for the device to "reconnect" via CASE — which
            // never happens for an Ethernet bridge — so CommissioningComplete is never sent and the
            // commissioning times out after 45 seconds.
            (GeneralCommissioningCluster.Attribute.supportsConcurrentConnection, .bool(true)),
            (GeneralCommissioningCluster.Attribute.clusterRevision, .unsignedInt(1)),
        ]
    }

    public func acceptedCommands() -> [CommandID] {
        [
            GeneralCommissioningCluster.Command.armFailSafe,
            GeneralCommissioningCluster.Command.setRegulatoryConfig,
            GeneralCommissioningCluster.Command.commissioningComplete,
        ]
    }

    public func generatedCommands() -> [CommandID] {
        [
            GeneralCommissioningCluster.Command.armFailSafeResponse,
            GeneralCommissioningCluster.Command.setRegulatoryConfigResponse,
            GeneralCommissioningCluster.Command.commissioningCompleteResponse,
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

    // MARK: - Response Command IDs

    /// Maps request command IDs to their response command IDs per the Matter spec.
    ///
    /// Per spec §11.9.7, each request command has a paired response command with a
    /// distinct ID that MUST appear in the InvokeResponse CommandPath.
    public func responseCommandID(for requestCommandID: CommandID) -> CommandID? {
        switch requestCommandID {
        case GeneralCommissioningCluster.Command.armFailSafe:
            return GeneralCommissioningCluster.Command.armFailSafeResponse
        case GeneralCommissioningCluster.Command.setRegulatoryConfig:
            return GeneralCommissioningCluster.Command.setRegulatoryConfigResponse
        case GeneralCommissioningCluster.Command.commissioningComplete:
            return GeneralCommissioningCluster.Command.commissioningCompleteResponse
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
        logger.debug("ArmFailSafe: expiryLengthSeconds=\(request.expiryLengthSeconds) breadcrumb=\(request.breadcrumb) currentlyArmed=\(commissioningState.isFailSafeArmed)")

        if request.expiryLengthSeconds == 0 {
            // Disarm: revert any staged state
            commissioningState.disarmFailSafe()
            logger.debug("ArmFailSafe: disarmed fail-safe")
        } else {
            // Arm with expiry
            let expiresAt = Date().addingTimeInterval(TimeInterval(request.expiryLengthSeconds))
            commissioningState.armFailSafe(expiresAt: expiresAt)
            logger.debug("ArmFailSafe: armed fail-safe for \(request.expiryLengthSeconds)s, isArmed=\(commissioningState.isFailSafeArmed)")
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
        logger.debug("SetRegulatoryConfig: newRegulatoryConfig=\(request.newRegulatoryConfig) breadcrumb=\(request.breadcrumb)")

        // Validate the requested config is within capability bounds
        let capabilityRaw = store.get(
            endpoint: endpointID,
            cluster: clusterID,
            attribute: GeneralCommissioningCluster.Attribute.locationCapability
        )?.uintValue ?? 2
        let capability = GeneralCommissioningCluster.RegulatoryLocationType(rawValue: UInt8(capabilityRaw))
            ?? .indoorOutdoor
        let requested = request.newRegulatoryConfig
        // IndoorOutdoor capability allows any config; Indoor only allows Indoor;
        // Outdoor only allows Outdoor.
        let configAllowed: Bool
        switch capability {
        case .indoorOutdoor:
            configAllowed = true
        case .indoor:
            configAllowed = (requested == .indoor)
        case .outdoor:
            configAllowed = (requested == .outdoor)
        }
        guard configAllowed else {
            return GeneralCommissioningCluster.SetRegulatoryConfigResponse(
                errorCode: .valueOutsideRange,
                debugText: "Regulatory config outside location capability"
            ).toTLVElement()
        }

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

    // MARK: - Event Generation

    /// GeneralCommissioning cluster does not define any events in the Matter spec.
    /// Previously emitted a bogus "commissioningComplete" event (ID 0x02) which
    /// caused Apple Home to reject subscribe priming reports with InvalidAction.
    public func generatedEvents(commandID: CommandID, endpointID: EndpointID, store: AttributeStore) -> [ClusterEvent] {
        return []
    }

    // MARK: - CommissioningComplete

    private func handleCommissioningComplete(
        store: AttributeStore,
        endpointID: EndpointID
    ) -> TLVElement {
        logger.debug("CommissioningComplete: isFailSafeArmed=\(commissioningState.isFailSafeArmed)")
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
