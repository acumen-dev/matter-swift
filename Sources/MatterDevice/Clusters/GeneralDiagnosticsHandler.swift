// GeneralDiagnosticsHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Cluster handler for the General Diagnostics cluster (0x0033).
///
/// Provides diagnostics information about the node: network interfaces, reboot count,
/// uptime, fault lists, and boot reason. Also handles `TestEventTrigger` (0x00)
/// for certification testing.
///
/// All attributes are read-only. Uptime is computed from `startTime` at init.
public struct GeneralDiagnosticsHandler: ClusterHandler {

    public let clusterID = ClusterID.generalDiagnostics

    private let startTime: Date
    private let networkInterfaceName: String

    public init(startTime: Date = Date(), networkInterfaceName: String = "en0") {
        self.startTime = startTime
        self.networkInterfaceName = networkInterfaceName
    }

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        let iface = GeneralDiagnosticsCluster.NetworkInterface(
            name: networkInterfaceName,
            isOperational: true,
            offPremiseServicesReachableIPv4: nil,
            offPremiseServicesReachableIPv6: nil,
            hardwareAddress: Data(count: 6),
            ipv4Addresses: [],
            ipv6Addresses: [],
            type: .ethernet
        )

        let uptimeSeconds = UInt64(max(0, Date().timeIntervalSince(startTime)))

        return [
            (GeneralDiagnosticsCluster.Attribute.networkInterfaces, .array([iface.toTLVElement()])),
            (GeneralDiagnosticsCluster.Attribute.rebootCount, .unsignedInt(0)),
            (GeneralDiagnosticsCluster.Attribute.upTime, .unsignedInt(uptimeSeconds)),
            (GeneralDiagnosticsCluster.Attribute.bootReason, .unsignedInt(UInt64(GeneralDiagnosticsCluster.BootReasonEnum.powerOnReboot.rawValue))),
            (GeneralDiagnosticsCluster.Attribute.activeHardwareFaults, .array([])),
            (GeneralDiagnosticsCluster.Attribute.activeRadioFaults, .array([])),
            (GeneralDiagnosticsCluster.Attribute.activeNetworkFaults, .array([])),
            (GeneralDiagnosticsCluster.Attribute.testEventTriggersEnabled, .bool(false)),
            (AttributeID.featureMap, .unsignedInt(0)),
            (AttributeID.clusterRevision, .unsignedInt(1)),
        ]
    }

    public func acceptedCommands() -> [CommandID] {
        [GeneralDiagnosticsCluster.Command.testEventTrigger]
    }

    public func handleCommand(
        commandID: CommandID,
        fields: TLVElement?,
        store: AttributeStore,
        endpointID: EndpointID
    ) throws -> TLVElement? {
        switch commandID {
        case GeneralDiagnosticsCluster.Command.testEventTrigger:
            guard let fields else {
                throw GeneralDiagnosticsCluster.GeneralDiagnosticsError.missingField
            }
            let request = try GeneralDiagnosticsCluster.TestEventTriggerRequest.fromTLVElement(fields)

            // Check if test event triggers are enabled
            let enabled = store.get(
                endpoint: endpointID,
                cluster: clusterID,
                attribute: GeneralDiagnosticsCluster.Attribute.testEventTriggersEnabled
            )?.boolValue ?? false

            guard enabled else {
                throw GeneralDiagnosticsCluster.GeneralDiagnosticsError.testEventTriggersNotEnabled
            }

            // Successfully triggered — validate enableKey is 16 bytes
            guard request.enableKey.count == 16 else {
                throw GeneralDiagnosticsCluster.GeneralDiagnosticsError.missingField
            }

            return nil

        default:
            return nil
        }
    }

    // MARK: - Event Factories

    /// Create a BootReason event for this node.
    ///
    /// Should be emitted on device startup to record the reason for booting.
    public func bootReasonEvent(reason: GeneralDiagnosticsCluster.BootReasonEnum) -> ClusterEvent {
        ClusterEvent(
            eventID: GeneralDiagnosticsCluster.Event.bootReason,
            priority: .critical,
            data: .structure([
                TLVElement.TLVField(tag: .contextSpecific(0), value: .unsignedInt(UInt64(reason.rawValue)))
            ]),
            isUrgent: false
        )
    }
}
