// TimeSynchronizationHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Cluster handler for the Time Synchronization cluster (0x0038).
///
/// Provides UTC time tracking and allows controllers to set the node's UTC time
/// via the `SetUTCTime` command. Optional but commonly expected by controllers.
///
/// Attributes `utcTime`, `granularity`, and `timeSource` are updated by the
/// `SetUTCTime` command. All other attributes are read-only.
public struct TimeSynchronizationHandler: ClusterHandler {

    public let clusterID = ClusterID.timeSynchronization

    public init() {}

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        [
            (TimeSynchronizationCluster.Attribute.utcTime, .null),
            (TimeSynchronizationCluster.Attribute.granularity, .unsignedInt(UInt64(TimeSynchronizationCluster.Granularity.noTimeGranularity.rawValue))),
            (TimeSynchronizationCluster.Attribute.timeSource, .unsignedInt(UInt64(TimeSynchronizationCluster.TimeSource.none.rawValue))),
            (TimeSynchronizationCluster.Attribute.trustedTimeSource, .null),
            (TimeSynchronizationCluster.Attribute.defaultNTP, .null),
            (TimeSynchronizationCluster.Attribute.featureMap, .unsignedInt(0)),
            (TimeSynchronizationCluster.Attribute.clusterRevision, .unsignedInt(2)),
        ]
    }

    public func handleCommand(
        commandID: CommandID,
        fields: TLVElement?,
        store: AttributeStore,
        endpointID: EndpointID
    ) throws -> TLVElement? {
        switch commandID {
        case TimeSynchronizationCluster.Command.setUTCTime:
            guard let fields else {
                throw TimeSynchronizationCluster.TimeSynchronizationError.missingField
            }
            let request = try TimeSynchronizationCluster.SetUTCTimeRequest.fromTLVElement(fields)

            // Validate granularity is in range (0-4)
            guard request.granularity.rawValue <= 4 else {
                throw TimeSynchronizationCluster.TimeSynchronizationError.invalidGranularity
            }

            // Write utcTime attribute
            store.set(
                endpoint: endpointID,
                cluster: clusterID,
                attribute: TimeSynchronizationCluster.Attribute.utcTime,
                value: .unsignedInt(request.utcTime)
            )

            // Write granularity attribute
            store.set(
                endpoint: endpointID,
                cluster: clusterID,
                attribute: TimeSynchronizationCluster.Attribute.granularity,
                value: .unsignedInt(UInt64(request.granularity.rawValue))
            )

            // Write timeSource if provided
            if let source = request.timeSource {
                store.set(
                    endpoint: endpointID,
                    cluster: clusterID,
                    attribute: TimeSynchronizationCluster.Attribute.timeSource,
                    value: .unsignedInt(UInt64(source.rawValue))
                )
            }

            return nil

        default:
            return nil
        }
    }
}
