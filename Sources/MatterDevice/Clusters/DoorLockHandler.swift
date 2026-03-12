// DoorLockHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Cluster handler for the Door Lock cluster (0x0101).
///
/// Handles LockDoor and UnlockDoor commands by updating the `lockState`
/// attribute. Lock state values: 1 = Locked, 2 = Unlocked.
public struct DoorLockHandler: ClusterHandler {

    public let clusterID = ClusterID.doorLock

    /// Called when the lock state changes due to a command. Receives the new lock state value.
    public var onChange: (@Sendable (UInt8) -> Void)?

    public init(onChange: (@Sendable (UInt8) -> Void)? = nil) {
        self.onChange = onChange
    }

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        [
            (DoorLockCluster.Attribute.lockState, .unsignedInt(1)),       // Locked
            (DoorLockCluster.Attribute.lockType, .unsignedInt(0)),        // Deadbolt
            (DoorLockCluster.Attribute.actuatorEnabled, .bool(true)),
        ]
    }

    public func handleCommand(
        commandID: CommandID,
        fields: TLVElement?,
        store: AttributeStore,
        endpointID: EndpointID
    ) throws -> TLVElement? {
        switch commandID {
        case DoorLockCluster.Command.lockDoor:
            store.set(endpoint: endpointID, cluster: clusterID, attribute: DoorLockCluster.Attribute.lockState, value: .unsignedInt(1))
            onChange?(1)

        case DoorLockCluster.Command.unlockDoor:
            store.set(endpoint: endpointID, cluster: clusterID, attribute: DoorLockCluster.Attribute.lockState, value: .unsignedInt(2))
            onChange?(2)

        default:
            break
        }
        return nil
    }
}
