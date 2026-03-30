// ThreadNetworkManager.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(OpenThread)

import Foundation
import Logging
import MatterTransport
import OpenThread

/// High-level Thread network management.
///
/// Provides a simplified API for forming, joining, and monitoring Thread
/// networks. Wraps ``ThreadInstance`` with additional state tracking
/// and convenience methods.
///
/// ```swift
/// let manager = try ThreadNetworkManager(
///     radioURL: "spinel+hdlc+uart:///dev/ttyACM0"
/// )
///
/// // Form a new network
/// try await manager.formNetwork(name: "MyHome", channel: 15)
///
/// // Or scan and join an existing one
/// let networks = try await manager.scan()
/// try await manager.joinNetwork(dataset: existingDataset)
///
/// // Monitor state
/// for await state in manager.networkState {
///     print("Role: \(state.role), Neighbors: \(state.neighborCount)")
/// }
/// ```
public actor ThreadNetworkManager {
    /// The underlying OpenThread instance.
    public let threadInstance: ThreadInstance

    /// The Thread transport for Matter communication.
    public let transport: ThreadTransport

    /// The Thread discovery service.
    public let discovery: ThreadDiscovery

    private let logger: Logger
    private var currentDataset: ThreadDataset?

    /// Current network state.
    public struct NetworkState: Sendable {
        public let role: ThreadDeviceRole
        public let networkName: String
        public let channel: UInt16
        public let panID: UInt16
        public let neighborCount: Int
        public let partitionID: UInt32
    }

    /// Initialize with a radio co-processor URL.
    ///
    /// - Parameters:
    ///   - radioURL: Spinel radio URL (e.g., `"spinel+hdlc+uart:///dev/ttyACM0"`).
    ///   - logger: Logger instance.
    public init(
        radioURL: String,
        logger: Logger = Logger(label: "matter.thread.manager")
    ) throws {
        self.logger = logger
        self.threadInstance = try ThreadInstance(radioURL: radioURL, logger: logger)
        self.transport = ThreadTransport(instance: threadInstance, logger: logger)
        self.discovery = ThreadDiscovery(instance: threadInstance, logger: logger)
    }

    /// Form a new Thread network with a random dataset.
    ///
    /// The device will become the Leader of the new network.
    ///
    /// - Parameters:
    ///   - name: Network name (up to 16 characters).
    ///   - channel: IEEE 802.15.4 channel (11-26, default: 15).
    public func formNetwork(name: String = "MatterThread", channel: UInt16 = 15) throws {
        let dataset = ThreadDataset.random(networkName: name, channel: channel)
        try threadInstance.formNetwork(dataset: dataset)
        try threadInstance.start()
        currentDataset = dataset
        logger.info("Formed Thread network: \(name) on channel \(channel)")
    }

    /// Join an existing Thread network.
    ///
    /// - Parameter dataset: The operational dataset from the existing network.
    public func joinNetwork(dataset: ThreadDataset) throws {
        try threadInstance.joinNetwork(dataset: dataset)
        try threadInstance.start()
        currentDataset = dataset
        logger.info("Joining Thread network: \(dataset.networkName)")
    }

    /// Scan for available Thread networks.
    public func scan() async throws -> [ThreadScanResult] {
        try await threadInstance.scan()
    }

    /// Get the current active dataset.
    public func getActiveDataset() throws -> ThreadDataset? {
        try? threadInstance.getActiveDataset()
    }

    /// Get current network information.
    public func getNetworkInfo() -> ThreadNetworkInfo {
        threadInstance.getNetworkInfo()
    }

    /// Get the current device role.
    public func getRole() -> ThreadDeviceRole {
        threadInstance.getDeviceRole()
    }

    /// Get the neighbor table.
    public func getNeighbors() -> [ThreadNeighborInfo] {
        threadInstance.getNeighborTable()
    }

    /// Stream of network state updates.
    ///
    /// Yields a new ``NetworkState`` each time the Thread state changes
    /// (role change, network data update, neighbor added/removed, etc.).
    public var networkState: AsyncStream<NetworkState> {
        AsyncStream { continuation in
            Task {
                for await change in self.threadInstance.stateChanges {
                    let info = self.threadInstance.getNetworkInfo()
                    let neighbors = self.threadInstance.getNeighborTable()

                    continuation.yield(NetworkState(
                        role: info.role,
                        networkName: info.networkName,
                        channel: info.channel,
                        panID: info.panID,
                        neighborCount: neighbors.count,
                        partitionID: info.partitionID
                    ))
                }
                continuation.finish()
            }
        }
    }

    /// Stop the Thread network.
    public func stop() throws {
        try threadInstance.stop()
        logger.info("Thread network stopped")
    }
}

#endif
