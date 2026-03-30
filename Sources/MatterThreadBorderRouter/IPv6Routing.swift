// IPv6Routing.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(OpenThread)

import Foundation
import Logging
import OpenThread

/// Manages IPv6 routing between the Thread mesh and infrastructure network.
///
/// Uses OpenThread's border routing APIs (`otBorderRouting*`) to:
/// - Advertise on-mesh prefixes to Thread devices
/// - Route IPv6 traffic between Thread and infrastructure interfaces
/// - Handle Router Advertisements and prefix delegation
final class IPv6Routing: @unchecked Sendable {
    private let instance: OpaquePointer  // otInstance*
    private let infraInterface: String
    private let logger: Logger

    init(instance: OpaquePointer, infraInterface: String, logger: Logger) {
        self.instance = instance
        self.infraInterface = infraInterface
        self.logger = logger
    }

    func start() throws {
        // The border routing module was initialized and enabled by BorderRouter.
        // Here we configure additional routing parameters.

        // Enable IPv6 forwarding on the instance
        try throwIfError(otIp6SetEnabled(instance, true))

        // Add external route for infrastructure prefix if needed
        // The border routing module handles most of this automatically,
        // but we can add static routes if required.

        logger.info("IPv6 routing started for Thread <-> \(infraInterface)")
    }

    func stop() {
        logger.info("IPv6 routing stopped")
    }

    /// Get the list of prefixes being advertised to the Thread mesh.
    func getOnMeshPrefixes() -> [OnMeshPrefix] {
        var prefixes: [OnMeshPrefix] = []
        var iterator = otNetworkDataIterator()
        var config = otBorderRouterConfig()

        while otBorderRouterGetNextOnMeshPrefix(
            instance, &iterator, &config
        ) == OT_ERROR_NONE {
            prefixes.append(OnMeshPrefix(config: config))
        }

        return prefixes
    }

    /// Add an on-mesh prefix to the Thread network data.
    func addOnMeshPrefix(_ prefix: OnMeshPrefix) throws {
        var config = prefix.toOTConfig()
        try throwIfError(otBorderRouterAddOnMeshPrefix(instance, &config))
        try throwIfError(otBorderRouterRegister(instance))
        logger.info("Added on-mesh prefix: \(prefix.description)")
    }
}

/// An on-mesh prefix advertised to Thread devices.
struct OnMeshPrefix: Sendable, CustomStringConvertible {
    let prefixBytes: Data
    let prefixLength: UInt8
    let isStable: Bool
    let isSLAAC: Bool
    let isDHCP: Bool
    let isDefaultRoute: Bool
    let isOnMesh: Bool
    let preference: Int8

    var description: String {
        let hex = prefixBytes.map { String(format: "%02x", $0) }.joined(separator: ":")
        return "\(hex)/\(prefixLength)"
    }

    init(config: otBorderRouterConfig) {
        var c = config
        self.prefixBytes = withUnsafeBytes(of: &c.mPrefix.mPrefix.mFields.m8) {
            Data($0.prefix(Int(config.mPrefix.mLength + 7) / 8))
        }
        self.prefixLength = config.mPrefix.mLength
        self.isStable = config.mStable
        self.isSLAAC = config.mSlaac
        self.isDHCP = config.mDhcp
        self.isDefaultRoute = config.mDefaultRoute
        self.isOnMesh = config.mOnMesh
        self.preference = config.mPreference
    }

    func toOTConfig() -> otBorderRouterConfig {
        var config = otBorderRouterConfig()
        config.mPrefix.mLength = prefixLength
        prefixBytes.withUnsafeBytes { src in
            withUnsafeMutableBytes(of: &config.mPrefix.mPrefix.mFields.m8) { dst in
                dst.copyMemory(from: UnsafeRawBufferPointer(
                    start: src.baseAddress, count: min(src.count, dst.count)))
            }
        }
        config.mStable = isStable
        config.mSlaac = isSLAAC
        config.mDhcp = isDHCP
        config.mDefaultRoute = isDefaultRoute
        config.mOnMesh = isOnMesh
        config.mPreference = preference
        return config
    }
}

#endif
