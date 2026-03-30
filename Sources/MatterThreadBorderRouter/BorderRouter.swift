// BorderRouter.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(OpenThread)

import Foundation
import Logging
import MatterThread
import OpenThread

/// Thread Border Router implementation.
///
/// Bridges Thread mesh traffic to the infrastructure (Ethernet/Wi-Fi) network.
/// Provides IPv6 routing, SRP proxy, DNS proxy, and optional NAT64.
///
/// ```swift
/// let manager = try ThreadNetworkManager(radioURL: "spinel+hdlc+uart:///dev/ttyACM0")
/// try await manager.formNetwork(name: "MyHome")
///
/// let borderRouter = BorderRouter(
///     networkManager: manager,
///     infraInterface: "eth0"
/// )
/// try borderRouter.start()
/// ```
public actor BorderRouter {
    private let networkManager: ThreadNetworkManager
    private let infraInterface: String
    private let logger: Logger

    private var ipv6Routing: IPv6Routing?
    private var srpProxy: SRPProxy?
    private var dnsProxy: DNSProxy?
    private var nat64: NAT64Translator?

    /// Border Router configuration.
    public struct Configuration: Sendable {
        /// Infrastructure network interface (e.g., "eth0", "en0").
        public let infraInterface: String
        /// Enable NAT64 translation (IPv4 access for Thread devices).
        public let enableNAT64: Bool
        /// Enable SRP proxy (advertise Thread services on LAN).
        public let enableSRPProxy: Bool
        /// Enable DNS proxy (forward DNS queries for Thread devices).
        public let enableDNSProxy: Bool

        public init(
            infraInterface: String = "eth0",
            enableNAT64: Bool = true,
            enableSRPProxy: Bool = true,
            enableDNSProxy: Bool = true
        ) {
            self.infraInterface = infraInterface
            self.enableNAT64 = enableNAT64
            self.enableSRPProxy = enableSRPProxy
            self.enableDNSProxy = enableDNSProxy
        }
    }

    private let configuration: Configuration

    public init(
        networkManager: ThreadNetworkManager,
        configuration: Configuration = Configuration(),
        logger: Logger = Logger(label: "matter.thread.br")
    ) {
        self.networkManager = networkManager
        self.infraInterface = configuration.infraInterface
        self.configuration = configuration
        self.logger = logger
    }

    /// Start the border router services.
    public func start() throws {
        let instance = networkManager.threadInstance.instance

        // Enable border routing
        try throwIfError(otBorderRoutingInit(
            instance,
            0,  // Infrastructure interface index (0 = auto)
            true
        ))
        try throwIfError(otBorderRoutingSetEnabled(instance, true))

        // Start component services
        ipv6Routing = IPv6Routing(
            instance: instance,
            infraInterface: infraInterface,
            logger: logger
        )
        try ipv6Routing?.start()

        if configuration.enableSRPProxy {
            srpProxy = SRPProxy(instance: instance, logger: logger)
            try srpProxy?.start()
        }

        if configuration.enableDNSProxy {
            dnsProxy = DNSProxy(instance: instance, logger: logger)
            try dnsProxy?.start()
        }

        if configuration.enableNAT64 {
            nat64 = NAT64Translator(instance: instance, logger: logger)
            try nat64?.start()
        }

        logger.info("Border router started on \(infraInterface)")
    }

    /// Stop the border router services.
    public func stop() throws {
        let instance = networkManager.threadInstance.instance

        nat64?.stop()
        dnsProxy?.stop()
        srpProxy?.stop()
        ipv6Routing?.stop()

        try throwIfError(otBorderRoutingSetEnabled(instance, false))
        logger.info("Border router stopped")
    }

    /// Get border router status.
    public func getStatus() -> BorderRouterStatus {
        let instance = networkManager.threadInstance.instance
        let role = networkManager.threadInstance.getDeviceRole()

        return BorderRouterStatus(
            isRunning: otBorderRoutingGetState(instance) != OT_BORDER_ROUTING_STATE_DISABLED,
            deviceRole: role,
            infraInterface: infraInterface,
            nat64Enabled: configuration.enableNAT64,
            srpProxyEnabled: configuration.enableSRPProxy,
            dnsProxyEnabled: configuration.enableDNSProxy
        )
    }
}

/// Border router operational status.
public struct BorderRouterStatus: Sendable {
    public let isRunning: Bool
    public let deviceRole: ThreadDeviceRole
    public let infraInterface: String
    public let nat64Enabled: Bool
    public let srpProxyEnabled: Bool
    public let dnsProxyEnabled: Bool
}

#endif
