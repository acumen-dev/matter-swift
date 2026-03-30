// SRPProxy.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(OpenThread)

import Foundation
import Logging
import OpenThread

/// Proxies SRP service registrations from Thread devices to the
/// infrastructure network via mDNS.
///
/// Thread devices register services (e.g., Matter `_matterc._udp`) with the
/// SRP server running on the border router. The SRP proxy then advertises
/// these services on the infrastructure network so IP-based controllers
/// (phones, hubs) can discover Thread devices.
final class SRPProxy: @unchecked Sendable {
    private let instance: OpaquePointer  // otInstance*
    private let logger: Logger

    init(instance: OpaquePointer, logger: Logger) {
        self.instance = instance
        self.logger = logger
    }

    func start() throws {
        // Enable the SRP server
        otSrpServerSetAutoEnableMode(instance, true)

        logger.info("SRP proxy started")
    }

    func stop() {
        otSrpServerSetAutoEnableMode(instance, false)
        logger.info("SRP proxy stopped")
    }

    /// Get registered SRP services.
    func getRegisteredServices() -> [SRPServiceInfo] {
        var services: [SRPServiceInfo] = []
        var host = otSrpServerGetNextHost(instance, nil)

        while let h = host {
            let hostName = otSrpServerHostGetFullName(h)
                .map { String(cString: $0) } ?? ""

            var addrCount: UInt8 = 0
            let addrs = otSrpServerHostGetAddresses(h, &addrCount)
            var addresses: [String] = []
            if let addrs {
                for i in 0..<Int(addrCount) {
                    var buf = [CChar](repeating: 0, count: 64)
                    withUnsafePointer(to: addrs[i]) { ptr in
                        otIp6AddressToString(ptr, &buf, 64)
                    }
                    addresses.append(String(cString: buf))
                }
            }

            var svc = otSrpServerHostGetNextService(h, nil)
            while let s = svc {
                let instanceName = otSrpServerServiceGetInstanceName(s)
                    .map { String(cString: $0) } ?? ""
                let serviceName = otSrpServerServiceGetServiceName(s)
                    .map { String(cString: $0) } ?? ""
                let port = otSrpServerServiceGetPort(s)

                services.append(SRPServiceInfo(
                    instanceName: instanceName,
                    serviceName: serviceName,
                    hostName: hostName,
                    port: port,
                    addresses: addresses
                ))

                svc = otSrpServerHostGetNextService(h, s)
            }

            host = otSrpServerGetNextHost(instance, h)
        }

        return services
    }
}

/// Information about a service registered via SRP.
struct SRPServiceInfo: Sendable {
    let instanceName: String
    let serviceName: String
    let hostName: String
    let port: UInt16
    let addresses: [String]
}

#endif
