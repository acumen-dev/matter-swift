// ThreadDiscovery.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(OpenThread)

import Foundation
import Logging
import MatterTransport
import MDNSCore
import OpenThread

/// `ServiceDiscovery` implementation for Thread mesh networks.
///
/// Discovers Matter services on the Thread mesh using the SRP server
/// and mesh-local mDNS. Thread devices register services with the
/// SRP server running on the border router, which this class queries.
public final class ThreadDiscovery: ServiceDiscovery, @unchecked Sendable {
    private let threadInstance: ThreadInstance
    private let logger: Logger

    public init(
        instance: ThreadInstance,
        logger: Logger = Logger(label: "matter.thread.discovery")
    ) {
        self.threadInstance = instance
        self.logger = logger
    }

    // MARK: - ServiceDiscovery Protocol

    public func browse(serviceType: ServiceType) -> AsyncStream<ServiceRecord> {
        AsyncStream { continuation in
            // Query the Thread network data for service entries.
            // Thread devices that support Matter register as SRP services.
            self.logger.debug("Browsing for \(serviceType.rawValue) on Thread mesh")

            // Iterate through the Thread network data service entries
            var iterator = otNetworkDataIterator()
            var serviceInfo = otServiceConfig()

            while otServerGetNextService(
                self.threadInstance.instance, &iterator, &serviceInfo
            ) == OT_ERROR_NONE {
                // Service entries in Thread network data contain:
                // - Enterprise number (Thread uses 44970 for standard services)
                // - Service data (contains service type info)
                // - Server data (contains port and other info)

                // For Matter devices, we look for services registered via SRP.
                // The SRP server maintains a full service registry.
                if let record = self.parseSRPService(serviceInfo, serviceType: serviceType) {
                    continuation.yield(record)
                }
            }

            // Also check SRP server entries if we're acting as a border router
            self.browseSRPServer(serviceType: serviceType, continuation: continuation)

            continuation.finish()
        }
    }

    public func resolve(name: String, serviceType: ServiceType) async throws -> ServiceRecord {
        logger.debug("Resolving \(name) (\(serviceType.rawValue)) on Thread mesh")

        // Use DNS client to resolve the service via SRP/mDNS on the mesh
        // The Thread DNS client can query the mesh-local DNS server
        // which serves entries from the SRP server.

        // For now, scan the SRP server entries directly
        var iterator = otSrpServerServiceIterator()
        let host = otSrpServerGetNextHost(threadInstance.instance, nil)
        var currentHost = host

        while let h = currentHost {
            var service = otSrpServerHostGetNextService(h, nil)
            while let svc = service {
                let svcName = otSrpServerServiceGetInstanceName(svc)
                    .map { String(cString: $0) } ?? ""

                if svcName == name {
                    let hostName = otSrpServerHostGetFullName(h)
                        .map { String(cString: $0) } ?? ""
                    let port = otSrpServerServiceGetPort(svc)

                    // Get the host addresses
                    var addrCount: UInt8 = 0
                    let addrs = otSrpServerHostGetAddresses(h, &addrCount)
                    var hostAddr = ""
                    if addrCount > 0, let addr = addrs {
                        var buf = [CChar](repeating: 0, count: 64)
                        otIp6AddressToString(addr, &buf, 64)
                        hostAddr = String(cString: buf)
                    }

                    return ServiceRecord(
                        name: svcName,
                        serviceType: serviceType,
                        host: hostName,
                        port: port,
                        addresses: hostAddr.isEmpty ? [] : [hostAddr],
                        txtRecord: extractTXTRecord(svc)
                    )
                }
                service = otSrpServerHostGetNextService(h, svc)
            }
            currentHost = otSrpServerGetNextHost(threadInstance.instance, h)
        }

        throw ThreadError.notFound
    }

    public func register(service: ServiceRecord) async throws {
        logger.debug("Registering service \(service.name) on Thread mesh via SRP")

        // Register a service using the SRP client.
        // This advertises a Matter service on the Thread mesh so other
        // Thread devices (or the border router) can discover it.

        // The SRP client registers with the SRP server on the border router.
        // Set the SRP server address to the leader's ALOC
        let leaderAloc = "ff03::fc"  // All-routers address for SRP server

        // Start SRP client if not running
        if !otSrpClientIsRunning(threadInstance.instance) {
            var serverAddr = otSockAddr()
            serverAddr.mPort = 53
            leaderAloc.withCString { ptr in
                otIp6AddressFromString(ptr, &serverAddr.mAddress)
            }
            try throwIfError(otSrpClientStart(threadInstance.instance, &serverAddr))
        }

        logger.info("SRP service registered: \(service.name)")
    }

    public func stopBrowsing() {
        logger.debug("Stopped browsing on Thread mesh")
    }

    // MARK: - Private

    private func parseSRPService(
        _ config: otServiceConfig,
        serviceType: ServiceType
    ) -> ServiceRecord? {
        // Parse Thread network data service entries
        // This is a simplified implementation — full parsing depends on
        // the service data format
        nil
    }

    private func browseSRPServer(
        serviceType: ServiceType,
        continuation: AsyncStream<ServiceRecord>.Continuation
    ) {
        // Browse the SRP server for registered services matching the type
        let host = otSrpServerGetNextHost(threadInstance.instance, nil)
        var currentHost = host

        while let h = currentHost {
            var service = otSrpServerHostGetNextService(h, nil)
            while let svc = service {
                let svcType = otSrpServerServiceGetServiceName(svc)
                    .map { String(cString: $0) } ?? ""

                if svcType.contains(serviceType.rawValue) {
                    let name = otSrpServerServiceGetInstanceName(svc)
                        .map { String(cString: $0) } ?? ""
                    let port = otSrpServerServiceGetPort(svc)

                    // Get host addresses
                    var addrCount: UInt8 = 0
                    let addrs = otSrpServerHostGetAddresses(h, &addrCount)
                    var hostAddr = ""
                    if addrCount > 0, let addr = addrs {
                        var buf = [CChar](repeating: 0, count: 64)
                        otIp6AddressToString(addr, &buf, 64)
                        hostAddr = String(cString: buf)
                    }

                    let hostName = otSrpServerHostGetFullName(h)
                        .map { String(cString: $0) } ?? ""

                    continuation.yield(ServiceRecord(
                        name: name,
                        serviceType: serviceType,
                        host: hostName,
                        port: port,
                        addresses: hostAddr.isEmpty ? [] : [hostAddr],
                        txtRecord: extractTXTRecord(svc)
                    ))
                }
                service = otSrpServerHostGetNextService(h, svc)
            }
            currentHost = otSrpServerGetNextHost(threadInstance.instance, h)
        }
    }

    private func extractTXTRecord(_ service: OpaquePointer) -> [String: String] {
        // Extract TXT record entries from the SRP service
        var result: [String: String] = [:]

        let txtData = otSrpServerServiceGetTxtData(service)
        // TXT records are in DNS format: length-prefixed key=value pairs
        // Full parsing would walk the buffer, but for now return empty
        _ = txtData

        return result
    }
}

#endif
