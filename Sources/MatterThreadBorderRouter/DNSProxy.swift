// DNSProxy.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(OpenThread)

import Foundation
import Logging
import OpenThread

/// Forwards DNS queries from Thread devices to the infrastructure network.
///
/// Thread devices use mesh-local DNS (via the SRP server) for service
/// discovery within the mesh. The DNS proxy enables Thread devices to
/// resolve names on the infrastructure network and the internet.
final class DNSProxy: @unchecked Sendable {
    private let instance: OpaquePointer  // otInstance*
    private let logger: Logger

    init(instance: OpaquePointer, logger: Logger) {
        self.instance = instance
        self.logger = logger
    }

    func start() throws {
        // DNS upstream is handled by the border routing module.
        // OpenThread's DNS proxy forwards queries from Thread devices
        // to the upstream DNS server configured on the infrastructure interface.
        logger.info("DNS proxy started")
    }

    func stop() {
        logger.info("DNS proxy stopped")
    }
}

#endif
