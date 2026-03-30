// NAT64Translator.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(OpenThread)

import Foundation
import Logging
import OpenThread

/// Provides NAT64 translation for Thread devices to reach IPv4 hosts.
///
/// Thread devices are IPv6-only. NAT64 translates IPv6 packets with a
/// well-known prefix (e.g., `64:ff9b::/96`) to IPv4, enabling Thread
/// devices to communicate with IPv4-only services on the internet.
final class NAT64Translator: @unchecked Sendable {
    private let instance: OpaquePointer  // otInstance*
    private let logger: Logger

    init(instance: OpaquePointer, logger: Logger) {
        self.instance = instance
        self.logger = logger
    }

    func start() throws {
        // Enable NAT64 via OpenThread's built-in translator
        try throwIfError(otNat64SetEnabled(instance, true))
        logger.info("NAT64 translator started")
    }

    func stop() {
        otNat64SetEnabled(instance, false)
        logger.info("NAT64 translator stopped")
    }

    /// Get NAT64 translation counters.
    func getCounters() -> NAT64Counters {
        var counters = otNat64Counters()
        otNat64GetCounters(instance, &counters)

        return NAT64Counters(
            total4To6Packets: counters.m4To6Packets,
            total4To6Bytes: counters.m4To6Bytes,
            total6To4Packets: counters.m6To4Packets,
            total6To4Bytes: counters.m6To4Bytes
        )
    }
}

/// NAT64 translation statistics.
struct NAT64Counters: Sendable {
    let total4To6Packets: UInt64
    let total4To6Bytes: UInt64
    let total6To4Packets: UInt64
    let total6To4Bytes: UInt64
}

#endif
