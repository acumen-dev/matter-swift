// MatterLogKey.swift
// Copyright 2026 Monagle Pty Ltd

import Logging
import MatterTransport

/// Stable, namespaced metadata keys on swift-matter's controller log lines; spans use the same
/// names for their attributes. Ids are hex (`0x…`), counters decimal.
public enum MatterLogKey {
    public static let subsystem = "matter.subsystem"
    public static let node = "matter.node"
    public static let session = "matter.session"
    public static let exchange = "matter.exchange"
    public static let protocolID = "matter.protocol"
    public static let opcode = "matter.opcode"
    public static let counter = "matter.counter"
    public static let ack = "matter.ack"
    public static let endpoint = "matter.endpoint"
    public static let cluster = "matter.cluster"
    public static let command = "matter.command"
    public static let attribute = "matter.attribute"
    public static let imStatus = "matter.im_status"
    public static let subscription = "matter.subscription"
    public static let latencyMs = "matter.latency_ms"
    public static let attempt = "matter.attempt"
    public static let reason = "matter.reason"

    public static let all: [String] = [
        subsystem, node, session, exchange, protocolID, opcode, counter, ack, endpoint, cluster,
        command, attribute, imStatus, subscription, latencyMs, attempt, reason,
    ]
}

/// The `matter.subsystem` a line belongs to. A runtime level table can filter on it.
public enum MatterSubsystem: String, Sendable, CaseIterable {
    case messenger, mrp, exchange, session
    case caseHandshake = "case"
    case paseHandshake = "pase"
    case im, subscription, discovery, transport
}

extension Logger {
    /// This logger (same label and handler) with `matter.subsystem` set.
    public func withSubsystem(_ subsystem: MatterSubsystem) -> Logger {
        var logger = self
        logger[metadataKey: MatterLogKey.subsystem] = .string(subsystem.rawValue)
        return logger
    }
}

/// Formatting for `matter.*` metadata values and span attributes.
public enum MatterLogValue {
    public static func hexString<T: BinaryInteger>(_ value: T) -> String {
        "0x" + String(value, radix: 16, uppercase: true)
    }

    public static func hex<T: BinaryInteger>(_ value: T) -> Logger.MetadataValue {
        .string(hexString(value))
    }

    public static func decimal<T: BinaryInteger>(_ value: T) -> Logger.MetadataValue {
        .string(String(value))
    }

    /// Whole milliseconds, truncated.
    public static func milliseconds(_ duration: Duration) -> Int64 {
        let (seconds, attoseconds) = duration.components
        return seconds * 1_000 + attoseconds / 1_000_000_000_000_000
    }

    public static func latency(_ duration: Duration) -> Logger.MetadataValue {
        .string(String(milliseconds(duration)))
    }

    /// `host:port`, with an IPv6 host in brackets.
    public static func address(_ address: MatterAddress) -> String {
        address.host.contains(":") ? "[\(address.host)]:\(address.port)" : "\(address.host):\(address.port)"
    }
}
