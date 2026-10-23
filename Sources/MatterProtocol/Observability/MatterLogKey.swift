// MatterLogKey.swift
// Copyright 2026 Monagle Pty Ltd

import Logging
import MatterTransport
import MatterTypes

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
    public static let instance = "matter.instance"
    public static let timed = "matter.timed"
    public static let paths = "matter.paths"
    /// The network interface a frame or session's traffic leaves by (`en0`).
    public static let interface = "matter.interface"
    /// The local (source) address of that path.
    public static let localAddress = "matter.local_address"

    public static let all: [String] = [
        subsystem, node, session, exchange, protocolID, opcode, counter, ack, endpoint, cluster,
        command, attribute, imStatus, subscription, latencyMs, attempt, reason, instance, timed, paths,
        interface, localAddress,
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
    /// `0x` plus upper-case hex, no padding: `0xA`, `0x102`.
    public static func hexString<T: BinaryInteger>(_ value: T) -> String {
        MatterHex.string(value)
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

    /// `host:port`, with an IPv6 host in brackets (once: a host that arrived bracketed keeps its one pair).
    public static func address(_ address: MatterAddress) -> String {
        let host = MatterAddress.strippingBrackets(address.host)
        return host.contains(":") ? "[\(host)]:\(address.port)" : "\(host):\(address.port)"
    }
}

// MARK: - Interaction Model values

extension MatterLogValue {
    /// Clusters whose command fields or attribute values can carry secrets or credentials:
    /// Network Commissioning 0x0031 (Wi-Fi credentials, Thread datasets), Administrator
    /// Commissioning 0x003C (PAKE verifier, salt), Operational Credentials 0x003E (IPK in
    /// AddNOC), Group Key Management 0x003F (epoch keys), ICD Management 0x0046 (check-in keys),
    /// Door Lock 0x0101 (PIN and RFID codes), Thread Border Router Management 0x0452 and Thread
    /// Network Directory 0x0453 (operational datasets), Account Login 0x050E (setup PINs).
    /// Their values are never rendered.
    public static let sensitiveClusters: Set<UInt32> = [
        0x0031, 0x003C, 0x003E, 0x003F, 0x0046, 0x0101, 0x0452, 0x0453, 0x050E,
    ]

    /// A decoded TLV value (command fields, an attribute value) as text; `none` for no value.
    /// Fails closed: `<redacted>` for a cluster in ``sensitiveClusters``, and for an unknown
    /// one (a wildcard path) that could be one.
    ///
    /// The renderer for IM values in `matter.*` log lines and spans, including a consumer's own.
    public static func value(_ value: TLVElement?, clusterID: ClusterID?) -> String {
        guard let clusterID, !sensitiveClusters.contains(clusterID.rawValue) else { return "<redacted>" }
        guard let value else { return "none" }
        return String(describing: value)
    }

    /// `endpoint/cluster/attribute` in hex, `*` for a wildcard.
    public static func path(_ path: AttributePath) -> String {
        let endpoint = path.endpointID.map { hexString($0.rawValue) } ?? "*"
        let cluster = path.clusterID.map { hexString($0.rawValue) } ?? "*"
        let attribute = path.attributeID.map { hexString($0.rawValue) } ?? "*"
        return "\(endpoint)/\(cluster)/\(attribute)"
    }

    /// A report entry's path, plus its status for a status entry. Never its value: render that
    /// with ``value(_:clusterID:)``.
    public static func reportEntry(_ report: AttributeReportIB) -> String {
        if let data = report.attributeData { return path(data.path) }
        if let status = report.attributeStatus {
            return "\(path(status.path)) status \(hexString(status.status.status))"
        }
        return "?"
    }
}
