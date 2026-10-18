// IMInstrumentation.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Logging
import Tracing
import MatterTypes
import MatterProtocol

// MARK: - IM operation

/// What one public IM call addresses: the metric `kind`, its span name and its log/span fields.
struct IMOperation: Sendable {
    let kind: IMRequestKind
    let nodeID: NodeID
    let endpointID: EndpointID
    let clusterID: ClusterID
    var commandID: CommandID? = nil
    var attributeID: AttributeID? = nil

    var spanName: String {
        switch kind {
        case .invoke, .timed: return "matter.im.invoke"
        case .read: return "matter.im.read"
        case .write: return "matter.im.write"
        }
    }

    var metadata: Logger.Metadata {
        var metadata = Logger.Metadata.node(nodeID)
        metadata[MatterLogKey.endpoint] = MatterLogValue.hex(endpointID.rawValue)
        metadata[MatterLogKey.cluster] = MatterLogValue.hex(clusterID.rawValue)
        if let commandID { metadata[MatterLogKey.command] = MatterLogValue.hex(commandID.rawValue) }
        if let attributeID { metadata[MatterLogKey.attribute] = MatterLogValue.hex(attributeID.rawValue) }
        return metadata
    }

    /// ``metadata`` plus the call's latency and the IM status it ended with, if any.
    func responseMetadata(elapsed: Duration, imStatus: UInt8?) -> Logger.Metadata {
        var metadata = self.metadata
        metadata[MatterLogKey.latencyMs] = MatterLogValue.latency(elapsed)
        if let imStatus { metadata[MatterLogKey.imStatus] = MatterLogValue.hex(imStatus) }
        return metadata
    }

    func annotate(_ span: any Span) {
        span.attributes[MatterLogKey.node] = MatterLogValue.hexString(nodeID.rawValue)
        span.attributes[MatterLogKey.endpoint] = MatterLogValue.hexString(endpointID.rawValue)
        span.attributes[MatterLogKey.cluster] = MatterLogValue.hexString(clusterID.rawValue)
        if let commandID { span.attributes[MatterLogKey.command] = MatterLogValue.hexString(commandID.rawValue) }
        if let attributeID { span.attributes[MatterLogKey.attribute] = MatterLogValue.hexString(attributeID.rawValue) }
        if kind == .timed { span.attributes["matter.timed"] = true }
    }
}

// MARK: - Formatting

/// Rendering of IM paths and values for logs and spans.
enum IMFormat {
    /// Clusters whose command fields or attribute values can carry secrets: Administrator
    /// Commissioning (PAKE verifier, salt), Operational Credentials (IPK in AddNOC), Group Key
    /// Management (epoch keys). Their values are never rendered.
    static let sensitiveClusters: Set<UInt32> = [0x003C, 0x003E, 0x003F]

    /// A decoded TLV value as text; `<redacted>` for a sensitive cluster, `none` for no value.
    static func value(_ value: TLVElement?, clusterID: ClusterID?) -> String {
        if let clusterID, sensitiveClusters.contains(clusterID.rawValue) { return "<redacted>" }
        guard let value else { return "none" }
        return String(describing: value)
    }

    /// `endpoint/cluster/attribute` in hex, `*` for a wildcard.
    static func path(_ path: AttributePath) -> String {
        let endpoint = path.endpointID.map { MatterLogValue.hexString($0.rawValue) } ?? "*"
        let cluster = path.clusterID.map { MatterLogValue.hexString($0.rawValue) } ?? "*"
        let attribute = path.attributeID.map { MatterLogValue.hexString($0.rawValue) } ?? "*"
        return "\(endpoint)/\(cluster)/\(attribute)"
    }

    /// A report entry's path, with its status when the device sent one instead of data.
    static func describe(_ report: AttributeReportIB) -> String {
        if let data = report.attributeData { return path(data.path) }
        if let status = report.attributeStatus {
            return "\(path(status.path)) status \(MatterLogValue.hexString(status.status.status))"
        }
        return "?"
    }
}
