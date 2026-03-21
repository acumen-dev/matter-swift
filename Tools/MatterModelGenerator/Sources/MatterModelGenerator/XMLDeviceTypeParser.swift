// XMLDeviceTypeParser.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

/// Parses a CHIP spec XML device type file into a `DeviceTypeDefinition`.
final class XMLDeviceTypeParser: NSObject, XMLParserDelegate {

    private var deviceType: DeviceTypeDefinition?

    private var deviceID: UInt32 = 0
    private var deviceName = ""
    private var deviceRevision = 0
    private var deviceClassification = ""
    private var requiredClusters: [DeviceTypeCluster] = []

    private var elementStack: [String] = []

    // Current cluster being parsed
    private var currentClusterID: UInt32 = 0
    private var currentClusterName = ""
    private var currentClusterSide = ""
    private var inCluster = false

    // Conformance — only set from direct children of <cluster>
    private var clusterConformance: SimpleConformanceBuilder?
    /// Tracks whether the conformance has been set at the cluster level.
    /// Once set, nested conformance tags (inside features/attributes) are ignored.
    private var clusterConformanceSet = false

    // MARK: - Public API

    static func parse(contentsOf url: URL) throws -> DeviceTypeDefinition? {
        let parser = XMLDeviceTypeParser()
        return try parser.parseFile(at: url)
    }

    private func parseFile(at url: URL) throws -> DeviceTypeDefinition? {
        guard let xmlParser = XMLParser(contentsOf: url) else { return nil }
        xmlParser.delegate = self
        xmlParser.parse()
        return deviceType
    }

    // MARK: - XMLParserDelegate

    func parser(_ parser: XMLParser, didStartElement elementName: String,
                namespaceURI: String?, qualifiedName: String?,
                attributes attrs: [String: String]) {

        elementStack.append(elementName)

        switch elementName {
        case "deviceType":
            deviceID = parseHexOrDecimal(attrs["id"] ?? "0")
            deviceName = attrs["name"] ?? ""
            deviceRevision = Int(attrs["revision"] ?? "0") ?? 0

        case "classification":
            if parentElement == "deviceType" {
                deviceClassification = attrs["class"] ?? attrs["scope"] ?? ""
            }

        case "cluster":
            if parentElement == "clusters" {
                inCluster = true
                currentClusterID = parseHexOrDecimal(attrs["id"] ?? "0")
                currentClusterName = attrs["name"] ?? ""
                currentClusterSide = attrs["side"] ?? "server"
                clusterConformance = SimpleConformanceBuilder()
                clusterConformanceSet = false
            }

        case "mandatoryConform":
            // Only set cluster conformance for direct children of <cluster>
            if parentElement == "cluster" && !clusterConformanceSet {
                clusterConformance?.type = .mandatory
                clusterConformanceSet = true
            }
        case "optionalConform":
            if parentElement == "cluster" && !clusterConformanceSet {
                clusterConformance?.type = .optional
                clusterConformanceSet = true
            }
        case "disallowConform":
            if parentElement == "cluster" && !clusterConformanceSet {
                clusterConformance?.type = .disallowed
                clusterConformanceSet = true
            }
        case "otherwiseConform":
            // otherwiseConform (e.g., provisional + optional) — treat as optional
            if parentElement == "cluster" && !clusterConformanceSet {
                clusterConformance?.type = .optional
                clusterConformanceSet = true
            }
        case "provisionalConform":
            if parentElement == "cluster" && !clusterConformanceSet {
                clusterConformance?.type = .optional
                clusterConformanceSet = true
            }

        default:
            break
        }
    }

    func parser(_ parser: XMLParser, didEndElement elementName: String,
                namespaceURI: String?, qualifiedName: String?) {

        defer { elementStack.removeLast() }

        switch elementName {
        case "deviceType":
            deviceType = DeviceTypeDefinition(
                id: deviceID,
                name: deviceName,
                revision: deviceRevision,
                classification: deviceClassification,
                requiredClusters: requiredClusters
            )

        case "cluster":
            if inCluster, parentElement == "clusters" {
                let conf = clusterConformance?.build() ?? .unknown
                requiredClusters.append(DeviceTypeCluster(
                    id: currentClusterID,
                    name: currentClusterName,
                    side: currentClusterSide,
                    conformance: conf
                ))
                clusterConformance = nil
                clusterConformanceSet = false
                inCluster = false
            }

        default:
            break
        }
    }

    // MARK: - Helpers

    private var parentElement: String? {
        guard elementStack.count >= 2 else { return nil }
        return elementStack[elementStack.count - 2]
    }

    private func parseHexOrDecimal(_ string: String) -> UInt32 {
        if string.hasPrefix("0x") || string.hasPrefix("0X") {
            return UInt32(string.dropFirst(2), radix: 16) ?? 0
        }
        return UInt32(string) ?? 0
    }
}

// MARK: - Simple Conformance Builder

private class SimpleConformanceBuilder {
    enum ConformanceType { case mandatory, optional, disallowed, unknown }
    var type: ConformanceType = .unknown

    func build() -> Conformance {
        switch type {
        case .mandatory: return .mandatory
        case .optional: return .optional
        case .disallowed: return .disallowed
        case .unknown: return .unknown
        }
    }
}
