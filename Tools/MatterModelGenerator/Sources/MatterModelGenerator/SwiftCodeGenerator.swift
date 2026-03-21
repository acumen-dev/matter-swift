// SwiftCodeGenerator.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

/// Generates Swift source files from parsed cluster and device type definitions.
struct SwiftCodeGenerator {

    /// Cluster names that should NOT be generated because they have hand-written
    /// files with struct types and TLV serialization (Phase 2 candidates).
    static let skipClusters: Set<String> = [
        "Access Control",
        "Basic Information",
        "Bridged Device Basic Information",
        "General Commissioning",
        "Descriptor",
        "Group Key Management",
        "Network Commissioning",
        "Operational Credentials",
        "Administrator Commissioning",   // adminCommissioning in hand-written
    ]

    /// ClusterID property name overrides for backward compatibility with hand-written code.
    /// Maps XML cluster name → desired Swift property name.
    static let clusterIDNameOverrides: [String: String] = [
        "Administrator Commissioning Cluster": "adminCommissioning",
        "Node Operational Credentials Cluster": "operationalCredentials",
        "Smoke CO Alarm Cluster": "smokeCoAlarm",
        "Water Content Measurement Clusters": "relativeHumidityMeasurement",
    ]

    /// Cluster enum name overrides for backward compatibility.
    static let clusterEnumNameOverrides: [String: String] = [
        "Smoke CO Alarm Cluster": "SmokeCOAlarmCluster",
        "Water Content Measurement Clusters": "RelativeHumidityMeasurementCluster",
    ]

    /// DeviceTypeID property name overrides for backward compatibility.
    static let deviceTypeNameOverrides: [String: String] = [
        "Smoke CO Alarm": "smokeCoAlarm",
    ]

    /// Global attribute IDs that are already defined in MatterTypes/Identifiers.swift.
    static let globalAttributeIDs: Set<UInt32> = [
        0xFFF8, // GeneratedCommandList
        0xFFF9, // AcceptedCommandList
        0xFFFA, // EventList
        0xFFFB, // AttributeList
        0xFFFC, // FeatureMap
        0xFFFD, // ClusterRevision
    ]

    /// Hand-written cluster enum name overrides.
    /// Maps XML cluster name (without " Cluster" suffix) → actual Swift enum name.
    static let skipClusterEnumNames: [String: String] = [
        "Access Control": "AccessControlCluster",
        "Basic Information": "BasicInformationCluster",
        "Bridged Device Basic Information": "BridgedDeviceBasicInfoCluster",
        "General Commissioning": "GeneralCommissioningCluster",
        "Descriptor": "DescriptorCluster",
        "Group Key Management": "GroupKeyManagementCluster",
        "Network Commissioning": "NetworkCommissioningCluster",
        "Operational Credentials": "OperationalCredentialsCluster",
        // Administrator Commissioning has no hand-written cluster enum — skip spec generation
    ]

    /// Generates all Swift source files for the given clusters and device types.
    static func generate(
        clusters: [ClusterDefinition],
        deviceTypes: [DeviceTypeDefinition],
        outputDir: URL,
        sourceDir: String
    ) throws {
        let clustersDir = outputDir.appendingPathComponent("Clusters")
        try FileManager.default.createDirectory(at: clustersDir, withIntermediateDirectories: true)

        // Generate individual cluster files
        var generatedClusters: [(id: UInt32, xmlName: String, enumName: String)] = []
        var registryEntries: [(clusterIDProp: String, enumName: String)] = []

        for cluster in clusters.sorted(by: { $0.id < $1.id }) {
            // Skip abstract/template clusters with ID 0
            if cluster.id == 0 { continue }

            // Check if this cluster should be skipped (has hand-written implementation)
            let xmlNameClean = cluster.name.hasSuffix(" Cluster")
                ? String(cluster.name.dropLast(8))
                : cluster.name
            let shouldSkip = Self.skipClusters.contains(cluster.name)
                || Self.skipClusters.contains(xmlNameClean)

            let enumName = clusterEnumNameOverrides[cluster.name]
                ?? NamingConventions.clusterEnumName(from: cluster.name)
            generatedClusters.append((id: cluster.id, xmlName: cluster.name, enumName: enumName))

            // Build the ClusterID property name for the registry
            let clusterIDProp = clusterIDNameOverrides[cluster.name]
                ?? NamingConventions.clusterIDPropertyName(from: cluster.name)

            if shouldSkip {
                // For skipped clusters, generate a separate spec file
                let skipEnumName = skipClusterEnumNames[cluster.name]
                    ?? skipClusterEnumNames[xmlNameClean]
                if let skipEnumName {
                    let specContent = generateSkippedClusterSpec(
                        cluster: cluster, enumName: skipEnumName, sourceDir: sourceDir
                    )
                    let specFileURL = clustersDir.appendingPathComponent(
                        "\(skipEnumName).spec.generated.swift"
                    )
                    try specContent.write(to: specFileURL, atomically: true, encoding: .utf8)
                    registryEntries.append((clusterIDProp: clusterIDProp, enumName: skipEnumName))
                }
                continue
            }

            let content = generateClusterFile(cluster: cluster, enumName: enumName, sourceDir: sourceDir)
            let fileURL = clustersDir.appendingPathComponent(
                NamingConventions.clusterFileName(enumName: enumName)
            )
            try content.write(to: fileURL, atomically: true, encoding: .utf8)
            registryEntries.append((clusterIDProp: clusterIDProp, enumName: enumName))
        }

        // Generate ClusterDefinitions.generated.swift
        let defsContent = generateClusterDefinitions(
            clusters: generatedClusters,
            deviceTypes: deviceTypes
        )
        let defsURL = outputDir.appendingPathComponent("ClusterDefinitions.generated.swift")
        try defsContent.write(to: defsURL, atomically: true, encoding: .utf8)

        // Generate ClusterMetadata.generated.swift
        let metaContent = generateClusterMetadata(entries: registryEntries)
        let metaURL = outputDir.appendingPathComponent("ClusterMetadata.generated.swift")
        try metaContent.write(to: metaURL, atomically: true, encoding: .utf8)
    }

    // MARK: - Cluster File Generation

    private static func generateClusterFile(
        cluster: ClusterDefinition,
        enumName: String,
        sourceDir: String
    ) -> String {
        var lines: [String] = []

        // Header
        lines.append("// \(enumName).generated.swift")
        lines.append("// GENERATED by MatterModelGenerator — DO NOT EDIT")
        lines.append("// Source: connectedhomeip \(sourceDir)")
        lines.append("// Copyright 2026 Monagle Pty Ltd")
        lines.append("")
        lines.append("import MatterTypes")
        lines.append("")

        // Cluster doc comment
        lines.append("/// \(cluster.name) (0x\(hex(cluster.id))), revision \(cluster.revision)")
        lines.append("public enum \(enumName) {")
        lines.append("")

        // Revision
        lines.append("    public static let revision: UInt16 = \(cluster.revision)")

        // Features
        if !cluster.features.isEmpty {
            lines.append("")
            lines.append("    // MARK: - Features")
            lines.append("")
            lines.append("    public struct Feature: OptionSet, Sendable {")
            lines.append("        public let rawValue: UInt32")
            lines.append("        public init(rawValue: UInt32) { self.rawValue = rawValue }")

            for feat in cluster.features {
                let propName = NamingConventions.featurePropertyName(from: feat.name)
                let confDesc = feat.conformance.description
                let summary = confDesc.isEmpty ? feat.summary : "\(feat.summary) — \(confDesc)"
                lines.append("        /// \(summary)")
                lines.append("        public static let \(escaped(propName)) = Feature(rawValue: 1 << \(feat.bit))")
            }
            lines.append("    }")
        }

        // Attributes (excluding global ones, deduplicated by property name)
        let userAttributes = cluster.attributes.filter { !globalAttributeIDs.contains($0.id) }
        if !userAttributes.isEmpty {
            lines.append("")
            lines.append("    // MARK: - Attributes")
            lines.append("")
            lines.append("    public enum Attribute {")
            var seenAttrNames = Set<String>()
            for attr in userAttributes {
                let propName = NamingConventions.propertyName(from: attr.name)
                if seenAttrNames.contains(propName) { continue }
                seenAttrNames.insert(propName)
                let meta = attributeMetadata(attr)
                lines.append("        /// \(attr.name) — \(meta)")
                lines.append("        public static let \(escaped(propName)) = AttributeID(rawValue: 0x\(hex(attr.id)))")
            }
            lines.append("    }")
        }

        // Commands (only commandToServer = client-initiated)
        let clientCommands = cluster.commands.filter { $0.direction == "commandToServer" }
        if !clientCommands.isEmpty {
            lines.append("")
            lines.append("    // MARK: - Commands")
            lines.append("")
            lines.append("    public enum Command {")
            for cmd in clientCommands {
                let propName = NamingConventions.propertyName(from: cmd.name)
                let confDesc = cmd.conformance.description
                let meta = confDesc.isEmpty ? "" : ", \(confDesc)"
                lines.append("        /// \(cmd.name)\(meta)")
                lines.append("        public static let \(escaped(propName)) = CommandID(rawValue: 0x\(hex(cmd.id)))")
            }
            lines.append("    }")
        }

        // Server response commands
        let serverCommands = cluster.commands.filter { $0.direction == "commandToClient" }
        if !serverCommands.isEmpty {
            lines.append("")
            lines.append("    // MARK: - Response Commands")
            lines.append("")
            lines.append("    public enum ResponseCommand {")
            for cmd in serverCommands {
                let propName = NamingConventions.propertyName(from: cmd.name)
                lines.append("        /// \(cmd.name)")
                lines.append("        public static let \(escaped(propName)) = CommandID(rawValue: 0x\(hex(cmd.id)))")
            }
            lines.append("    }")
        }

        // Events
        if !cluster.events.isEmpty {
            lines.append("")
            lines.append("    // MARK: - Events")
            lines.append("")
            lines.append("    public enum Event {")
            for evt in cluster.events {
                let propName = NamingConventions.propertyName(from: evt.name)
                let confDesc = evt.conformance.description
                let meta = confDesc.isEmpty
                    ? "priority: \(evt.priority)"
                    : "priority: \(evt.priority), \(confDesc)"
                lines.append("        /// \(evt.name) — \(meta)")
                lines.append("        public static let \(escaped(propName)) = EventID(rawValue: 0x\(hex(evt.id)))")
            }
            lines.append("    }")
        }

        // Enum datatypes
        for enumDef in cluster.enums {
            lines.append("")
            generateEnum(enumDef, into: &lines)
        }

        // Bitmap datatypes
        for bitmapDef in cluster.bitmaps {
            lines.append("")
            generateBitmap(bitmapDef, into: &lines)
        }

        lines.append("}")
        lines.append("")

        // Generate spec metadata as an extension
        let specLines = generateClusterSpecExtension(cluster: cluster, enumName: enumName)
        lines.append(contentsOf: specLines)

        return lines.joined(separator: "\n")
    }

    // MARK: - Enum Generation

    private static func generateEnum(_ enumDef: EnumDefinition, into lines: inout [String]) {
        // Skip empty enums and enums with spaces in name (e.g., "Status Codes")
        let typeName = sanitizeTypeName(enumDef.name)
        if enumDef.items.isEmpty { return }

        // Determine raw value type from the enum name or values
        let maxValue = enumDef.items.map(\.value).max() ?? 0
        let rawType: String = maxValue > 255 ? "UInt16" : "UInt8"

        // Deduplicate items by value (some specs have duplicate raw values for aliases)
        var seenValues = Set<UInt32>()
        var seenNames = Set<String>()
        var uniqueItems: [EnumItem] = []
        for item in enumDef.items {
            let caseName = NamingConventions.enumCaseName(from: item.name)
            if seenValues.contains(item.value) || seenNames.contains(caseName) { continue }
            seenValues.insert(item.value)
            seenNames.insert(caseName)
            uniqueItems.append(item)
        }

        lines.append("    public enum \(typeName): \(rawType), Sendable, Equatable {")
        for item in uniqueItems {
            let caseName = NamingConventions.enumCaseName(from: item.name)
            lines.append("        case \(escaped(caseName)) = \(item.value)")
        }
        lines.append("    }")
    }

    // MARK: - Bitmap Generation

    private static func generateBitmap(_ bitmapDef: BitmapDefinition, into lines: inout [String]) {
        let typeName = sanitizeTypeName(bitmapDef.name)
        if bitmapDef.bitfields.isEmpty { return }

        // Determine raw value type from max bit
        let maxBit = bitmapDef.bitfields.map(\.bit).max() ?? 0
        let rawType: String
        if maxBit >= 16 {
            rawType = "UInt32"
        } else if maxBit >= 8 {
            rawType = "UInt16"
        } else {
            rawType = "UInt8"
        }

        lines.append("    public struct \(typeName): OptionSet, Sendable {")
        lines.append("        public let rawValue: \(rawType)")
        lines.append("        public init(rawValue: \(rawType)) { self.rawValue = rawValue }")
        for field in bitmapDef.bitfields {
            let propName = NamingConventions.bitmapFieldName(from: field.name)
            lines.append("        public static let \(escaped(propName)) = \(typeName)(rawValue: 1 << \(field.bit))")
        }
        lines.append("    }")
    }

    // MARK: - Cluster Definitions File

    private static func generateClusterDefinitions(
        clusters: [(id: UInt32, xmlName: String, enumName: String)],
        deviceTypes: [DeviceTypeDefinition]
    ) -> String {
        var lines: [String] = []

        lines.append("// ClusterDefinitions.generated.swift")
        lines.append("// GENERATED by MatterModelGenerator — DO NOT EDIT")
        lines.append("// Copyright 2026 Monagle Pty Ltd")
        lines.append("")
        lines.append("import MatterTypes")
        lines.append("")

        // Cluster IDs
        lines.append("// MARK: - Standard Cluster IDs")
        lines.append("")
        lines.append("extension ClusterID {")

        // Calculate max property name length for alignment
        let clusterProps = clusters.map {
            let propName = clusterIDNameOverrides[$0.xmlName]
                ?? NamingConventions.clusterIDPropertyName(from: $0.xmlName)
            return (propName, $0.id)
        }
        let maxLen = clusterProps.map(\.0.count).max() ?? 0

        for (propName, id) in clusterProps {
            let padding = String(repeating: " ", count: max(0, maxLen - propName.count))
            lines.append("    public static let \(escaped(propName))\(padding) = ClusterID(rawValue: 0x\(hex(id)))")
        }
        lines.append("}")

        // Device Type IDs
        if !deviceTypes.isEmpty {
            lines.append("")
            lines.append("// MARK: - Standard Device Type IDs")
            lines.append("")
            lines.append("extension DeviceTypeID {")

            let dtProps = deviceTypes.sorted(by: { $0.id < $1.id })
                .filter { $0.id != 0 }  // Skip abstract device types
                .map {
                    let propName = deviceTypeNameOverrides[$0.name]
                        ?? NamingConventions.deviceTypePropertyName(from: $0.name)
                    return (propName, $0.id)
                }
            let dtMaxLen = dtProps.map(\.0.count).max() ?? 0

            for (propName, id) in dtProps {
                let padding = String(repeating: " ", count: max(0, dtMaxLen - propName.count))
                lines.append("    public static let \(escaped(propName))\(padding) = DeviceTypeID(rawValue: 0x\(hex(id)))")
            }
            lines.append("}")
        }

        lines.append("")
        return lines.joined(separator: "\n")
    }

    // MARK: - Helpers

    /// Sanitizes a type name by removing spaces and making it a valid Swift identifier.
    private static func sanitizeTypeName(_ name: String) -> String {
        if name.contains(" ") || name.contains("/") || name.contains("-") {
            // Split and PascalCase
            let words = name.components(separatedBy: CharacterSet(charactersIn: " /-"))
                .filter { !$0.isEmpty }
            return words.map { $0.prefix(1).uppercased() + $0.dropFirst() }.joined()
        }
        return name
    }

    private static func hex(_ value: UInt32) -> String {
        String(format: "%04X", value)
    }

    private static func attributeMetadata(_ attr: AttributeDefinition) -> String {
        var parts: [String] = []
        parts.append("type: \(attr.type)")
        if attr.isWritable { parts.append("writable") }
        if attr.isNullable { parts.append("nullable") }
        if attr.isScene { parts.append("scene") }
        if let p = attr.persistence, !p.isEmpty { parts.append(p) }
        let confDesc = attr.conformance.description
        if !confDesc.isEmpty { parts.append(confDesc) }
        return parts.joined(separator: ", ")
    }

    /// Escapes Swift keywords used as identifiers.
    private static func escaped(_ name: String) -> String {
        let swiftKeywords: Set<String> = [
            "as", "break", "case", "catch", "class", "continue", "default",
            "defer", "do", "else", "enum", "extension", "fallthrough", "false",
            "for", "func", "guard", "if", "import", "in", "init", "inout",
            "internal", "is", "let", "nil", "operator", "override", "private",
            "protocol", "public", "repeat", "required", "rethrows", "return",
            "self", "Self", "static", "struct", "subscript", "super", "switch",
            "throw", "throws", "true", "try", "typealias", "var", "where", "while",
            // contextual keywords that might conflict
            "Type", "Protocol",
        ]
        if swiftKeywords.contains(name) {
            return "`\(name)`"
        }
        return name
    }

    // MARK: - Cluster Spec Generation

    /// Maps an XML attribute type string to a `MatterAttributeType` Swift expression.
    ///
    /// Handles primitive types, semantic aliases from the Matter spec §7.18.2,
    /// and named types (enums/bitmaps/structs) defined within the cluster.
    /// Falls back to `.unknown` for unresolvable cross-cluster references.
    private static func matterTypeToSwift(_ typeName: String, cluster: ClusterDefinition) -> String {
        let t = typeName.trimmingCharacters(in: .whitespaces)
        guard !t.isEmpty else { return ".unknown" }

        switch t.lowercased() {
        // Boolean
        case "bool":
            return ".bool"

        // Unsigned integers — primitives and semantic aliases
        case "uint8", "enum8", "bitmap8",
             "percent", "action_id", "status":
            return ".uint8"
        case "uint16", "enum16", "bitmap16",
             "percent100ths", "unsignedtemperature",
             "vendor", "vendor_id",
             "group_id", "endpoint_no", "halftime":
            return ".uint16"
        case "uint24":
            return ".uint24"
        case "uint32", "elapsed", "elapsed_s", "utc", "epoch", "epoch_s",
             "event_no", "data_ver", "cluster_id", "devtype_id",
             "bitmap32", "namespace", "tag":
            return ".uint32"
        case "uint64", "node", "node_id",
             "fabric_id", "fabric_idx",
             "eui64", "entry_idx":
            return ".uint64"

        // Signed integers — primitives and semantic aliases
        case "int8":
            return ".int8"
        case "int16",
             "temperature", "signedtemperature", "temperaturedifference":
            return ".int16"
        case "int32":
            return ".int32"
        case "int64",
             "amperage", "amperage_ma",
             "energy", "energy_mwh",
             "voltage", "voltage_mv",
             "power", "power_mw":
            return ".int64"

        // Floating point
        case "single":
            return ".single"
        case "double":
            return ".double"

        // String types
        case "string", "char_string", "long_char_string":
            return ".string"

        // Octet string types — includes IP address types stored as byte arrays
        case "octstr", "octet_string", "long_octet_string",
             "ipv6adr", "ipv6pre", "ipv4adr",
             "hwadr", "ipadr":
            return ".octstr"

        // List / array
        case "list", "datatypelist":
            return ".list"

        default:
            break
        }

        // Named types — resolve from this cluster's parsed data types
        if let enumDef = cluster.enums.first(where: { $0.name == t }) {
            let maxValue = enumDef.items.map(\.value).max() ?? 0
            return maxValue > 255 ? ".uint16" : ".uint8"
        }

        if let bitmapDef = cluster.bitmaps.first(where: { $0.name == t }) {
            let maxBit = bitmapDef.bitfields.map(\.bit).max() ?? 0
            if maxBit >= 16 { return ".uint32" }
            if maxBit >= 8 { return ".uint16" }
            return ".uint8"
        }

        if cluster.structs.contains(where: { $0.name == t }) {
            return ".structure"
        }

        // Cross-cluster reference or unrecognised type — skip type checking
        return ".unknown"
    }

    /// Build a feature code → bit position map for a cluster.
    private static func featureCodeToBit(for cluster: ClusterDefinition) -> [String: Int] {
        var map: [String: Int] = [:]
        for feat in cluster.features {
            map[feat.code] = feat.bit
        }
        return map
    }

    /// Generates `static let spec` extension lines for a generated cluster.
    private static func generateClusterSpecExtension(
        cluster: ClusterDefinition,
        enumName: String
    ) -> [String] {
        var lines: [String] = []
        let featureMap = featureCodeToBit(for: cluster)

        lines.append("// MARK: - Spec Metadata")
        lines.append("")
        lines.append("extension \(enumName) {")
        lines.append("")
        lines.append("    public static let spec = ClusterSpec(")
        lines.append("        clusterID: ClusterID(rawValue: 0x\(hex(cluster.id))),")
        lines.append("        revision: \(cluster.revision),")

        // Attributes (excluding globals)
        let userAttributes = cluster.attributes.filter { !globalAttributeIDs.contains($0.id) }
        lines.append("        attributes: [")
        var seenAttrNames = Set<String>()
        for attr in userAttributes {
            let propName = NamingConventions.propertyName(from: attr.name)
            if seenAttrNames.contains(propName) { continue }
            seenAttrNames.insert(propName)
            let confCode = attr.conformance.toSwiftCode(featureCodeToBit: featureMap)
            let typeCode = matterTypeToSwift(attr.type, cluster: cluster)
            let nullable = attr.isNullable ? "true" : "false"
            lines.append("            AttributeSpec(id: AttributeID(rawValue: 0x\(hex(attr.id))), name: \"\(attr.name)\", conformance: \(confCode), type: \(typeCode), isNullable: \(nullable)),")
        }
        lines.append("        ],")

        // Commands (only commandToServer)
        let clientCommands = cluster.commands.filter { $0.direction == "commandToServer" }
        lines.append("        commands: [")
        for cmd in clientCommands {
            let confCode = cmd.conformance.toSwiftCode(featureCodeToBit: featureMap)
            lines.append("            CommandSpec(id: CommandID(rawValue: 0x\(hex(cmd.id))), name: \"\(cmd.name)\", conformance: \(confCode)),")
        }
        lines.append("        ]")
        lines.append("    )")
        lines.append("}")
        lines.append("")

        return lines
    }

    /// Generates a separate spec file for a skipped (hand-written) cluster.
    private static func generateSkippedClusterSpec(
        cluster: ClusterDefinition,
        enumName: String,
        sourceDir: String
    ) -> String {
        var lines: [String] = []

        lines.append("// \(enumName).spec.generated.swift")
        lines.append("// GENERATED by MatterModelGenerator — DO NOT EDIT")
        lines.append("// Source: connectedhomeip \(sourceDir)")
        lines.append("// Copyright 2026 Monagle Pty Ltd")
        lines.append("")
        lines.append("import MatterTypes")
        lines.append("")

        let specLines = generateClusterSpecExtension(cluster: cluster, enumName: enumName)
        lines.append(contentsOf: specLines)

        return lines.joined(separator: "\n")
    }

    /// Generates the ClusterMetadata.generated.swift registry file.
    private static func generateClusterMetadata(
        entries: [(clusterIDProp: String, enumName: String)]
    ) -> String {
        var lines: [String] = []

        lines.append("// ClusterMetadata.generated.swift")
        lines.append("// GENERATED by MatterModelGenerator — DO NOT EDIT")
        lines.append("// Copyright 2026 Monagle Pty Ltd")
        lines.append("")
        lines.append("import MatterTypes")
        lines.append("")
        lines.append("/// Registry of cluster spec metadata for runtime validation.")
        lines.append("///")
        lines.append("/// Used by `ClusterValidator` to look up mandatory attributes and commands")
        lines.append("/// for a given cluster ID.")
        lines.append("public enum ClusterSpecRegistry {")
        lines.append("")
        lines.append("    /// Returns the spec metadata for a standard cluster, or `nil` for unknown/vendor clusters.")
        lines.append("    public static func spec(for clusterID: ClusterID) -> ClusterSpec? {")
        lines.append("        specs[clusterID]")
        lines.append("    }")
        lines.append("")
        lines.append("    private static let specs: [ClusterID: ClusterSpec] = [")

        for entry in entries {
            lines.append("        .\(escaped(entry.clusterIDProp)): \(entry.enumName).spec,")
        }

        lines.append("    ]")
        lines.append("}")
        lines.append("")

        return lines.joined(separator: "\n")
    }
}
