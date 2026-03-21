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

    /// Struct/command type names that conflict with hand-written extensions.
    /// Maps cluster XML name (without " Cluster" suffix) → set of type names to skip.
    static let skipGeneratedTypes: [String: Set<String>] = [
        "General Diagnostics": ["TestEventTriggerRequest", "NetworkInterface"],
        "Time Synchronization": ["SetUTCTimeRequest"],
        "Groups": ["ResponseCommand"],
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

        // Generate DeviceTypeRegistry.generated.swift
        if !deviceTypes.isEmpty {
            let dtDir = outputDir.appendingPathComponent("DeviceTypes")
            try FileManager.default.createDirectory(at: dtDir, withIntermediateDirectories: true)

            // Build a cluster name → ClusterID property name lookup from all parsed clusters
            var clusterNameToIDProp: [String: String] = [:]
            for cluster in clusters {
                let xmlNameClean = cluster.name.hasSuffix(" Cluster")
                    ? String(cluster.name.dropLast(8))
                    : cluster.name
                let propName = clusterIDNameOverrides[cluster.name]
                    ?? NamingConventions.clusterIDPropertyName(from: cluster.name)
                clusterNameToIDProp[cluster.name] = propName
                clusterNameToIDProp[xmlNameClean] = propName
            }

            let dtContent = generateDeviceTypeRegistry(
                deviceTypes: deviceTypes,
                clusterNameToIDProp: clusterNameToIDProp
            )
            let dtURL = dtDir.appendingPathComponent("DeviceTypeRegistry.generated.swift")
            try dtContent.write(to: dtURL, atomically: true, encoding: .utf8)
        }
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
        lines.append("import Foundation")
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
        // Determine which types to skip (hand-written conflicts) - need early for ResponseCommand
        let xmlNameCleanEarly = cluster.name.hasSuffix(" Cluster")
            ? String(cluster.name.dropLast(8))
            : cluster.name
        let skipTypesEarly = skipGeneratedTypes[cluster.name] ?? skipGeneratedTypes[xmlNameCleanEarly] ?? []

        let serverCommands = cluster.commands.filter { $0.direction == "commandToClient" || $0.direction == "responseFromServer" }
        if !serverCommands.isEmpty && !skipTypesEarly.contains("ResponseCommand") {
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

        // Determine which types to skip (hand-written conflicts)
        let xmlNameClean = cluster.name.hasSuffix(" Cluster")
            ? String(cluster.name.dropLast(8))
            : cluster.name
        let skipTypes = skipGeneratedTypes[cluster.name] ?? skipGeneratedTypes[xmlNameClean] ?? []

        // Struct datatypes
        for structDef in cluster.structs {
            let typeName = sanitizeTypeName(structDef.name)
            if skipTypes.contains(typeName) { continue }
            lines.append("")
            generateStructType(structDef, cluster: cluster, into: &lines)
        }

        // Command request/response structs
        for cmd in cluster.commands {
            let structName = NamingConventions.commandStructName(from: cmd.name, direction: cmd.direction)
            if skipTypes.contains(structName) { continue }
            generateCommandStruct(cmd, cluster: cluster, into: &lines)
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

    // MARK: - Swift Type Mapping

    /// Maps an XML type string to a Swift type name for struct properties.
    ///
    /// Returns the Swift type string, without Optional wrapping.
    /// The caller is responsible for appending `?` when `isNullable` or `isOptional`.
    private static func swiftFieldType(
        _ xmlType: String?,
        cluster: ClusterDefinition,
        isNullable: Bool,
        isOptional: Bool,
        listElementType: String? = nil
    ) -> String {
        guard let xmlType, !xmlType.isEmpty else {
            let base = "TLVElement"
            return (isNullable || isOptional) ? "\(base)?" : base
        }

        let base: String
        switch xmlType.lowercased() {
        case "bool":
            base = "Bool"
        case "uint8", "enum8", "bitmap8", "percent", "action_id", "status":
            base = "UInt8"
        case "uint16", "enum16", "bitmap16", "percent100ths",
             "vendor", "vendor_id", "group_id", "endpoint_no":
            base = "UInt16"
        case "uint32", "bitmap32", "epoch_s", "elapsed_s", "elapsed",
             "utc", "epoch", "event_no", "data_ver",
             "cluster_id", "devtype_id":
            base = "UInt32"
        case "uint64", "node_id", "node", "fabric_id", "fabric_idx",
             "eui64", "entry_idx":
            base = "UInt64"
        case "int8":
            base = "Int8"
        case "int16", "temperature", "signedtemperature", "temperaturedifference":
            base = "Int16"
        case "int32":
            base = "Int32"
        case "int64", "amperage", "amperage_ma", "energy", "energy_mwh",
             "voltage", "voltage_mv", "power", "power_mw":
            base = "Int64"
        case "string", "char_string", "long_char_string":
            base = "String"
        case "octstr", "octet_string", "long_octet_string",
             "ipv6adr", "ipv6pre", "ipv4adr", "hwadr", "ipadr":
            base = "Data"
        case "single":
            base = "Float"
        case "double":
            base = "Double"
        case "list", "datatypelist":
            if let elemType = listElementType {
                let innerType = swiftFieldType(elemType, cluster: cluster, isNullable: false, isOptional: false)
                base = "[\(innerType)]"
            } else {
                base = "[TLVElement]"
            }
        default:
            // Named enums → raw integer type
            if let enumDef = cluster.enums.first(where: { $0.name == xmlType }) {
                let maxValue = enumDef.items.map(\.value).max() ?? 0
                base = maxValue > 255 ? "UInt16" : "UInt8"
            }
            // Named bitmaps → raw integer type
            else if let bitmapDef = cluster.bitmaps.first(where: { $0.name == xmlType }) {
                let maxBit = bitmapDef.bitfields.map(\.bit).max() ?? 0
                if maxBit >= 16 { base = "UInt32" }
                else if maxBit >= 8 { base = "UInt16" }
                else { base = "UInt8" }
            }
            // Named structs (cluster-local)
            else if cluster.structs.contains(where: { $0.name == xmlType }) {
                let typeName = sanitizeTypeName(xmlType)
                base = typeName
            }
            // Unknown
            else {
                base = "TLVElement"
            }
        }

        return (isNullable || isOptional) ? "\(base)?" : base
    }

    /// Returns the TLV element type category for a given XML type — used for
    /// choosing the right TLV encoding expression.
    private static func tlvCategory(_ xmlType: String?, cluster: ClusterDefinition) -> String {
        guard let xmlType, !xmlType.isEmpty else { return "element" }
        switch xmlType.lowercased() {
        case "bool": return "bool"
        case "uint8", "enum8", "bitmap8", "percent", "action_id", "status",
             "uint16", "enum16", "bitmap16", "percent100ths",
             "vendor", "vendor_id", "group_id", "endpoint_no",
             "uint32", "bitmap32", "epoch_s", "elapsed_s", "elapsed",
             "utc", "epoch", "event_no", "data_ver",
             "cluster_id", "devtype_id",
             "uint64", "node_id", "node", "fabric_id", "fabric_idx",
             "eui64", "entry_idx":
            return "uint"
        case "int8", "int16", "int32", "int64",
             "temperature", "signedtemperature", "temperaturedifference",
             "amperage", "amperage_ma", "energy", "energy_mwh",
             "voltage", "voltage_mv", "power", "power_mw":
            return "int"
        case "string", "char_string", "long_char_string": return "string"
        case "octstr", "octet_string", "long_octet_string",
             "ipv6adr", "ipv6pre", "ipv4adr", "hwadr", "ipadr": return "octstr"
        case "single": return "float"
        case "double": return "double"
        case "list", "datatypelist": return "list"
        default:
            if cluster.enums.contains(where: { $0.name == xmlType }) { return "uint" }
            if cluster.bitmaps.contains(where: { $0.name == xmlType }) { return "uint" }
            if cluster.structs.contains(where: { $0.name == xmlType }) { return "struct" }
            return "element"
        }
    }

    /// Returns a Swift expression that encodes a property value to a TLVElement.
    private static func tlvEncodeExpression(
        propName: String,
        xmlType: String?,
        cluster: ClusterDefinition,
        isNullable: Bool,
        listElementType: String? = nil
    ) -> String {
        let cat = tlvCategory(xmlType, cluster: cluster)
        // For nullable fields, the caller wraps the optional check
        let name = escaped(propName)
        switch cat {
        case "bool":
            return ".bool(\(name))"
        case "uint":
            return ".unsignedInt(UInt64(\(name)))"
        case "int":
            return ".signedInt(Int64(\(name)))"
        case "string":
            return ".utf8String(\(name))"
        case "octstr":
            return ".octetString(\(name))"
        case "float":
            return ".float(\(name))"
        case "double":
            return ".double(\(name))"
        case "struct":
            return "\(name).toTLVElement()"
        case "list":
            if let elemType = listElementType {
                let elemCat = tlvCategory(elemType, cluster: cluster)
                switch elemCat {
                case "struct":
                    return ".array(\(name).map { $0.toTLVElement() })"
                case "bool":
                    return ".array(\(name).map { .bool($0) })"
                case "uint":
                    return ".array(\(name).map { .unsignedInt(UInt64($0)) })"
                case "int":
                    return ".array(\(name).map { .signedInt(Int64($0)) })"
                case "string":
                    return ".array(\(name).map { .utf8String($0) })"
                case "octstr":
                    return ".array(\(name).map { .octetString($0) })"
                default:
                    return ".array(\(name))"
                }
            }
            // Unknown element type — assume [TLVElement]
            return ".array(\(name))"
        default:
            return name
        }
    }

    /// Returns Swift code lines that decode a field from a TLV structure.
    ///
    /// The returned code expects `fields` to be a `[TLVField]` in scope.
    private static func tlvDecodeLines(
        fieldName: String,
        xmlType: String?,
        tag: UInt32,
        cluster: ClusterDefinition,
        isNullable: Bool,
        isOptional: Bool,
        listElementType: String? = nil
    ) -> (varDecl: String, decodeCode: [String]) {
        let propName = NamingConventions.structPropertyName(from: fieldName)
        let swiftType = swiftFieldType(xmlType, cluster: cluster, isNullable: isNullable, isOptional: isOptional, listElementType: listElementType)
        let cat = tlvCategory(xmlType, cluster: cluster)
        let tagExpr = "UInt8(\(tag))"

        if isOptional {
            // Optional field — nil if absent
            var lines: [String] = []
            let accessor = valueAccessor(cat, xmlType: xmlType, cluster: cluster, listElementType: listElementType)
            lines.append("            let \(escaped(propName)): \(swiftType)")
            lines.append("            if let fieldValue = element[contextTag: \(tagExpr)] {")
            if isNullable {
                lines.append("                if fieldValue.isNull {")
                lines.append("                    \(escaped(propName)) = nil")
                lines.append("                } else {")
                lines.append("                    \(escaped(propName)) = \(accessor("fieldValue"))")
                lines.append("                }")
            } else {
                lines.append("                \(escaped(propName)) = \(accessor("fieldValue"))")
            }
            lines.append("            } else {")
            lines.append("                \(escaped(propName)) = nil")
            lines.append("            }")
            return ("", lines)
        } else {
            // Required field
            var lines: [String] = []
            lines.append("            guard let raw_\(propName) = element[contextTag: \(tagExpr)] else {")
            lines.append("                throw TLVDecodingError.missingField(name: \"\(fieldName)\", tag: \(tagExpr))")
            lines.append("            }")
            if isNullable {
                let accessor = valueAccessor(cat, xmlType: xmlType, cluster: cluster, listElementType: listElementType)
                lines.append("            let \(escaped(propName)): \(swiftType)")
                lines.append("            if raw_\(propName).isNull {")
                lines.append("                \(escaped(propName)) = nil")
                lines.append("            } else {")
                lines.append("                \(escaped(propName)) = \(accessor("raw_\(propName)"))")
                lines.append("            }")
            } else {
                let accessor = valueAccessor(cat, xmlType: xmlType, cluster: cluster, listElementType: listElementType)
                lines.append("            let \(escaped(propName)) = \(accessor("raw_\(propName)"))")
            }
            return ("", lines)
        }
    }

    /// Returns a Swift expression that extracts a typed value from a TLVElement variable name.
    private static func valueAccessor(
        _ cat: String,
        xmlType: String?,
        cluster: ClusterDefinition,
        listElementType: String? = nil
    ) -> (String) -> String {
        switch cat {
        case "bool":
            return { "\($0).boolValue ?? false" }
        case "uint":
            let swiftType = swiftFieldType(xmlType, cluster: cluster, isNullable: false, isOptional: false)
            return { "\(swiftType)(\($0).uintValue ?? 0)" }
        case "int":
            let swiftType = swiftFieldType(xmlType, cluster: cluster, isNullable: false, isOptional: false)
            return { "\(swiftType)(\($0).intValue ?? 0)" }
        case "string":
            return { "\($0).stringValue ?? \"\"" }
        case "octstr":
            return { "\($0).dataValue ?? Data()" }
        case "float":
            return { "({ if case .float(let v) = \($0) { return v } else { return 0 } })()" }
        case "double":
            return { "({ if case .double(let v) = \($0) { return v } else { return 0 } })()" }
        case "struct":
            let typeName = sanitizeTypeName(xmlType ?? "")
            return { "try \(typeName).fromTLVElement(\($0))" }
        case "list":
            if let elemType = listElementType {
                let innerCat = tlvCategory(elemType, cluster: cluster)
                if innerCat == "struct" {
                    let innerTypeName = sanitizeTypeName(elemType)
                    return { "(\($0).arrayElements ?? []).compactMap { try? \(innerTypeName).fromTLVElement($0) }" }
                } else {
                    let innerAccessor = valueAccessor(innerCat, xmlType: elemType, cluster: cluster)
                    return { "(\($0).arrayElements ?? []).map { \(innerAccessor("$0")) }" }
                }
            }
            return { "\($0).arrayElements ?? []" }
        default:
            return { $0 }
        }
    }

    // MARK: - Struct Type Generation

    /// Generates a `TLVCodable` struct nested within the cluster enum.
    private static func generateStructType(
        _ structDef: StructDefinition,
        cluster: ClusterDefinition,
        into lines: inout [String]
    ) {
        let typeName = sanitizeTypeName(structDef.name)
        let fieldsToGenerate = structDef.fields.filter { $0.type != nil }
        if fieldsToGenerate.isEmpty { return }

        lines.append("    // MARK: - \(typeName)")
        lines.append("")
        lines.append("    public struct \(typeName): TLVCodable, Equatable {")

        // Properties
        for field in fieldsToGenerate {
            let propName = NamingConventions.structPropertyName(from: field.name)
            let swiftType = swiftFieldType(field.type, cluster: cluster, isNullable: field.isNullable, isOptional: field.isOptional, listElementType: field.listElementType)
            lines.append("        public var \(escaped(propName)): \(swiftType)")
        }

        // FabricIndex for fabric-scoped structs
        if structDef.isFabricScoped {
            lines.append("        public var fabricIndex: UInt8?")
        }

        lines.append("")

        // Init
        var initParams: [String] = []
        for field in fieldsToGenerate {
            let propName = NamingConventions.structPropertyName(from: field.name)
            let swiftType = swiftFieldType(field.type, cluster: cluster, isNullable: field.isNullable, isOptional: field.isOptional, listElementType: field.listElementType)
            let defaultVal = (field.isOptional || field.isNullable) ? " = nil" : ""
            initParams.append("            \(escaped(propName)): \(swiftType)\(defaultVal)")
        }
        if structDef.isFabricScoped {
            initParams.append("            fabricIndex: UInt8? = nil")
        }
        lines.append("        public init(")
        lines.append(initParams.joined(separator: ",\n"))
        lines.append("        ) {")
        for field in fieldsToGenerate {
            let propName = NamingConventions.structPropertyName(from: field.name)
            lines.append("            self.\(escaped(propName)) = \(escaped(propName))")
        }
        if structDef.isFabricScoped {
            lines.append("            self.fabricIndex = fabricIndex")
        }
        lines.append("        }")

        // toTLVElement
        lines.append("")
        lines.append("        public func toTLVElement() -> TLVElement {")
        lines.append("            var fields: [TLVElement.TLVField] = []")
        for field in fieldsToGenerate {
            let propName = NamingConventions.structPropertyName(from: field.name)
            let tag = field.id
            if field.isOptional || field.isNullable {
                lines.append("            if let val = \(escaped(propName)) {")
                let encExpr = tlvEncodeExpression(propName: "val", xmlType: field.type, cluster: cluster, isNullable: false, listElementType: field.listElementType)
                    .replacingOccurrences(of: "`val`", with: "val")
                lines.append("                fields.append(TLVElement.TLVField(tag: .contextSpecific(\(tag)), value: \(encExpr)))")
                if field.isNullable && !field.isOptional {
                    lines.append("            } else {")
                    lines.append("                fields.append(TLVElement.TLVField(tag: .contextSpecific(\(tag)), value: .null))")
                }
                lines.append("            }")
            } else {
                let encExpr = tlvEncodeExpression(propName: propName, xmlType: field.type, cluster: cluster, isNullable: false, listElementType: field.listElementType)
                lines.append("            fields.append(TLVElement.TLVField(tag: .contextSpecific(\(tag)), value: \(encExpr)))")
            }
        }
        if structDef.isFabricScoped {
            lines.append("            if let fi = fabricIndex {")
            lines.append("                fields.append(TLVElement.TLVField(tag: .contextSpecific(0xFE), value: .unsignedInt(UInt64(fi))))")
            lines.append("            }")
        }
        lines.append("            return .structure(fields)")
        lines.append("        }")

        // fromTLVElement
        lines.append("")
        lines.append("        public static func fromTLVElement(_ element: TLVElement) throws -> \(typeName) {")
        lines.append("            // Accept both structure and list (matter.js vs CHIP SDK)")
        lines.append("            switch element {")
        lines.append("            case .structure, .list: break")
        lines.append("            default: throw TLVDecodingError.invalidStructure")
        lines.append("            }")

        for field in fieldsToGenerate {
            let (_, decodeLines) = tlvDecodeLines(
                fieldName: field.name,
                xmlType: field.type,
                tag: field.id,
                cluster: cluster,
                isNullable: field.isNullable,
                isOptional: field.isOptional,
                listElementType: field.listElementType
            )
            for line in decodeLines {
                lines.append(line)
            }
        }

        // FabricIndex decode
        var fabricIndexLine = ""
        if structDef.isFabricScoped {
            lines.append("            let fabricIndex: UInt8? = element[contextTag: 0xFE].flatMap { UInt8($0.uintValue ?? 0) }")
            fabricIndexLine = ", fabricIndex: fabricIndex"
        }

        // Construct return value
        var args: [String] = []
        for field in fieldsToGenerate {
            let propName = NamingConventions.structPropertyName(from: field.name)
            args.append("\(escaped(propName)): \(escaped(propName))")
        }
        let argStr = args.joined(separator: ", ")
        lines.append("            return \(typeName)(\(argStr)\(fabricIndexLine))")
        lines.append("        }")

        lines.append("    }")
    }

    // MARK: - Command Struct Generation

    /// Generates a request or response struct for a command that has fields.
    private static func generateCommandStruct(
        _ cmd: CommandDefinition,
        cluster: ClusterDefinition,
        into lines: inout [String]
    ) {
        let fieldsToGenerate = cmd.fields.filter { $0.type != nil }
        if fieldsToGenerate.isEmpty { return }

        let structName = NamingConventions.commandStructName(from: cmd.name, direction: cmd.direction)

        lines.append("")
        lines.append("    // MARK: - \(structName)")
        lines.append("")
        lines.append("    public struct \(structName): TLVCodable, Equatable {")

        // Properties
        for field in fieldsToGenerate {
            let propName = NamingConventions.structPropertyName(from: field.name)
            let swiftType = swiftFieldType(field.type, cluster: cluster, isNullable: field.isNullable, isOptional: field.isOptional, listElementType: field.listElementType)
            lines.append("        public var \(escaped(propName)): \(swiftType)")
        }

        lines.append("")

        // Init
        var initParams: [String] = []
        for field in fieldsToGenerate {
            let propName = NamingConventions.structPropertyName(from: field.name)
            let swiftType = swiftFieldType(field.type, cluster: cluster, isNullable: field.isNullable, isOptional: field.isOptional, listElementType: field.listElementType)
            let defaultVal = (field.isOptional || field.isNullable) ? " = nil" : ""
            initParams.append("            \(escaped(propName)): \(swiftType)\(defaultVal)")
        }
        lines.append("        public init(")
        lines.append(initParams.joined(separator: ",\n"))
        lines.append("        ) {")
        for field in fieldsToGenerate {
            let propName = NamingConventions.structPropertyName(from: field.name)
            lines.append("            self.\(escaped(propName)) = \(escaped(propName))")
        }
        lines.append("        }")

        // toTLVElement
        lines.append("")
        lines.append("        public func toTLVElement() -> TLVElement {")
        lines.append("            var fields: [TLVElement.TLVField] = []")
        for field in fieldsToGenerate {
            let propName = NamingConventions.structPropertyName(from: field.name)
            let tag = field.id
            if field.isOptional || field.isNullable {
                lines.append("            if let val = \(escaped(propName)) {")
                let encExpr = tlvEncodeExpression(propName: "val", xmlType: field.type, cluster: cluster, isNullable: false, listElementType: field.listElementType)
                    .replacingOccurrences(of: "`val`", with: "val")
                lines.append("                fields.append(TLVElement.TLVField(tag: .contextSpecific(\(tag)), value: \(encExpr)))")
                if field.isNullable && !field.isOptional {
                    lines.append("            } else {")
                    lines.append("                fields.append(TLVElement.TLVField(tag: .contextSpecific(\(tag)), value: .null))")
                }
                lines.append("            }")
            } else {
                let encExpr = tlvEncodeExpression(propName: propName, xmlType: field.type, cluster: cluster, isNullable: false, listElementType: field.listElementType)
                lines.append("            fields.append(TLVElement.TLVField(tag: .contextSpecific(\(tag)), value: \(encExpr)))")
            }
        }
        lines.append("            return .structure(fields)")
        lines.append("        }")

        // fromTLVElement
        lines.append("")
        lines.append("        public static func fromTLVElement(_ element: TLVElement) throws -> \(structName) {")
        lines.append("            // Accept both structure and list (matter.js vs CHIP SDK)")
        lines.append("            switch element {")
        lines.append("            case .structure, .list: break")
        lines.append("            default: throw TLVDecodingError.invalidStructure")
        lines.append("            }")

        for field in fieldsToGenerate {
            let (_, decodeLines) = tlvDecodeLines(
                fieldName: field.name,
                xmlType: field.type,
                tag: field.id,
                cluster: cluster,
                isNullable: field.isNullable,
                isOptional: field.isOptional,
                listElementType: field.listElementType
            )
            for line in decodeLines {
                lines.append(line)
            }
        }

        // Construct return value
        var args: [String] = []
        for field in fieldsToGenerate {
            let propName = NamingConventions.structPropertyName(from: field.name)
            args.append("\(escaped(propName)): \(escaped(propName))")
        }
        let argStr = args.joined(separator: ", ")
        lines.append("            return \(structName)(\(argStr))")
        lines.append("        }")

        lines.append("    }")
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

            // Build field specs
            let fieldSpecs = cmd.fields.compactMap { field -> String? in
                guard let type = field.type else { return nil }
                let typeCode = matterTypeToSwift(type, cluster: cluster)
                let isOptional = field.isOptional ? "true" : "false"
                let isNullable = field.isNullable ? "true" : "false"
                guard field.id <= UInt32(UInt8.max) else { return nil }
                return "FieldSpec(id: \(field.id), name: \"\(field.name)\", type: \(typeCode), isOptional: \(isOptional), isNullable: \(isNullable))"
            }

            // Build response ID
            var responseIDCode = "nil"
            if let responseName = cmd.response, responseName != "Y" {
                // Look up the response command's ID
                if let responseCmd = cluster.commands.first(where: { $0.name == responseName }) {
                    responseIDCode = "CommandID(rawValue: 0x\(hex(responseCmd.id)))"
                }
            }

            // Build optional parameters
            var extras: [String] = []
            if !fieldSpecs.isEmpty {
                extras.append("fields: [\(fieldSpecs.joined(separator: ", "))]")
            }
            if responseIDCode != "nil" {
                extras.append("responseID: \(responseIDCode)")
            }
            if cmd.isFabricScoped {
                extras.append("isFabricScoped: true")
            }
            if cmd.isTimedInvoke {
                extras.append("isTimedInvoke: true")
            }

            let extrasStr = extras.isEmpty ? "" : ", \(extras.joined(separator: ", "))"
            lines.append("            CommandSpec(id: CommandID(rawValue: 0x\(hex(cmd.id))), name: \"\(cmd.name)\", conformance: \(confCode)\(extrasStr)),")
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

    // MARK: - Device Type Registry Generation

    /// Generates the DeviceTypeRegistry.generated.swift file.
    ///
    /// Resolves cluster names from device type XML to `ClusterID` property names
    /// using the provided lookup table. Unresolved names fall back to hex literals.
    private static func generateDeviceTypeRegistry(
        deviceTypes: [DeviceTypeDefinition],
        clusterNameToIDProp: [String: String]
    ) -> String {
        var lines: [String] = []

        lines.append("// DeviceTypeRegistry.generated.swift")
        lines.append("// GENERATED by MatterModelGenerator — DO NOT EDIT")
        lines.append("// Copyright 2026 Monagle Pty Ltd")
        lines.append("")
        lines.append("import MatterTypes")
        lines.append("")
        lines.append("extension DeviceTypeRegistry {")
        lines.append("")
        lines.append("    /// Registers all device types parsed from the Matter spec XML.")
        lines.append("    /// Called once during `DeviceTypeRegistry` initialisation.")
        lines.append("    static func registerGeneratedTypes(into specs: inout [DeviceTypeID: DeviceTypeSpec]) {")

        let sorted = deviceTypes.sorted(by: { $0.id < $1.id })
            .filter { $0.id != 0 }  // Skip abstract device types

        for dt in sorted {
            let propName = deviceTypeNameOverrides[dt.name]
                ?? NamingConventions.deviceTypePropertyName(from: dt.name)

            // Separate server clusters into mandatory and optional
            let mandatoryServerClusters = dt.requiredClusters.filter { cluster in
                guard cluster.side == "server" else { return false }
                if case .mandatory = cluster.conformance { return true }
                return false
            }
            let optionalServerClusters = dt.requiredClusters.filter { cluster in
                guard cluster.side == "server" else { return false }
                if case .mandatory = cluster.conformance { return false }
                if case .disallowed = cluster.conformance { return false }
                return true
            }

            // Resolve cluster names to ClusterID expressions
            let requiredExprs = mandatoryServerClusters.map { cluster in
                clusterIDExpression(cluster: cluster, lookup: clusterNameToIDProp)
            }
            let optionalExprs = optionalServerClusters.map { cluster in
                clusterIDExpression(cluster: cluster, lookup: clusterNameToIDProp)
            }

            lines.append("")
            lines.append("        // \(dt.name) (0x\(hex(dt.id)))")
            lines.append("        specs[.\(escaped(propName))] = DeviceTypeSpec(")
            lines.append("            id: .\(escaped(propName)),")
            lines.append("            name: \"\(dt.name)\",")
            lines.append("            revision: \(dt.revision),")

            // Required server clusters
            if requiredExprs.isEmpty {
                lines.append("            requiredServerClusters: [],")
            } else if requiredExprs.count <= 3 {
                lines.append("            requiredServerClusters: [\(requiredExprs.joined(separator: ", "))],")
            } else {
                lines.append("            requiredServerClusters: [")
                for expr in requiredExprs {
                    lines.append("                \(expr),")
                }
                lines.append("            ],")
            }

            // Optional server clusters
            if optionalExprs.isEmpty {
                lines.append("            optionalServerClusters: []")
            } else if optionalExprs.count <= 3 {
                lines.append("            optionalServerClusters: [\(optionalExprs.joined(separator: ", "))]")
            } else {
                lines.append("            optionalServerClusters: [")
                for expr in optionalExprs {
                    lines.append("                \(expr),")
                }
                lines.append("            ]")
            }

            lines.append("        )")
        }

        lines.append("    }")
        lines.append("}")
        lines.append("")

        return lines.joined(separator: "\n")
    }

    /// Returns a `ClusterID` Swift expression for a device type cluster reference.
    private static func clusterIDExpression(
        cluster: DeviceTypeCluster,
        lookup: [String: String]
    ) -> String {
        if let propName = lookup[cluster.name] {
            return ".\(escaped(propName))"
        }
        // Fallback: hex literal
        return "ClusterID(rawValue: 0x\(hex(cluster.id)))"
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
