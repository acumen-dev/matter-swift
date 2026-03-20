// XMLClusterParser.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

/// Parses a CHIP spec XML cluster file into a `ClusterDefinition`.
final class XMLClusterParser: NSObject, XMLParserDelegate {

    private var cluster: ClusterDefinition?

    // Cluster-level accumulators
    private var clusterID: UInt32 = 0
    private var clusterName = ""
    private var clusterRevision = 0
    private var clusterClassification = ""
    private var features: [FeatureDefinition] = []
    private var attributes: [AttributeDefinition] = []
    private var commands: [CommandDefinition] = []
    private var events: [EventDefinition] = []
    private var enums: [EnumDefinition] = []
    private var bitmaps: [BitmapDefinition] = []
    private var structs: [StructDefinition] = []

    // Current element stack for context
    private var elementStack: [String] = []
    private var characterBuffer = ""

    // Feature being parsed
    private var currentFeature: PartialFeature?

    // Attribute being parsed
    private var currentAttribute: PartialAttribute?

    // Command being parsed
    private var currentCommand: PartialCommand?
    private var currentCommandFields: [FieldDefinition] = []

    // Event being parsed
    private var currentEvent: PartialEvent?
    private var currentEventFields: [FieldDefinition] = []

    // Enum being parsed
    private var currentEnum: PartialEnum?
    private var currentEnumItems: [EnumItem] = []

    // Bitmap being parsed
    private var currentBitmap: PartialBitmap?
    private var currentBitmapFields: [BitfieldItem] = []

    // Struct being parsed
    private var currentStruct: PartialStruct?
    private var currentStructFields: [FieldDefinition] = []

    // Conformance parsing
    private var conformanceStack: [ConformanceBuilder] = []

    // Field being parsed (for commands, events, structs)
    private var currentField: PartialField?

    // MARK: - Public API

    static func parse(contentsOf url: URL) throws -> ClusterDefinition? {
        let parser = XMLClusterParser()
        return try parser.parseFile(at: url)
    }

    private func parseFile(at url: URL) throws -> ClusterDefinition? {
        guard let xmlParser = XMLParser(contentsOf: url) else {
            return nil
        }
        xmlParser.delegate = self
        xmlParser.parse()
        return cluster
    }

    // MARK: - XMLParserDelegate

    func parser(_ parser: XMLParser, didStartElement elementName: String,
                namespaceURI: String?, qualifiedName: String?,
                attributes attrs: [String: String]) {

        elementStack.append(elementName)
        characterBuffer = ""

        switch elementName {
        case "cluster":
            clusterID = parseHexOrDecimal(attrs["id"] ?? "0")
            clusterName = attrs["name"] ?? ""
            clusterRevision = Int(attrs["revision"] ?? "0") ?? 0

        case "clusterId":
            // <clusterId id="0x003E" name="Operational Credentials"/>
            // Used when the root <cluster> has an empty id attribute
            if parentElement == "clusterIds" {
                let childID = parseHexOrDecimal(attrs["id"] ?? "0")
                if childID != 0 && clusterID == 0 {
                    clusterID = childID
                }
            }

        case "classification":
            if parentElement == "cluster" {
                clusterClassification = attrs["role"] ?? attrs["scope"] ?? ""
            }

        case "feature":
            if parentElement == "features" {
                currentFeature = PartialFeature(
                    bit: Int(attrs["bit"] ?? "0") ?? 0,
                    code: attrs["code"] ?? "",
                    name: attrs["name"] ?? "",
                    summary: attrs["summary"] ?? ""
                )
                conformanceStack.append(ConformanceBuilder())
            } else if isInConformance {
                // <feature name="X"/> inside a conformance element
                pushConformanceExpression(.feature(attrs["name"] ?? ""))
            }

        case "attribute":
            if isInConformance {
                // <attribute name="X"/> inside a conformance element
                pushConformanceExpression(.attribute(attrs["name"] ?? ""))
            } else if parentElement == "attributes" {
                currentAttribute = PartialAttribute(
                    id: parseHexOrDecimal(attrs["id"] ?? "0"),
                    name: attrs["name"] ?? "",
                    type: attrs["type"] ?? "unknown",
                    defaultValue: attrs["default"]
                )
                conformanceStack.append(ConformanceBuilder())
            }

        case "access":
            if let attr = currentAttribute, parentElement == "attribute" {
                var updated = attr
                if attrs["read"] == "true" { updated.isReadable = true }
                if attrs["write"] == "true" { updated.isWritable = true }
                if let rp = attrs["readPrivilege"] { updated.readPrivilege = rp }
                if let wp = attrs["writePrivilege"] { updated.writePrivilege = wp }
                currentAttribute = updated
            }
            if currentCommand != nil, let ip = attrs["invokePrivilege"] {
                currentCommand?.invokePrivilege = ip
            }

        case "quality":
            if currentAttribute != nil, parentElement == "attribute" {
                if attrs["nullable"] == "true" { currentAttribute?.isNullable = true }
                if attrs["scene"] == "true" { currentAttribute?.isScene = true }
                currentAttribute?.persistence = attrs["persistence"]
            }
            if currentField != nil {
                if attrs["nullable"] == "true" { currentField?.isNullable = true }
            }

        case "command":
            if parentElement == "commands" {
                currentCommand = PartialCommand(
                    id: parseHexOrDecimal(attrs["id"] ?? "0"),
                    name: attrs["name"] ?? "",
                    direction: attrs["direction"] ?? "commandToServer",
                    response: attrs["response"],
                    isFabricScoped: attrs["isFabricScoped"] == "true",
                    isTimedInvoke: attrs["mustUseTimedInvoke"] == "true"
                )
                currentCommandFields = []
                conformanceStack.append(ConformanceBuilder())
            }

        case "event":
            if parentElement == "events" {
                currentEvent = PartialEvent(
                    id: parseHexOrDecimal(attrs["id"] ?? "0"),
                    name: attrs["name"] ?? "",
                    priority: attrs["priority"] ?? "info"
                )
                currentEventFields = []
                conformanceStack.append(ConformanceBuilder())
            }

        case "field":
            if currentCommand != nil || currentEvent != nil || currentStruct != nil {
                currentField = PartialField(
                    id: parseHexOrDecimal(attrs["id"] ?? attrs["fieldId"] ?? "0"),
                    name: attrs["name"] ?? "",
                    type: attrs["type"]
                )
                conformanceStack.append(ConformanceBuilder())
            }

        case "item":
            if currentEnum != nil {
                let item = PartialEnumItem(
                    value: parseHexOrDecimal(attrs["value"] ?? "0"),
                    name: attrs["name"] ?? "",
                    summary: attrs["summary"] ?? ""
                )
                currentEnumItems.append(EnumItem(
                    value: item.value,
                    name: item.name,
                    summary: item.summary,
                    conformance: .unknown // will be updated on close
                ))
                conformanceStack.append(ConformanceBuilder())
            }

        case "bitfield":
            if currentBitmap != nil {
                let field = PartialBitfield(
                    bit: Int(attrs["bit"] ?? "0") ?? 0,
                    name: attrs["name"] ?? "",
                    summary: attrs["summary"] ?? ""
                )
                currentBitmapFields.append(BitfieldItem(
                    bit: field.bit,
                    name: field.name,
                    summary: field.summary,
                    conformance: .unknown
                ))
                conformanceStack.append(ConformanceBuilder())
            }

        case "enum":
            if parentElement == "dataTypes" {
                currentEnum = PartialEnum(name: attrs["name"] ?? "")
                currentEnumItems = []
            }

        case "bitmap":
            if parentElement == "dataTypes" {
                currentBitmap = PartialBitmap(name: attrs["name"] ?? "")
                currentBitmapFields = []
            }

        case "struct":
            if parentElement == "dataTypes" {
                currentStruct = PartialStruct(
                    name: attrs["name"] ?? "",
                    isFabricScoped: attrs["isFabricScoped"] == "true"
                )
                currentStructFields = []
            }

        // Conformance elements
        case "mandatoryConform":
            conformanceStack.last?.type = .mandatory
        case "optionalConform":
            conformanceStack.last?.type = .optional
        case "provisionalConform":
            conformanceStack.last?.type = .provisional
        case "deprecateConform":
            conformanceStack.last?.type = .deprecated
        case "disallowConform":
            conformanceStack.last?.type = .disallowed
        case "otherwiseConform":
            conformanceStack.last?.type = .otherwise
            conformanceStack.last?.otherwiseChildren = []

        case "notTerm":
            conformanceStack.last?.pushLogical(.not)
        case "orTerm":
            conformanceStack.last?.pushLogical(.or)
        case "andTerm":
            conformanceStack.last?.pushLogical(.and)

        case "condition":
            if isInConformance {
                pushConformanceExpression(.condition(attrs["name"] ?? ""))
            }

        default:
            break
        }
    }

    func parser(_ parser: XMLParser, didEndElement elementName: String,
                namespaceURI: String?, qualifiedName: String?) {

        defer { elementStack.removeLast() }

        switch elementName {
        case "cluster":
            cluster = ClusterDefinition(
                id: clusterID,
                name: clusterName,
                revision: clusterRevision,
                classification: clusterClassification,
                features: features,
                attributes: attributes,
                commands: commands,
                events: events,
                enums: enums,
                bitmaps: bitmaps,
                structs: structs
            )

        case "feature":
            if parentElement == "features", let feat = currentFeature {
                let conf = conformanceStack.popLast()?.build() ?? .unknown
                features.append(FeatureDefinition(
                    bit: feat.bit, code: feat.code, name: feat.name,
                    summary: feat.summary, conformance: conf
                ))
                currentFeature = nil
            }

        case "attribute":
            if let attr = currentAttribute, !isInConformance {
                let conf = conformanceStack.popLast()?.build() ?? .unknown
                attributes.append(AttributeDefinition(
                    id: attr.id, name: attr.name, type: attr.type,
                    isReadable: attr.isReadable, isWritable: attr.isWritable,
                    readPrivilege: attr.readPrivilege, writePrivilege: attr.writePrivilege,
                    isNullable: attr.isNullable, isScene: attr.isScene,
                    persistence: attr.persistence, conformance: conf,
                    defaultValue: attr.defaultValue
                ))
                currentAttribute = nil
            }

        case "command":
            if let cmd = currentCommand, parentElement == "commands" {
                let conf = conformanceStack.popLast()?.build() ?? .unknown
                commands.append(CommandDefinition(
                    id: cmd.id, name: cmd.name, direction: cmd.direction,
                    response: cmd.response, invokePrivilege: cmd.invokePrivilege,
                    conformance: conf, fields: currentCommandFields,
                    isFabricScoped: cmd.isFabricScoped, isTimedInvoke: cmd.isTimedInvoke
                ))
                currentCommand = nil
            }

        case "event":
            if let evt = currentEvent, parentElement == "events" {
                let conf = conformanceStack.popLast()?.build() ?? .unknown
                events.append(EventDefinition(
                    id: evt.id, name: evt.name, priority: evt.priority,
                    conformance: conf, fields: currentEventFields
                ))
                currentEvent = nil
            }

        case "field":
            if let field = currentField {
                let conf = conformanceStack.popLast()?.build() ?? .unknown
                let def = FieldDefinition(
                    id: field.id, name: field.name, type: field.type,
                    isNullable: field.isNullable, isOptional: field.isOptional,
                    conformance: conf
                )
                if currentCommand != nil {
                    currentCommandFields.append(def)
                } else if currentEvent != nil {
                    currentEventFields.append(def)
                } else if currentStruct != nil {
                    currentStructFields.append(def)
                }
                currentField = nil
            }

        case "item":
            if currentEnum != nil, !currentEnumItems.isEmpty {
                let conf = conformanceStack.popLast()?.build() ?? .unknown
                let idx = currentEnumItems.count - 1
                let item = currentEnumItems[idx]
                currentEnumItems[idx] = EnumItem(
                    value: item.value, name: item.name,
                    summary: item.summary, conformance: conf
                )
            }

        case "bitfield":
            if currentBitmap != nil, !currentBitmapFields.isEmpty {
                let conf = conformanceStack.popLast()?.build() ?? .unknown
                let idx = currentBitmapFields.count - 1
                let item = currentBitmapFields[idx]
                currentBitmapFields[idx] = BitfieldItem(
                    bit: item.bit, name: item.name,
                    summary: item.summary, conformance: conf
                )
            }

        case "enum":
            if let e = currentEnum, parentElement == "dataTypes" {
                enums.append(EnumDefinition(name: e.name, items: currentEnumItems))
                currentEnum = nil
            }

        case "bitmap":
            if let b = currentBitmap, parentElement == "dataTypes" {
                bitmaps.append(BitmapDefinition(name: b.name, bitfields: currentBitmapFields))
                currentBitmap = nil
            }

        case "struct":
            if let s = currentStruct, parentElement == "dataTypes" {
                structs.append(StructDefinition(
                    name: s.name, fields: currentStructFields,
                    isFabricScoped: s.isFabricScoped
                ))
                currentStruct = nil
            }

        // Conformance closing
        case "notTerm":
            conformanceStack.last?.popLogical(.not)
        case "orTerm":
            conformanceStack.last?.popLogical(.or)
        case "andTerm":
            conformanceStack.last?.popLogical(.and)

        case "mandatoryConform", "optionalConform":
            // If otherwiseConform is active, save this as a child
            if conformanceStack.count >= 2 {
                let parentBuilder = conformanceStack[conformanceStack.count - 2]
                if parentBuilder.type == .otherwise {
                    let childConf = conformanceStack.last?.build() ?? .unknown
                    parentBuilder.otherwiseChildren?.append(childConf)
                    // Reset the current builder for the next child
                    conformanceStack[conformanceStack.count - 1] = ConformanceBuilder()
                }
            }

        default:
            break
        }
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) {
        characterBuffer += string
    }

    // MARK: - Helpers

    private var parentElement: String? {
        guard elementStack.count >= 2 else { return nil }
        return elementStack[elementStack.count - 2]
    }

    private var isInConformance: Bool {
        elementStack.contains(where: {
            $0 == "mandatoryConform" || $0 == "optionalConform" ||
            $0 == "otherwiseConform" || $0 == "provisionalConform" ||
            $0 == "deprecateConform" || $0 == "disallowConform"
        })
    }

    private func pushConformanceExpression(_ expr: ConformanceExpression) {
        conformanceStack.last?.pushExpression(expr)
    }

    private func parseHexOrDecimal(_ string: String) -> UInt32 {
        if string.hasPrefix("0x") || string.hasPrefix("0X") {
            return UInt32(string.dropFirst(2), radix: 16) ?? 0
        }
        return UInt32(string) ?? 0
    }
}

// MARK: - Partial Types (mutable during parsing)

private struct PartialFeature {
    let bit: Int
    let code: String
    let name: String
    let summary: String
}

private struct PartialAttribute {
    let id: UInt32
    let name: String
    let type: String
    let defaultValue: String?
    var isReadable = true
    var isWritable = false
    var readPrivilege: String?
    var writePrivilege: String?
    var isNullable = false
    var isScene = false
    var persistence: String?
}

private struct PartialCommand {
    let id: UInt32
    let name: String
    let direction: String
    let response: String?
    var invokePrivilege: String?
    var isFabricScoped: Bool
    var isTimedInvoke: Bool
}

private struct PartialEvent {
    let id: UInt32
    let name: String
    let priority: String
}

private struct PartialField {
    let id: UInt32
    let name: String
    let type: String?
    var isNullable = false
    var isOptional = false
}

private struct PartialEnum {
    let name: String
}

private struct PartialEnumItem {
    let value: UInt32
    let name: String
    let summary: String
}

private struct PartialBitmap {
    let name: String
}

private struct PartialBitfield {
    let bit: Int
    let name: String
    let summary: String
}

private struct PartialStruct {
    let name: String
    let isFabricScoped: Bool
}

// MARK: - Conformance Builder

/// Tracks the state of conformance parsing within a single scope.
private class ConformanceBuilder {
    enum ConformanceType {
        case mandatory, optional, provisional, deprecated, disallowed, otherwise, unknown
    }

    enum LogicalOp {
        case not, or, and
    }

    var type: ConformanceType = .unknown
    var expressions: [ConformanceExpression] = []
    var logicalStack: [(LogicalOp, [ConformanceExpression])] = []
    var otherwiseChildren: [Conformance]?

    func pushExpression(_ expr: ConformanceExpression) {
        if logicalStack.last != nil {
            logicalStack[logicalStack.count - 1].1.append(expr)
        } else {
            expressions.append(expr)
        }
    }

    func pushLogical(_ op: LogicalOp) {
        logicalStack.append((op, []))
    }

    func popLogical(_ op: LogicalOp) {
        guard let (stackOp, children) = logicalStack.popLast(), stackOp == op else { return }
        let expr: ConformanceExpression
        switch op {
        case .not:
            expr = .not(children.first ?? .feature(""))
        case .or:
            expr = .or(children)
        case .and:
            expr = .and(children)
        }
        pushExpression(expr)
    }

    func build() -> Conformance {
        let condition = expressions.first

        switch type {
        case .mandatory:
            if let cond = condition {
                return .mandatoryIf(cond)
            }
            return .mandatory
        case .optional:
            if let cond = condition {
                return .optionalIf(cond)
            }
            return .optional
        case .provisional:
            return .provisional
        case .deprecated:
            return .deprecated
        case .disallowed:
            return .disallowed
        case .otherwise:
            return .otherwise(otherwiseChildren ?? [])
        case .unknown:
            return .unknown
        }
    }
}
