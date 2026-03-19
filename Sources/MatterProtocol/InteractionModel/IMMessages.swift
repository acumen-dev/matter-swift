// IMMessages.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

/// Interaction Model message structures.
///
/// All IM messages are TLV-encoded structures exchanged over encrypted sessions.
/// Each message type corresponds to a specific `InteractionModelOpcode`.

/// InteractionModelRevision tag (context-specific 0xFF) and value.
/// Per Matter spec §8.1.1, all IM messages include this tag to identify the
/// protocol revision. The CHIP SDK (and Apple Home) always includes this field.
private let kInteractionModelRevisionTag: UInt8 = 0xFF
private let kInteractionModelRevision: UInt64 = 12

/// Creates a TLV field for the InteractionModelRevision tag.
private func interactionModelRevisionField() -> TLVElement.TLVField {
    .init(tag: .contextSpecific(kInteractionModelRevisionTag), value: .unsignedInt(kInteractionModelRevision))
}

// MARK: - Read Request

/// Read request — read one or more attributes.
///
/// ```
/// Structure {
///   0: attributeRequests (array of AttributePath, optional)
///   1: eventRequests (array of EventPath, optional)
///   2: eventFilters (array of EventFilter, optional)
///   3: isFabricFiltered (bool)
///   4: dataVersionFilters (array of DataVersionFilter, optional)
/// }
/// ```
public struct ReadRequest: Sendable, Equatable {

    private enum Tag {
        static let attributeRequests: UInt8 = 0
        static let eventRequests: UInt8 = 1
        static let eventFilters: UInt8 = 2
        static let isFabricFiltered: UInt8 = 3
        static let dataVersionFilters: UInt8 = 4
    }

    public let attributeRequests: [AttributePath]
    public let eventRequests: [EventPath]
    public let eventFilters: [EventFilterIB]
    public let isFabricFiltered: Bool
    public let dataVersionFilters: [DataVersionFilter]

    public init(
        attributeRequests: [AttributePath] = [],
        eventRequests: [EventPath] = [],
        eventFilters: [EventFilterIB] = [],
        isFabricFiltered: Bool = true,
        dataVersionFilters: [DataVersionFilter] = []
    ) {
        self.attributeRequests = attributeRequests
        self.eventRequests = eventRequests
        self.eventFilters = eventFilters
        self.isFabricFiltered = isFabricFiltered
        self.dataVersionFilters = dataVersionFilters
    }

    public func tlvEncode() -> Data {
        TLVEncoder.encode(toTLVElement())
    }

    public func toTLVElement() -> TLVElement {
        var fields: [TLVElement.TLVField] = []

        if !attributeRequests.isEmpty {
            fields.append(.init(
                tag: .contextSpecific(Tag.attributeRequests),
                value: .array(attributeRequests.map { $0.toTLVElement() })
            ))
        }

        if !eventRequests.isEmpty {
            fields.append(.init(
                tag: .contextSpecific(Tag.eventRequests),
                value: .array(eventRequests.map { $0.toTLVElement() })
            ))
        }

        if !eventFilters.isEmpty {
            fields.append(.init(
                tag: .contextSpecific(Tag.eventFilters),
                value: .array(eventFilters.map { $0.toTLVElement() })
            ))
        }

        fields.append(.init(tag: .contextSpecific(Tag.isFabricFiltered), value: .bool(isFabricFiltered)))

        if !dataVersionFilters.isEmpty {
            fields.append(.init(
                tag: .contextSpecific(Tag.dataVersionFilters),
                value: .array(dataVersionFilters.map { $0.toTLVElement() })
            ))
        }

        return .structure(fields)
    }

    public static func fromTLV(_ data: Data) throws -> ReadRequest {
        let (_, element) = try TLVDecoder.decode(data)
        return try fromTLVElement(element)
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> ReadRequest {
        guard case .structure(let fields) = element else {
            throw IMError.invalidMessage("ReadRequest: expected structure")
        }

        var attrPaths: [AttributePath] = []
        if let attrField = fields.first(where: { $0.tag == .contextSpecific(Tag.attributeRequests) }),
           case .array(let elements) = attrField.value {
            attrPaths = try elements.map { try AttributePath.fromTLVElement($0) }
        }

        var eventPaths: [EventPath] = []
        if let eventField = fields.first(where: { $0.tag == .contextSpecific(Tag.eventRequests) }),
           case .array(let elements) = eventField.value {
            eventPaths = try elements.map { try EventPath.fromTLVElement($0) }
        }

        var eventFilters: [EventFilterIB] = []
        if let filterField = fields.first(where: { $0.tag == .contextSpecific(Tag.eventFilters) }),
           case .array(let elements) = filterField.value {
            eventFilters = try elements.map { try EventFilterIB.fromTLVElement($0) }
        }

        let isFabricFiltered = fields.first(where: { $0.tag == .contextSpecific(Tag.isFabricFiltered) })?.value.boolValue ?? true

        var dvFilters: [DataVersionFilter] = []
        if let dvField = fields.first(where: { $0.tag == .contextSpecific(Tag.dataVersionFilters) }),
           case .array(let elements) = dvField.value {
            dvFilters = try elements.map { try DataVersionFilter.fromTLVElement($0) }
        }

        return ReadRequest(
            attributeRequests: attrPaths,
            eventRequests: eventPaths,
            eventFilters: eventFilters,
            isFabricFiltered: isFabricFiltered,
            dataVersionFilters: dvFilters
        )
    }
}

// MARK: - Report Data

/// Report data — response to a Read or subscription notification.
///
/// ```
/// Structure {
///   0: subscriptionID (unsigned int, optional)
///   1: attributeReports (array, optional)
///   2: eventReports (array, optional)
///   3: moreChunkedMessages (bool, optional)
///   4: suppressResponse (bool, optional)
/// }
/// ```
public struct ReportData: Sendable, Equatable {

    private enum Tag {
        static let subscriptionID: UInt8 = 0
        static let attributeReports: UInt8 = 1
        static let eventReports: UInt8 = 2
        static let moreChunkedMessages: UInt8 = 3
        static let suppressResponse: UInt8 = 4
    }

    public let subscriptionID: SubscriptionID?
    public let attributeReports: [AttributeReportIB]
    public let eventReports: [EventReportIB]
    public let moreChunkedMessages: Bool
    public let suppressResponse: Bool

    public init(
        subscriptionID: SubscriptionID? = nil,
        attributeReports: [AttributeReportIB] = [],
        eventReports: [EventReportIB] = [],
        moreChunkedMessages: Bool = false,
        suppressResponse: Bool = false
    ) {
        self.subscriptionID = subscriptionID
        self.attributeReports = attributeReports
        self.eventReports = eventReports
        self.moreChunkedMessages = moreChunkedMessages
        self.suppressResponse = suppressResponse
    }

    public func tlvEncode() -> Data {
        TLVEncoder.encode(toTLVElement())
    }

    public func toTLVElement() -> TLVElement {
        var fields: [TLVElement.TLVField] = []

        if let sid = subscriptionID {
            fields.append(.init(tag: .contextSpecific(Tag.subscriptionID), value: .unsignedInt(UInt64(sid.rawValue))))
        }

        if !attributeReports.isEmpty {
            fields.append(.init(
                tag: .contextSpecific(Tag.attributeReports),
                value: .array(attributeReports.map { $0.toTLVElement() })
            ))
        }

        if !eventReports.isEmpty {
            fields.append(.init(
                tag: .contextSpecific(Tag.eventReports),
                value: .array(eventReports.map { $0.toTLVElement() })
            ))
        }

        if moreChunkedMessages {
            fields.append(.init(tag: .contextSpecific(Tag.moreChunkedMessages), value: .bool(true)))
        }
        if suppressResponse {
            fields.append(.init(tag: .contextSpecific(Tag.suppressResponse), value: .bool(true)))
        }
        fields.append(interactionModelRevisionField())

        return .structure(fields)
    }

    public static func fromTLV(_ data: Data) throws -> ReportData {
        let (_, element) = try TLVDecoder.decode(data)
        return try fromTLVElement(element)
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> ReportData {
        guard case .structure(let fields) = element else {
            throw IMError.invalidMessage("ReportData: expected structure")
        }

        let subID = fields.first(where: { $0.tag == .contextSpecific(Tag.subscriptionID) })?.value.uintValue.map { SubscriptionID(rawValue: UInt32($0)) }

        var reports: [AttributeReportIB] = []
        if let attrField = fields.first(where: { $0.tag == .contextSpecific(Tag.attributeReports) }),
           case .array(let elements) = attrField.value {
            reports = try elements.map { try AttributeReportIB.fromTLVElement($0) }
        }

        var evReports: [EventReportIB] = []
        if let evField = fields.first(where: { $0.tag == .contextSpecific(Tag.eventReports) }),
           case .array(let elements) = evField.value {
            evReports = try elements.map { try EventReportIB.fromTLVElement($0) }
        }

        let more = fields.first(where: { $0.tag == .contextSpecific(Tag.moreChunkedMessages) })?.value.boolValue ?? false
        let suppress = fields.first(where: { $0.tag == .contextSpecific(Tag.suppressResponse) })?.value.boolValue ?? false

        return ReportData(
            subscriptionID: subID,
            attributeReports: reports,
            eventReports: evReports,
            moreChunkedMessages: more,
            suppressResponse: suppress
        )
    }
}

// MARK: - Attribute Report IB

/// An individual attribute report within a ReportData.
///
/// ```
/// Structure {
///   0: attributeStatus (AttributeStatusIB, optional — on error)
///   1: attributeData (AttributeDataIB, optional — on success)
/// }
/// ```
public struct AttributeReportIB: Sendable, Equatable {

    private enum Tag {
        static let attributeStatus: UInt8 = 0
        static let attributeData: UInt8 = 1
    }

    public let attributeData: AttributeDataIB?
    public let attributeStatus: AttributeStatusIB?

    public init(attributeData: AttributeDataIB) {
        self.attributeData = attributeData
        self.attributeStatus = nil
    }

    public init(attributeStatus: AttributeStatusIB) {
        self.attributeData = nil
        self.attributeStatus = attributeStatus
    }

    public func toTLVElement() -> TLVElement {
        var fields: [TLVElement.TLVField] = []
        if let status = attributeStatus {
            fields.append(.init(tag: .contextSpecific(Tag.attributeStatus), value: status.toTLVElement()))
        }
        if let data = attributeData {
            fields.append(.init(tag: .contextSpecific(Tag.attributeData), value: data.toTLVElement()))
        }
        return .structure(fields)
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> AttributeReportIB {
        guard case .structure(let fields) = element else {
            throw IMError.invalidMessage("AttributeReportIB: expected structure")
        }

        if let dataField = fields.first(where: { $0.tag == .contextSpecific(Tag.attributeData) }) {
            return AttributeReportIB(attributeData: try AttributeDataIB.fromTLVElement(dataField.value))
        }

        if let statusField = fields.first(where: { $0.tag == .contextSpecific(Tag.attributeStatus) }) {
            return AttributeReportIB(attributeStatus: try AttributeStatusIB.fromTLVElement(statusField.value))
        }

        throw IMError.invalidMessage("AttributeReportIB: neither data nor status present")
    }
}

// MARK: - Attribute Report Chunking

extension AttributeReportIB {

    /// Whether this report contains a non-empty array attribute that can be chunked
    /// into REPLACE-ALL + individual APPEND elements across multiple messages.
    public var canBeChunked: Bool {
        guard let data = attributeData else { return false }
        guard data.path.listIndex == nil else { return false }
        guard case .array(let elements) = data.data, !elements.isEmpty else { return false }
        return true
    }

    /// Decompose an array-valued attribute report into chunked reports.
    ///
    /// Returns:
    /// - First element: REPLACE-ALL report with the first array element packed in
    ///   (path with `listIndex` absent, data = `.array([firstElement])`)
    /// - Remaining elements: APPEND reports for each subsequent element
    ///   (path with `listIndex = .null`, data = individual element value)
    ///
    /// If `canBeChunked` is false, returns `[self]` unchanged.
    public func chunkArrayAttribute() -> [AttributeReportIB] {
        guard let data = attributeData,
              case .array(let elements) = data.data,
              !elements.isEmpty else {
            return [self]
        }

        var chunks: [AttributeReportIB] = []

        // REPLACE-ALL: same path (listIndex absent), data = array with first element
        chunks.append(AttributeReportIB(attributeData: AttributeDataIB(
            dataVersion: data.dataVersion,
            path: data.path,
            data: .array([elements[0]])
        )))

        // APPEND: path with listIndex = .null, data = individual element
        let appendPath = AttributePath(
            endpointID: data.path.endpointID,
            clusterID: data.path.clusterID,
            attributeID: data.path.attributeID,
            nodeID: data.path.nodeID,
            listIndex: .null
        )
        for element in elements.dropFirst() {
            chunks.append(AttributeReportIB(attributeData: AttributeDataIB(
                dataVersion: data.dataVersion,
                path: appendPath,
                data: element
            )))
        }

        return chunks
    }
}

// MARK: - Attribute Data IB

/// Attribute data within a report.
///
/// ```
/// Structure {
///   0: dataVersion (unsigned int)
///   1: path (AttributePath)
///   2: data (any TLV element)
/// }
/// ```
public struct AttributeDataIB: Sendable, Equatable {

    private enum Tag {
        static let dataVersion: UInt8 = 0
        static let path: UInt8 = 1
        static let data: UInt8 = 2
    }

    /// Data version for conditional writes. Optional — omitted for unconditional writes.
    public let dataVersion: DataVersion?
    public let path: AttributePath
    public let data: TLVElement

    public init(dataVersion: DataVersion? = nil, path: AttributePath, data: TLVElement) {
        self.dataVersion = dataVersion
        self.path = path
        self.data = data
    }

    public func toTLVElement() -> TLVElement {
        var fields: [TLVElement.TLVField] = []
        if let dv = dataVersion {
            fields.append(.init(tag: .contextSpecific(Tag.dataVersion), value: .unsignedInt(UInt64(dv.rawValue))))
        }
        fields.append(.init(tag: .contextSpecific(Tag.path), value: path.toTLVElement()))
        fields.append(.init(tag: .contextSpecific(Tag.data), value: data))
        // Matter spec §10.6.4 says LIST; CHIP SDK uses LIST; matter.js uses STRUCTURE.
        // Apple Home accepts both. Use STRUCTURE to match matter.js (known-working with Apple Home).
        return .structure(fields)
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> AttributeDataIB {
        // Accept both LIST (spec-correct) and STRUCTURE (for backward compatibility)
        let fields: [TLVElement.TLVField]
        switch element {
        case .list(let f): fields = f
        case .structure(let f): fields = f
        default:
            throw IMError.invalidMessage("AttributeDataIB: expected list or structure")
        }

        // dataVersion is optional — omitted for unconditional writes (e.g., Apple Home ACL writes)
        let dv = fields.first(where: { $0.tag == .contextSpecific(Tag.dataVersion) })?.value.uintValue
            .map { DataVersion(rawValue: UInt32($0)) }

        guard let pathField = fields.first(where: { $0.tag == .contextSpecific(Tag.path) }) else {
            throw IMError.invalidMessage("AttributeDataIB: missing path")
        }
        guard let dataField = fields.first(where: { $0.tag == .contextSpecific(Tag.data) }) else {
            throw IMError.invalidMessage("AttributeDataIB: missing data")
        }

        return AttributeDataIB(
            dataVersion: dv,
            path: try AttributePath.fromTLVElement(pathField.value),
            data: dataField.value
        )
    }
}

// MARK: - Attribute Status IB

/// Attribute error status within a report.
///
/// ```
/// Structure {
///   0: path (AttributePath)
///   1: status (StatusIB)
/// }
/// ```
public struct AttributeStatusIB: Sendable, Equatable {

    private enum Tag {
        static let path: UInt8 = 0
        static let status: UInt8 = 1
    }

    public let path: AttributePath
    public let status: StatusIB

    public init(path: AttributePath, status: StatusIB) {
        self.path = path
        self.status = status
    }

    public func toTLVElement() -> TLVElement {
        // Matter spec says LIST; CHIP SDK uses LIST; matter.js uses STRUCTURE.
        // Use STRUCTURE to match matter.js (known-working with Apple Home).
        .structure([
            .init(tag: .contextSpecific(Tag.path), value: path.toTLVElement()),
            .init(tag: .contextSpecific(Tag.status), value: status.toTLVElement())
        ])
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> AttributeStatusIB {
        // Accept both LIST (spec-correct) and STRUCTURE (for backward compatibility)
        let fields: [TLVElement.TLVField]
        switch element {
        case .list(let f): fields = f
        case .structure(let f): fields = f
        default:
            throw IMError.invalidMessage("AttributeStatusIB: expected list or structure")
        }
        guard let pathField = fields.first(where: { $0.tag == .contextSpecific(Tag.path) }) else {
            throw IMError.invalidMessage("AttributeStatusIB: missing path")
        }
        guard let statusField = fields.first(where: { $0.tag == .contextSpecific(Tag.status) }) else {
            throw IMError.invalidMessage("AttributeStatusIB: missing status")
        }
        return AttributeStatusIB(
            path: try AttributePath.fromTLVElement(pathField.value),
            status: try StatusIB.fromTLVElement(statusField.value)
        )
    }
}

// MARK: - Status IB

/// Status result of an IM operation.
///
/// ```
/// Structure {
///   0: status (unsigned int — IMStatusCode)
///   1: clusterStatus (unsigned int, optional)
/// }
/// ```
public struct StatusIB: Sendable, Equatable {

    private enum Tag {
        static let status: UInt8 = 0
        static let clusterStatus: UInt8 = 1
    }

    public let status: UInt8
    public let clusterStatus: UInt8?

    public init(status: UInt8, clusterStatus: UInt8? = nil) {
        self.status = status
        self.clusterStatus = clusterStatus
    }

    /// Common status: success.
    public static let success = StatusIB(status: 0x00)

    /// Common status: unsupported attribute.
    public static let unsupportedAttribute = StatusIB(status: 0x86)

    /// Common status: invalid action.
    public static let invalidAction = StatusIB(status: 0x80)

    /// Common status: unsupported command.
    public static let unsupportedCommand = StatusIB(status: 0x81)

    /// Common status: unsupported endpoint.
    public static let unsupportedEndpoint = StatusIB(status: 0x7F)

    /// Common status: unsupported write.
    public static let unsupportedWrite = StatusIB(status: 0x88)

    /// Common status: unsupported cluster.
    public static let unsupportedCluster = StatusIB(status: 0xC3)

    /// Common status: unsupported access — ACL check denied the operation.
    public static let unsupportedAccess = StatusIB(status: 0x7E)

    public func toTLVElement() -> TLVElement {
        var fields: [TLVElement.TLVField] = [
            .init(tag: .contextSpecific(Tag.status), value: .unsignedInt(UInt64(status)))
        ]
        if let cs = clusterStatus {
            fields.append(.init(tag: .contextSpecific(Tag.clusterStatus), value: .unsignedInt(UInt64(cs))))
        }
        return .structure(fields)
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> StatusIB {
        guard case .structure(let fields) = element else {
            throw IMError.invalidStatus("StatusIB: expected structure")
        }
        guard let s = fields.first(where: { $0.tag == .contextSpecific(Tag.status) })?.value.uintValue else {
            throw IMError.invalidStatus("StatusIB: missing status")
        }
        let cs = fields.first(where: { $0.tag == .contextSpecific(Tag.clusterStatus) })?.value.uintValue.map { UInt8($0) }
        return StatusIB(status: UInt8(s), clusterStatus: cs)
    }
}

// MARK: - Write Request

/// Write request — write one or more attributes.
///
/// ```
/// Structure {
///   0: suppressResponse (bool, optional)
///   1: timedRequest (bool)
///   2: writeRequests (array of AttributeDataIB)
///   3: moreChunkedMessages (bool, optional)
/// }
/// ```
public struct WriteRequest: Sendable, Equatable {

    private enum Tag {
        static let suppressResponse: UInt8 = 0
        static let timedRequest: UInt8 = 1
        static let writeRequests: UInt8 = 2
        static let moreChunkedMessages: UInt8 = 3
    }

    public let suppressResponse: Bool
    public let timedRequest: Bool
    public let writeRequests: [AttributeDataIB]
    public let moreChunkedMessages: Bool

    public init(
        suppressResponse: Bool = false,
        timedRequest: Bool = false,
        writeRequests: [AttributeDataIB],
        moreChunkedMessages: Bool = false
    ) {
        self.suppressResponse = suppressResponse
        self.timedRequest = timedRequest
        self.writeRequests = writeRequests
        self.moreChunkedMessages = moreChunkedMessages
    }

    public func tlvEncode() -> Data {
        TLVEncoder.encode(toTLVElement())
    }

    public func toTLVElement() -> TLVElement {
        var fields: [TLVElement.TLVField] = []
        if suppressResponse { fields.append(.init(tag: .contextSpecific(Tag.suppressResponse), value: .bool(true))) }
        fields.append(.init(tag: .contextSpecific(Tag.timedRequest), value: .bool(timedRequest)))
        fields.append(.init(
            tag: .contextSpecific(Tag.writeRequests),
            value: .array(writeRequests.map { $0.toTLVElement() })
        ))
        if moreChunkedMessages { fields.append(.init(tag: .contextSpecific(Tag.moreChunkedMessages), value: .bool(true))) }
        return .structure(fields)
    }

    public static func fromTLV(_ data: Data) throws -> WriteRequest {
        let (_, element) = try TLVDecoder.decode(data)
        return try fromTLVElement(element)
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> WriteRequest {
        guard case .structure(let fields) = element else {
            throw IMError.invalidMessage("WriteRequest: expected structure")
        }

        let suppress = fields.first(where: { $0.tag == .contextSpecific(Tag.suppressResponse) })?.value.boolValue ?? false
        let timed = fields.first(where: { $0.tag == .contextSpecific(Tag.timedRequest) })?.value.boolValue ?? false
        let more = fields.first(where: { $0.tag == .contextSpecific(Tag.moreChunkedMessages) })?.value.boolValue ?? false

        var writes: [AttributeDataIB] = []
        if let writesField = fields.first(where: { $0.tag == .contextSpecific(Tag.writeRequests) }),
           case .array(let elements) = writesField.value {
            writes = try elements.map { try AttributeDataIB.fromTLVElement($0) }
        }

        return WriteRequest(
            suppressResponse: suppress,
            timedRequest: timed,
            writeRequests: writes,
            moreChunkedMessages: more
        )
    }
}

// MARK: - Write Response

/// Write response — per-attribute status results.
///
/// ```
/// Structure {
///   0: writeResponses (array of AttributeStatusIB)
/// }
/// ```
public struct WriteResponse: Sendable, Equatable {

    private enum Tag {
        static let writeResponses: UInt8 = 0
    }

    public let writeResponses: [AttributeStatusIB]

    public init(writeResponses: [AttributeStatusIB]) {
        self.writeResponses = writeResponses
    }

    public func tlvEncode() -> Data {
        TLVEncoder.encode(toTLVElement())
    }

    public func toTLVElement() -> TLVElement {
        .structure([
            .init(
                tag: .contextSpecific(Tag.writeResponses),
                value: .array(writeResponses.map { $0.toTLVElement() })
            ),
            interactionModelRevisionField()
        ])
    }

    public static func fromTLV(_ data: Data) throws -> WriteResponse {
        let (_, element) = try TLVDecoder.decode(data)
        return try fromTLVElement(element)
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> WriteResponse {
        guard case .structure(let fields) = element else {
            throw IMError.invalidMessage("WriteResponse: expected structure")
        }

        var responses: [AttributeStatusIB] = []
        if let field = fields.first(where: { $0.tag == .contextSpecific(Tag.writeResponses) }),
           case .array(let elements) = field.value {
            responses = try elements.map { try AttributeStatusIB.fromTLVElement($0) }
        }

        return WriteResponse(writeResponses: responses)
    }
}

// MARK: - Invoke Request

/// Invoke command request.
///
/// ```
/// Structure {
///   0: suppressResponse (bool)
///   1: timedRequest (bool)
///   2: invokeRequests (array of CommandDataIB)
///   3: moreChunkedMessages (bool, optional)
/// }
/// ```
public struct InvokeRequest: Sendable, Equatable {

    private enum Tag {
        static let suppressResponse: UInt8 = 0
        static let timedRequest: UInt8 = 1
        static let invokeRequests: UInt8 = 2
        static let moreChunkedMessages: UInt8 = 3
    }

    public let suppressResponse: Bool
    public let timedRequest: Bool
    public let invokeRequests: [CommandDataIB]
    /// True when this is an intermediate chunk in a multi-message invoke sequence (§8.6.3).
    public let moreChunkedMessages: Bool

    public init(
        suppressResponse: Bool = false,
        timedRequest: Bool = false,
        invokeRequests: [CommandDataIB],
        moreChunkedMessages: Bool = false
    ) {
        self.suppressResponse = suppressResponse
        self.timedRequest = timedRequest
        self.invokeRequests = invokeRequests
        self.moreChunkedMessages = moreChunkedMessages
    }

    public func tlvEncode() -> Data {
        TLVEncoder.encode(toTLVElement())
    }

    public func toTLVElement() -> TLVElement {
        var fields: [TLVElement.TLVField] = [
            .init(tag: .contextSpecific(Tag.suppressResponse), value: .bool(suppressResponse)),
            .init(tag: .contextSpecific(Tag.timedRequest), value: .bool(timedRequest)),
            .init(
                tag: .contextSpecific(Tag.invokeRequests),
                value: .array(invokeRequests.map { $0.toTLVElement() })
            )
        ]
        if moreChunkedMessages {
            fields.append(.init(tag: .contextSpecific(Tag.moreChunkedMessages), value: .bool(true)))
        }
        return .structure(fields)
    }

    public static func fromTLV(_ data: Data) throws -> InvokeRequest {
        let (_, element) = try TLVDecoder.decode(data)
        return try fromTLVElement(element)
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> InvokeRequest {
        guard case .structure(let fields) = element else {
            throw IMError.invalidMessage("InvokeRequest: expected structure")
        }

        let suppress = fields.first(where: { $0.tag == .contextSpecific(Tag.suppressResponse) })?.value.boolValue ?? false
        let timed = fields.first(where: { $0.tag == .contextSpecific(Tag.timedRequest) })?.value.boolValue ?? false
        let more = fields.first(where: { $0.tag == .contextSpecific(Tag.moreChunkedMessages) })?.value.boolValue ?? false

        var cmds: [CommandDataIB] = []
        if let field = fields.first(where: { $0.tag == .contextSpecific(Tag.invokeRequests) }),
           case .array(let elements) = field.value {
            cmds = try elements.map { try CommandDataIB.fromTLVElement($0) }
        }

        return InvokeRequest(suppressResponse: suppress, timedRequest: timed, invokeRequests: cmds, moreChunkedMessages: more)
    }
}

// MARK: - Invoke Response

/// Invoke command response.
///
/// ```
/// Structure {
///   0: suppressResponse (bool)
///   1: invokeResponses (array of InvokeResponseIB)
/// }
/// ```
public struct InvokeResponse: Sendable, Equatable {

    private enum Tag {
        static let suppressResponse: UInt8 = 0
        static let invokeResponses: UInt8 = 1
    }

    public let suppressResponse: Bool
    public let invokeResponses: [InvokeResponseIB]

    public init(suppressResponse: Bool = false, invokeResponses: [InvokeResponseIB]) {
        self.suppressResponse = suppressResponse
        self.invokeResponses = invokeResponses
    }

    public func tlvEncode() -> Data {
        TLVEncoder.encode(toTLVElement())
    }

    public func toTLVElement() -> TLVElement {
        .structure([
            .init(tag: .contextSpecific(Tag.suppressResponse), value: .bool(suppressResponse)),
            .init(
                tag: .contextSpecific(Tag.invokeResponses),
                value: .array(invokeResponses.map { $0.toTLVElement() })
            ),
            interactionModelRevisionField()
        ])
    }

    public static func fromTLV(_ data: Data) throws -> InvokeResponse {
        let (_, element) = try TLVDecoder.decode(data)
        return try fromTLVElement(element)
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> InvokeResponse {
        guard case .structure(let fields) = element else {
            throw IMError.invalidMessage("InvokeResponse: expected structure")
        }

        let suppress = fields.first(where: { $0.tag == .contextSpecific(Tag.suppressResponse) })?.value.boolValue ?? false

        var responses: [InvokeResponseIB] = []
        if let field = fields.first(where: { $0.tag == .contextSpecific(Tag.invokeResponses) }),
           case .array(let elements) = field.value {
            responses = try elements.map { try InvokeResponseIB.fromTLVElement($0) }
        }

        return InvokeResponse(suppressResponse: suppress, invokeResponses: responses)
    }
}

// MARK: - Command Data IB

/// A command invocation within an InvokeRequest.
///
/// ```
/// Structure {
///   0: commandPath (CommandPath)
///   1: commandFields (structure, optional — command parameters)
/// }
/// ```
public struct CommandDataIB: Sendable, Equatable {

    private enum Tag {
        static let commandPath: UInt8 = 0
        static let commandFields: UInt8 = 1
    }

    public let commandPath: CommandPath
    public let commandFields: TLVElement?

    public init(commandPath: CommandPath, commandFields: TLVElement? = nil) {
        self.commandPath = commandPath
        self.commandFields = commandFields
    }

    public func toTLVElement() -> TLVElement {
        var fields: [TLVElement.TLVField] = [
            .init(tag: .contextSpecific(Tag.commandPath), value: commandPath.toTLVElement())
        ]
        if let cf = commandFields {
            fields.append(.init(tag: .contextSpecific(Tag.commandFields), value: cf))
        }
        return .structure(fields)
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> CommandDataIB {
        guard case .structure(let fields) = element else {
            throw IMError.invalidMessage("CommandDataIB: expected structure")
        }
        guard let pathField = fields.first(where: { $0.tag == .contextSpecific(Tag.commandPath) }) else {
            throw IMError.invalidMessage("CommandDataIB: missing commandPath")
        }
        let cf = fields.first(where: { $0.tag == .contextSpecific(Tag.commandFields) })?.value
        return CommandDataIB(
            commandPath: try CommandPath.fromTLVElement(pathField.value),
            commandFields: cf
        )
    }
}

// MARK: - Invoke Response IB

/// An individual command response within an InvokeResponse.
///
/// ```
/// Structure {
///   0: command (CommandDataIB, optional — on success with response data)
///   1: status (CommandStatusIB, optional — on status/error)
/// }
/// ```
public struct InvokeResponseIB: Sendable, Equatable {

    private enum Tag {
        static let command: UInt8 = 0
        static let status: UInt8 = 1
    }

    public let command: CommandDataIB?
    public let status: CommandStatusIB?

    public init(command: CommandDataIB) {
        self.command = command
        self.status = nil
    }

    public init(status: CommandStatusIB) {
        self.command = nil
        self.status = status
    }

    public func toTLVElement() -> TLVElement {
        var fields: [TLVElement.TLVField] = []
        if let cmd = command {
            fields.append(.init(tag: .contextSpecific(Tag.command), value: cmd.toTLVElement()))
        }
        if let st = status {
            fields.append(.init(tag: .contextSpecific(Tag.status), value: st.toTLVElement()))
        }
        return .structure(fields)
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> InvokeResponseIB {
        guard case .structure(let fields) = element else {
            throw IMError.invalidMessage("InvokeResponseIB: expected structure")
        }
        if let cmdField = fields.first(where: { $0.tag == .contextSpecific(Tag.command) }) {
            return InvokeResponseIB(command: try CommandDataIB.fromTLVElement(cmdField.value))
        }
        if let stField = fields.first(where: { $0.tag == .contextSpecific(Tag.status) }) {
            return InvokeResponseIB(status: try CommandStatusIB.fromTLVElement(stField.value))
        }
        throw IMError.invalidMessage("InvokeResponseIB: neither command nor status present")
    }
}

// MARK: - Command Status IB

/// Status result for a command invocation.
///
/// ```
/// Structure {
///   0: commandPath (CommandPath)
///   1: status (StatusIB)
/// }
/// ```
public struct CommandStatusIB: Sendable, Equatable {

    private enum Tag {
        static let commandPath: UInt8 = 0
        static let status: UInt8 = 1
    }

    public let commandPath: CommandPath
    public let status: StatusIB

    public init(commandPath: CommandPath, status: StatusIB) {
        self.commandPath = commandPath
        self.status = status
    }

    public func toTLVElement() -> TLVElement {
        .structure([
            .init(tag: .contextSpecific(Tag.commandPath), value: commandPath.toTLVElement()),
            .init(tag: .contextSpecific(Tag.status), value: status.toTLVElement())
        ])
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> CommandStatusIB {
        guard case .structure(let fields) = element else {
            throw IMError.invalidMessage("CommandStatusIB: expected structure")
        }
        guard let pathField = fields.first(where: { $0.tag == .contextSpecific(Tag.commandPath) }) else {
            throw IMError.invalidMessage("CommandStatusIB: missing commandPath")
        }
        guard let statusField = fields.first(where: { $0.tag == .contextSpecific(Tag.status) }) else {
            throw IMError.invalidMessage("CommandStatusIB: missing status")
        }
        return CommandStatusIB(
            commandPath: try CommandPath.fromTLVElement(pathField.value),
            status: try StatusIB.fromTLVElement(statusField.value)
        )
    }
}

// MARK: - IM Status Response

/// Status response — acknowledges receipt of a prior IM message.
///
/// ```
/// Structure {
///   0: status (unsigned int — IMStatusCode)
/// }
/// ```
public struct IMStatusResponse: Sendable, Equatable {

    public let status: UInt8

    public init(status: UInt8) {
        self.status = status
    }

    public static let success = IMStatusResponse(status: 0x00)

    public func tlvEncode() -> Data {
        TLVEncoder.encode(.structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(UInt64(status))),
            interactionModelRevisionField()
        ]))
    }

    public static func fromTLV(_ data: Data) throws -> IMStatusResponse {
        let (_, element) = try TLVDecoder.decode(data)
        guard case .structure(let fields) = element,
              let s = fields.first(where: { $0.tag == .contextSpecific(0) })?.value.uintValue else {
            throw IMError.invalidMessage("IMStatusResponse: expected structure with status")
        }
        return IMStatusResponse(status: UInt8(s))
    }
}

// MARK: - Subscribe Request

/// Subscribe request — subscribe to one or more attributes and/or events.
///
/// ```
/// Structure {
///   0: keepSubscriptions (bool)
///   1: minIntervalFloor (unsigned int)
///   2: maxIntervalCeiling (unsigned int)
///   3: attributeRequests (array of AttributePath, optional)
///   4: eventRequests (array of EventPath, optional)
///   5: eventFilters (array of EventFilter, optional)
///   7: isFabricFiltered (bool)
/// }
/// ```
public struct SubscribeRequest: Sendable, Equatable {

    private enum Tag {
        static let keepSubscriptions: UInt8 = 0
        static let minIntervalFloor: UInt8 = 1
        static let maxIntervalCeiling: UInt8 = 2
        static let attributeRequests: UInt8 = 3
        static let eventRequests: UInt8 = 4
        static let eventFilters: UInt8 = 5
        static let dataVersionFilters: UInt8 = 6
        static let isFabricFiltered: UInt8 = 7
    }

    public let keepSubscriptions: Bool
    public let minIntervalFloor: UInt16
    public let maxIntervalCeiling: UInt16
    public let attributeRequests: [AttributePath]
    public let eventRequests: [EventPath]
    public let eventFilters: [EventFilterIB]
    public let dataVersionFilters: [DataVersionFilter]
    public let isFabricFiltered: Bool

    public init(
        keepSubscriptions: Bool = true,
        minIntervalFloor: UInt16,
        maxIntervalCeiling: UInt16,
        attributeRequests: [AttributePath] = [],
        eventRequests: [EventPath] = [],
        eventFilters: [EventFilterIB] = [],
        dataVersionFilters: [DataVersionFilter] = [],
        isFabricFiltered: Bool = true
    ) {
        self.keepSubscriptions = keepSubscriptions
        self.minIntervalFloor = minIntervalFloor
        self.maxIntervalCeiling = maxIntervalCeiling
        self.attributeRequests = attributeRequests
        self.eventRequests = eventRequests
        self.eventFilters = eventFilters
        self.dataVersionFilters = dataVersionFilters
        self.isFabricFiltered = isFabricFiltered
    }

    public func tlvEncode() -> Data {
        TLVEncoder.encode(toTLVElement())
    }

    public func toTLVElement() -> TLVElement {
        var fields: [TLVElement.TLVField] = []

        fields.append(.init(tag: .contextSpecific(Tag.keepSubscriptions), value: .bool(keepSubscriptions)))
        fields.append(.init(tag: .contextSpecific(Tag.minIntervalFloor), value: .unsignedInt(UInt64(minIntervalFloor))))
        fields.append(.init(tag: .contextSpecific(Tag.maxIntervalCeiling), value: .unsignedInt(UInt64(maxIntervalCeiling))))

        if !attributeRequests.isEmpty {
            fields.append(.init(
                tag: .contextSpecific(Tag.attributeRequests),
                value: .array(attributeRequests.map { $0.toTLVElement() })
            ))
        }

        if !eventRequests.isEmpty {
            fields.append(.init(
                tag: .contextSpecific(Tag.eventRequests),
                value: .array(eventRequests.map { $0.toTLVElement() })
            ))
        }

        if !eventFilters.isEmpty {
            fields.append(.init(
                tag: .contextSpecific(Tag.eventFilters),
                value: .array(eventFilters.map { $0.toTLVElement() })
            ))
        }

        if !dataVersionFilters.isEmpty {
            fields.append(.init(
                tag: .contextSpecific(Tag.dataVersionFilters),
                value: .array(dataVersionFilters.map { $0.toTLVElement() })
            ))
        }

        fields.append(.init(tag: .contextSpecific(Tag.isFabricFiltered), value: .bool(isFabricFiltered)))

        return .structure(fields)
    }

    public static func fromTLV(_ data: Data) throws -> SubscribeRequest {
        let (_, element) = try TLVDecoder.decode(data)
        return try fromTLVElement(element)
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> SubscribeRequest {
        guard case .structure(let fields) = element else {
            throw IMError.invalidMessage("SubscribeRequest: expected structure")
        }

        let keepSubs = fields.first(where: { $0.tag == .contextSpecific(Tag.keepSubscriptions) })?.value.boolValue ?? true

        guard let minFloor = fields.first(where: { $0.tag == .contextSpecific(Tag.minIntervalFloor) })?.value.uintValue else {
            throw IMError.invalidMessage("SubscribeRequest: missing minIntervalFloor")
        }
        guard let maxCeiling = fields.first(where: { $0.tag == .contextSpecific(Tag.maxIntervalCeiling) })?.value.uintValue else {
            throw IMError.invalidMessage("SubscribeRequest: missing maxIntervalCeiling")
        }

        var attrPaths: [AttributePath] = []
        if let attrField = fields.first(where: { $0.tag == .contextSpecific(Tag.attributeRequests) }),
           case .array(let elements) = attrField.value {
            attrPaths = try elements.map { try AttributePath.fromTLVElement($0) }
        }

        var eventPaths: [EventPath] = []
        if let eventField = fields.first(where: { $0.tag == .contextSpecific(Tag.eventRequests) }),
           case .array(let elements) = eventField.value {
            eventPaths = try elements.map { try EventPath.fromTLVElement($0) }
        }

        var eventFilters: [EventFilterIB] = []
        if let filterField = fields.first(where: { $0.tag == .contextSpecific(Tag.eventFilters) }),
           case .array(let elements) = filterField.value {
            eventFilters = try elements.map { try EventFilterIB.fromTLVElement($0) }
        }

        var dvFilters: [DataVersionFilter] = []
        if let dvField = fields.first(where: { $0.tag == .contextSpecific(Tag.dataVersionFilters) }),
           case .array(let elements) = dvField.value {
            dvFilters = try elements.map { try DataVersionFilter.fromTLVElement($0) }
        }

        let isFabricFiltered = fields.first(where: { $0.tag == .contextSpecific(Tag.isFabricFiltered) })?.value.boolValue ?? true

        return SubscribeRequest(
            keepSubscriptions: keepSubs,
            minIntervalFloor: UInt16(minFloor),
            maxIntervalCeiling: UInt16(maxCeiling),
            attributeRequests: attrPaths,
            eventRequests: eventPaths,
            eventFilters: eventFilters,
            dataVersionFilters: dvFilters,
            isFabricFiltered: isFabricFiltered
        )
    }
}

// MARK: - Timed Request

/// Timed interaction request — establishes a time-bounded window for a subsequent
/// write or invoke.
///
/// ```
/// Structure {
///   0: timeout (unsigned int — milliseconds)
/// }
/// ```
public struct TimedRequest: Sendable, Equatable {

    private enum Tag {
        static let timeoutMs: UInt8 = 0
    }

    /// Timeout in milliseconds. The subsequent write or invoke must arrive within this window.
    public let timeoutMs: UInt16

    public init(timeoutMs: UInt16) {
        self.timeoutMs = timeoutMs
    }

    public func tlvEncode() -> Data {
        TLVEncoder.encode(.structure([
            .init(tag: .contextSpecific(Tag.timeoutMs), value: .unsignedInt(UInt64(timeoutMs)))
        ]))
    }

    public static func fromTLV(_ data: Data) throws -> TimedRequest {
        let (_, element) = try TLVDecoder.decode(data)
        guard case .structure(let fields) = element,
              let ms = fields.first(where: { $0.tag == .contextSpecific(Tag.timeoutMs) })?.value.uintValue else {
            throw IMError.invalidMessage("TimedRequest: expected structure with timeout")
        }
        return TimedRequest(timeoutMs: UInt16(min(ms, UInt64(UInt16.max))))
    }
}

// MARK: - Data Version Filter

/// A client-supplied data version filter for a specific cluster path.
///
/// If the server's current `dataVersion` for `(endpointID, clusterID)` matches the
/// client's cached `dataVersion`, the server omits all attributes for that cluster
/// from the response — the cluster's data has not changed since the client last read it.
///
/// Per Matter spec §8.5.1.
///
/// TLV structure:
/// ```
/// Structure {
///   0: path (Structure { 0: endpointID (unsigned int), 1: clusterID (unsigned int) })
///   1: dataVersion (unsigned int)
/// }
/// ```
public struct DataVersionFilter: Sendable, Equatable {

    private enum Tag {
        static let path: UInt8 = 0
        static let dataVersion: UInt8 = 1
    }

    private enum PathTag {
        static let endpointID: UInt8 = 0
        static let clusterID: UInt8 = 1
    }

    /// The endpoint containing the cluster to filter.
    public let endpointID: EndpointID
    /// The cluster to filter.
    public let clusterID: ClusterID
    /// The client's cached data version for this cluster.
    public let dataVersion: UInt32

    public init(endpointID: EndpointID, clusterID: ClusterID, dataVersion: UInt32) {
        self.endpointID = endpointID
        self.clusterID = clusterID
        self.dataVersion = dataVersion
    }

    public func toTLVElement() -> TLVElement {
        let pathElement = TLVElement.structure([
            .init(tag: .contextSpecific(PathTag.endpointID), value: .unsignedInt(UInt64(endpointID.rawValue))),
            .init(tag: .contextSpecific(PathTag.clusterID), value: .unsignedInt(UInt64(clusterID.rawValue)))
        ])
        return .structure([
            .init(tag: .contextSpecific(Tag.path), value: pathElement),
            .init(tag: .contextSpecific(Tag.dataVersion), value: .unsignedInt(UInt64(dataVersion)))
        ])
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> DataVersionFilter {
        guard case .structure(let fields) = element else {
            throw IMError.invalidMessage("DataVersionFilter: expected structure")
        }

        guard let pathField = fields.first(where: { $0.tag == .contextSpecific(Tag.path) }) else {
            throw IMError.invalidMessage("DataVersionFilter: missing path")
        }
        guard case .structure(let pathFields) = pathField.value else {
            throw IMError.invalidMessage("DataVersionFilter: path must be a structure")
        }
        guard let epRaw = pathFields.first(where: { $0.tag == .contextSpecific(PathTag.endpointID) })?.value.uintValue else {
            throw IMError.invalidMessage("DataVersionFilter: missing endpointID in path")
        }
        guard let clRaw = pathFields.first(where: { $0.tag == .contextSpecific(PathTag.clusterID) })?.value.uintValue else {
            throw IMError.invalidMessage("DataVersionFilter: missing clusterID in path")
        }
        guard let dvRaw = fields.first(where: { $0.tag == .contextSpecific(Tag.dataVersion) })?.value.uintValue else {
            throw IMError.invalidMessage("DataVersionFilter: missing dataVersion")
        }

        return DataVersionFilter(
            endpointID: EndpointID(rawValue: UInt16(epRaw)),
            clusterID: ClusterID(rawValue: UInt32(clRaw)),
            dataVersion: UInt32(dvRaw)
        )
    }
}

// MARK: - Subscribe Response

/// Subscribe response — confirms a subscription with negotiated interval.
///
/// ```
/// Structure {
///   0: subscriptionID (unsigned int)
///   1: maxInterval (unsigned int)
/// }
/// ```
public struct SubscribeResponse: Sendable, Equatable {

    private enum Tag {
        static let subscriptionID: UInt8 = 0
        // Tag 1 is reserved (was used in older spec drafts).
        // The Matter spec and CHIP SDK use tag 2 for MaxInterval.
        static let maxInterval: UInt8 = 2
    }

    public let subscriptionID: SubscriptionID
    public let maxInterval: UInt16

    public init(subscriptionID: SubscriptionID, maxInterval: UInt16) {
        self.subscriptionID = subscriptionID
        self.maxInterval = maxInterval
    }

    public func tlvEncode() -> Data {
        TLVEncoder.encode(toTLVElement())
    }

    public func toTLVElement() -> TLVElement {
        .structure([
            .init(tag: .contextSpecific(Tag.subscriptionID), value: .unsignedInt(UInt64(subscriptionID.rawValue))),
            .init(tag: .contextSpecific(Tag.maxInterval), value: .unsignedInt(UInt64(maxInterval))),
            interactionModelRevisionField()
        ])
    }

    public static func fromTLV(_ data: Data) throws -> SubscribeResponse {
        let (_, element) = try TLVDecoder.decode(data)
        return try fromTLVElement(element)
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> SubscribeResponse {
        guard case .structure(let fields) = element else {
            throw IMError.invalidMessage("SubscribeResponse: expected structure")
        }

        guard let sid = fields.first(where: { $0.tag == .contextSpecific(Tag.subscriptionID) })?.value.uintValue else {
            throw IMError.invalidMessage("SubscribeResponse: missing subscriptionID")
        }
        guard let maxInt = fields.first(where: { $0.tag == .contextSpecific(Tag.maxInterval) })?.value.uintValue else {
            throw IMError.invalidMessage("SubscribeResponse: missing maxInterval")
        }

        return SubscribeResponse(
            subscriptionID: SubscriptionID(rawValue: UInt32(sid)),
            maxInterval: UInt16(maxInt)
        )
    }
}
