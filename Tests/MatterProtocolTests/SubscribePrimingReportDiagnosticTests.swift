// SubscribePrimingReportDiagnosticTests.swift
// Copyright 2026 Monagle Pty Ltd
//
// Diagnostic tests that simulate a subscribe priming report matching a real
// bridge configuration (root endpoint + aggregator + dimmable light).
// These tests validate that chunked report TLV encoding is structurally
// correct by re-decoding each chunk and independently validating the
// raw TLV byte stream.

import Testing
import Foundation
import MatterTypes
@testable import MatterProtocol

@Suite("Subscribe Priming Report Diagnostics")
struct SubscribePrimingReportDiagnosticTests {

    // MARK: - TLV Byte-Level Validator

    /// Independently validates a TLV byte stream for structural integrity.
    /// Returns nil on success or a description of the first error found.
    private func validateTLVBytes(_ data: Data) -> String? {
        var offset = 0
        var containerStack: [UInt8] = [] // Stack of container type bytes

        while offset < data.count {
            let controlByte = data[offset]
            let elementType = controlByte & 0x1F
            let tagForm = controlByte & 0xE0

            // End-of-container (0x18)
            if elementType == 0x18 {
                if containerStack.isEmpty {
                    return "Unexpected end-of-container at offset \(offset) — no open container"
                }
                containerStack.removeLast()
                offset += 1
                // If we've closed the outermost container, we should be done
                if containerStack.isEmpty && offset < data.count {
                    return "Trailing bytes after outermost container closed at offset \(offset) — \(data.count - offset) bytes remain"
                }
                continue
            }

            offset += 1 // past control byte

            // Consume tag bytes
            switch tagForm {
            case 0x00: break // anonymous — 0 tag bytes
            case 0x20: // context-specific — 1 tag byte
                guard offset < data.count else {
                    return "Truncated context-specific tag at offset \(offset - 1)"
                }
                offset += 1
            case 0x40: // common profile 2-byte tag
                guard offset + 2 <= data.count else {
                    return "Truncated common-profile-2 tag at offset \(offset - 1)"
                }
                offset += 2
            case 0x60: // common profile 4-byte tag
                guard offset + 4 <= data.count else {
                    return "Truncated common-profile-4 tag at offset \(offset - 1)"
                }
                offset += 4
            case 0x80: // fully qualified 6-byte tag
                guard offset + 6 <= data.count else {
                    return "Truncated fully-qualified-6 tag at offset \(offset - 1)"
                }
                offset += 6
            case 0xA0: // fully qualified 8-byte tag
                guard offset + 8 <= data.count else {
                    return "Truncated fully-qualified-8 tag at offset \(offset - 1)"
                }
                offset += 8
            default:
                return "Unknown tag form 0x\(String(tagForm, radix: 16)) at offset \(offset - 1)"
            }

            // Consume value bytes based on element type
            switch elementType {
            case 0x00: // signed int 1B
                guard offset + 1 <= data.count else { return "Truncated signedInt1 at offset \(offset)" }
                offset += 1
            case 0x01: // signed int 2B
                guard offset + 2 <= data.count else { return "Truncated signedInt2 at offset \(offset)" }
                offset += 2
            case 0x02: // signed int 4B
                guard offset + 4 <= data.count else { return "Truncated signedInt4 at offset \(offset)" }
                offset += 4
            case 0x03: // signed int 8B
                guard offset + 8 <= data.count else { return "Truncated signedInt8 at offset \(offset)" }
                offset += 8
            case 0x04: // unsigned int 1B
                guard offset + 1 <= data.count else { return "Truncated unsignedInt1 at offset \(offset)" }
                offset += 1
            case 0x05: // unsigned int 2B
                guard offset + 2 <= data.count else { return "Truncated unsignedInt2 at offset \(offset)" }
                offset += 2
            case 0x06: // unsigned int 4B
                guard offset + 4 <= data.count else { return "Truncated unsignedInt4 at offset \(offset)" }
                offset += 4
            case 0x07: // unsigned int 8B
                guard offset + 8 <= data.count else { return "Truncated unsignedInt8 at offset \(offset)" }
                offset += 8
            case 0x08, 0x09: // bool false, bool true
                break // no value bytes
            case 0x0A: // float 4B
                guard offset + 4 <= data.count else { return "Truncated float4 at offset \(offset)" }
                offset += 4
            case 0x0B: // float 8B (double)
                guard offset + 8 <= data.count else { return "Truncated float8 at offset \(offset)" }
                offset += 8
            case 0x0C: // utf8 string 1B length
                guard offset + 1 <= data.count else { return "Truncated utf8String1 length at offset \(offset)" }
                let len = Int(data[offset])
                offset += 1
                guard offset + len <= data.count else {
                    return "Truncated utf8String1 value at offset \(offset) — need \(len) bytes, have \(data.count - offset)"
                }
                offset += len
            case 0x0D: // utf8 string 2B length
                guard offset + 2 <= data.count else { return "Truncated utf8String2 length at offset \(offset)" }
                let len = Int(data[offset]) | (Int(data[offset + 1]) << 8)
                offset += 2
                guard offset + len <= data.count else {
                    return "Truncated utf8String2 value at offset \(offset) — need \(len) bytes, have \(data.count - offset)"
                }
                offset += len
            case 0x0E: // utf8 string 4B length
                guard offset + 4 <= data.count else { return "Truncated utf8String4 length at offset \(offset)" }
                let len = Int(data[offset]) | (Int(data[offset + 1]) << 8)
                    | (Int(data[offset + 2]) << 16) | (Int(data[offset + 3]) << 24)
                offset += 4
                guard offset + len <= data.count else {
                    return "Truncated utf8String4 value at offset \(offset)"
                }
                offset += len
            case 0x10: // octet string 1B length
                guard offset + 1 <= data.count else { return "Truncated octetString1 length at offset \(offset)" }
                let len = Int(data[offset])
                offset += 1
                guard offset + len <= data.count else {
                    return "Truncated octetString1 value at offset \(offset) — need \(len) bytes, have \(data.count - offset)"
                }
                offset += len
            case 0x11: // octet string 2B length
                guard offset + 2 <= data.count else { return "Truncated octetString2 length at offset \(offset)" }
                let len = Int(data[offset]) | (Int(data[offset + 1]) << 8)
                offset += 2
                guard offset + len <= data.count else {
                    return "Truncated octetString2 value at offset \(offset)"
                }
                offset += len
            case 0x12: // octet string 4B length
                guard offset + 4 <= data.count else { return "Truncated octetString4 length at offset \(offset)" }
                let len = Int(data[offset]) | (Int(data[offset + 1]) << 8)
                    | (Int(data[offset + 2]) << 16) | (Int(data[offset + 3]) << 24)
                offset += 4
                guard offset + len <= data.count else {
                    return "Truncated octetString4 value at offset \(offset)"
                }
                offset += len
            case 0x14: // null
                break // no value bytes
            case 0x15, 0x16, 0x17: // structure, array, list
                containerStack.append(elementType)
            default:
                return "Unknown element type 0x\(String(elementType, radix: 16)) at offset \(offset - 1)"
            }
        }

        if !containerStack.isEmpty {
            return "Unclosed containers at end of stream: \(containerStack.count) container(s) open"
        }
        return nil // success
    }

    // MARK: - Realistic Attribute Report Builder

    /// Build an attribute report with a specific value.
    private func report(
        ep: UInt16, cl: UInt32, attr: UInt32,
        value: TLVElement, dataVersion: UInt32 = 1
    ) -> AttributeReportIB {
        AttributeReportIB(attributeData: AttributeDataIB(
            dataVersion: DataVersion(rawValue: dataVersion),
            path: AttributePath(
                endpointID: EndpointID(rawValue: ep),
                clusterID: ClusterID(rawValue: cl),
                attributeID: AttributeID(rawValue: attr)
            ),
            data: value
        ))
    }

    /// Build global attribute reports for a cluster.
    private func globalReports(
        ep: UInt16, cl: UInt32,
        attrIDs: [UInt32],
        acceptedCmds: [UInt32] = [],
        generatedCmds: [UInt32] = [],
        clusterRevision: UInt16 = 1,
        featureMap: UInt32 = 0
    ) -> [AttributeReportIB] {
        [
            report(ep: ep, cl: cl, attr: 0xFFF8,
                   value: .array(generatedCmds.map { .unsignedInt(UInt64($0)) })),
            report(ep: ep, cl: cl, attr: 0xFFF9,
                   value: .array(acceptedCmds.map { .unsignedInt(UInt64($0)) })),
            report(ep: ep, cl: cl, attr: 0xFFFB,
                   value: .array(attrIDs.map { .unsignedInt(UInt64($0)) })),
            report(ep: ep, cl: cl, attr: 0xFFFC,
                   value: .unsignedInt(UInt64(featureMap))),
            report(ep: ep, cl: cl, attr: 0xFFFD,
                   value: .unsignedInt(UInt64(clusterRevision))),
        ]
    }

    /// Build all attribute reports for a realistic bridge (root + aggregator + dimmable light).
    private func buildRealisticBridgeReports() -> [AttributeReportIB] {
        var reports: [AttributeReportIB] = []

        // === Endpoint 0: Root Node ===

        // Descriptor (0x001D)
        let ep0DescAttrs: [UInt32] = [0x0000, 0x0001, 0x0002, 0x0003, 0xFFF8, 0xFFF9, 0xFFFB, 0xFFFC, 0xFFFD]
        reports.append(report(ep: 0, cl: 0x001D, attr: 0x0000,
            value: .array([
                .structure([
                    .init(tag: .contextSpecific(0), value: .unsignedInt(0x0016)), // rootNode
                    .init(tag: .contextSpecific(1), value: .unsignedInt(1))
                ])
            ])))
        reports.append(report(ep: 0, cl: 0x001D, attr: 0x0001,
            value: .array([0x001D, 0x001F, 0x0028, 0x0030, 0x0031, 0x0033, 0x0038, 0x003C, 0x003E, 0x003F].map {
                .unsignedInt(UInt64($0))
            })))
        reports.append(report(ep: 0, cl: 0x001D, attr: 0x0002, value: .array([])))
        reports.append(report(ep: 0, cl: 0x001D, attr: 0x0003,
            value: .array([.unsignedInt(1), .unsignedInt(3)])))
        reports += globalReports(ep: 0, cl: 0x001D, attrIDs: ep0DescAttrs)

        // AccessControl (0x001F)
        let aclEntry = TLVElement.structure([
            .init(tag: .contextSpecific(1), value: .unsignedInt(5)), // Administer
            .init(tag: .contextSpecific(2), value: .unsignedInt(2)), // CASE
            .init(tag: .contextSpecific(3), value: .array([.unsignedInt(112233)])),
            .init(tag: .contextSpecific(4), value: .null),
            .init(tag: .contextSpecific(0xFE), value: .unsignedInt(1)) // fabricIndex
        ])
        let aclAttrs: [UInt32] = [0x0000, 0x0001, 0xFFF8, 0xFFF9, 0xFFFB, 0xFFFC, 0xFFFD]
        reports.append(report(ep: 0, cl: 0x001F, attr: 0x0000, value: .array([aclEntry])))
        reports.append(report(ep: 0, cl: 0x001F, attr: 0x0001, value: .array([])))
        reports += globalReports(ep: 0, cl: 0x001F, attrIDs: aclAttrs)

        // BasicInformation (0x0028)
        let biAttrs: [UInt32] = [0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000A, 0x0012, 0x0013,
                                  0xFFF8, 0xFFF9, 0xFFFB, 0xFFFC, 0xFFFD]
        reports.append(report(ep: 0, cl: 0x0028, attr: 0x0000, value: .unsignedInt(1))) // dataModelRevision
        reports.append(report(ep: 0, cl: 0x0028, attr: 0x0001, value: .utf8String("TestVendor")))
        reports.append(report(ep: 0, cl: 0x0028, attr: 0x0002, value: .unsignedInt(0xFFF1)))
        reports.append(report(ep: 0, cl: 0x0028, attr: 0x0003, value: .utf8String("TestBridge")))
        reports.append(report(ep: 0, cl: 0x0028, attr: 0x0004, value: .unsignedInt(0x8000)))
        reports.append(report(ep: 0, cl: 0x0028, attr: 0x0005, value: .utf8String("")))
        reports.append(report(ep: 0, cl: 0x0028, attr: 0x0006, value: .utf8String("US")))
        reports.append(report(ep: 0, cl: 0x0028, attr: 0x0007, value: .unsignedInt(0)))
        reports.append(report(ep: 0, cl: 0x0028, attr: 0x0008, value: .utf8String("1.0")))
        reports.append(report(ep: 0, cl: 0x0028, attr: 0x0009, value: .unsignedInt(1)))
        reports.append(report(ep: 0, cl: 0x0028, attr: 0x000A, value: .utf8String("1.0")))
        reports.append(report(ep: 0, cl: 0x0028, attr: 0x0012, value: .utf8String("AABB-1122-3344")))
        // capabilityMinima (0x0013)
        reports.append(report(ep: 0, cl: 0x0028, attr: 0x0013, value: .structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(3)),  // caseSessionsPerFabric
            .init(tag: .contextSpecific(1), value: .unsignedInt(3))   // subscriptionsPerFabric
        ])))
        reports += globalReports(ep: 0, cl: 0x0028, attrIDs: biAttrs)

        // GeneralCommissioning (0x0030)
        let gcAttrs: [UInt32] = [0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0xFFF8, 0xFFF9, 0xFFFB, 0xFFFC, 0xFFFD]
        reports.append(report(ep: 0, cl: 0x0030, attr: 0x0000, value: .unsignedInt(0))) // breadcrumb
        reports.append(report(ep: 0, cl: 0x0030, attr: 0x0001, value: .structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(60)),
            .init(tag: .contextSpecific(1), value: .unsignedInt(900))
        ])))
        reports.append(report(ep: 0, cl: 0x0030, attr: 0x0002, value: .unsignedInt(0))) // regulatoryConfig
        reports.append(report(ep: 0, cl: 0x0030, attr: 0x0003, value: .unsignedInt(2))) // locationCapability
        reports.append(report(ep: 0, cl: 0x0030, attr: 0x0004, value: .bool(true)))
        reports += globalReports(ep: 0, cl: 0x0030, attrIDs: gcAttrs,
                                 acceptedCmds: [0, 2, 4], generatedCmds: [1, 3, 5])

        // NetworkCommissioning (0x0031)
        let ncAttrs: [UInt32] = [0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007,
                                  0xFFF8, 0xFFF9, 0xFFFB, 0xFFFC, 0xFFFD]
        reports.append(report(ep: 0, cl: 0x0031, attr: 0x0000, value: .unsignedInt(1)))
        let networkEntry = TLVElement.structure([
            .init(tag: .contextSpecific(0), value: .octetString(Data("en0".utf8))),
            .init(tag: .contextSpecific(1), value: .bool(true))
        ])
        reports.append(report(ep: 0, cl: 0x0031, attr: 0x0001, value: .array([networkEntry])))
        reports.append(report(ep: 0, cl: 0x0031, attr: 0x0002, value: .unsignedInt(30)))
        reports.append(report(ep: 0, cl: 0x0031, attr: 0x0003, value: .unsignedInt(60)))
        reports.append(report(ep: 0, cl: 0x0031, attr: 0x0004, value: .bool(true)))
        reports.append(report(ep: 0, cl: 0x0031, attr: 0x0005, value: .unsignedInt(0)))
        reports.append(report(ep: 0, cl: 0x0031, attr: 0x0006, value: .octetString(Data("en0".utf8))))
        reports.append(report(ep: 0, cl: 0x0031, attr: 0x0007, value: .signedInt(0)))
        reports += globalReports(ep: 0, cl: 0x0031, attrIDs: ncAttrs, featureMap: 0x04)

        // GeneralDiagnostics (0x0033)
        let gdAttrs: [UInt32] = [0x0000, 0x0001, 0x0002, 0x0004, 0xFFF8, 0xFFF9, 0xFFFB, 0xFFFC, 0xFFFD]
        let netIface = TLVElement.structure([
            .init(tag: .contextSpecific(0), value: .utf8String("en0")),
            .init(tag: .contextSpecific(1), value: .bool(true)),
            .init(tag: .contextSpecific(2), value: .null),
            .init(tag: .contextSpecific(3), value: .null),
            .init(tag: .contextSpecific(4), value: .octetString(Data(count: 6))),
            .init(tag: .contextSpecific(5), value: .array([])),
            .init(tag: .contextSpecific(6), value: .array([])),
            .init(tag: .contextSpecific(7), value: .unsignedInt(0))
        ])
        reports.append(report(ep: 0, cl: 0x0033, attr: 0x0000, value: .array([netIface])))
        reports.append(report(ep: 0, cl: 0x0033, attr: 0x0001, value: .unsignedInt(0)))
        reports.append(report(ep: 0, cl: 0x0033, attr: 0x0002, value: .unsignedInt(100)))
        reports.append(report(ep: 0, cl: 0x0033, attr: 0x0004, value: .unsignedInt(1)))
        reports += globalReports(ep: 0, cl: 0x0033, attrIDs: gdAttrs)

        // TimeSynchronization (0x0038) — minimal
        let tsAttrs: [UInt32] = [0xFFF8, 0xFFF9, 0xFFFB, 0xFFFC, 0xFFFD]
        reports += globalReports(ep: 0, cl: 0x0038, attrIDs: tsAttrs)

        // AdminCommissioning (0x003C)
        let acAttrs: [UInt32] = [0x0000, 0x0001, 0x0002, 0xFFF8, 0xFFF9, 0xFFFB, 0xFFFC, 0xFFFD]
        reports.append(report(ep: 0, cl: 0x003C, attr: 0x0000, value: .unsignedInt(0)))
        reports.append(report(ep: 0, cl: 0x003C, attr: 0x0001, value: .null))
        reports.append(report(ep: 0, cl: 0x003C, attr: 0x0002, value: .null))
        reports += globalReports(ep: 0, cl: 0x003C, attrIDs: acAttrs, acceptedCmds: [0, 1, 2])

        // OperationalCredentials (0x003E)
        let ocAttrs: [UInt32] = [0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005,
                                  0xFFF8, 0xFFF9, 0xFFFB, 0xFFFC, 0xFFFD]
        reports.append(report(ep: 0, cl: 0x003E, attr: 0x0000, value: .array([])))
        reports.append(report(ep: 0, cl: 0x003E, attr: 0x0001, value: .array([])))
        reports.append(report(ep: 0, cl: 0x003E, attr: 0x0002, value: .unsignedInt(5)))
        reports.append(report(ep: 0, cl: 0x003E, attr: 0x0003, value: .unsignedInt(1)))
        reports.append(report(ep: 0, cl: 0x003E, attr: 0x0004, value: .array([])))
        reports.append(report(ep: 0, cl: 0x003E, attr: 0x0005, value: .unsignedInt(1)))
        reports += globalReports(ep: 0, cl: 0x003E, attrIDs: ocAttrs,
                                 acceptedCmds: [0x0004, 0x0006, 0x0007, 0x0009, 0x000B],
                                 generatedCmds: [0x0001, 0x0003, 0x0005, 0x0008])

        // GroupKeyManagement (0x003F)
        let gkmAttrs: [UInt32] = [0x0000, 0x0001, 0x0002, 0x0003, 0xFFF8, 0xFFF9, 0xFFFB, 0xFFFC, 0xFFFD]
        reports.append(report(ep: 0, cl: 0x003F, attr: 0x0000, value: .array([])))
        reports.append(report(ep: 0, cl: 0x003F, attr: 0x0001, value: .array([])))
        reports.append(report(ep: 0, cl: 0x003F, attr: 0x0002, value: .unsignedInt(1)))
        reports.append(report(ep: 0, cl: 0x003F, attr: 0x0003, value: .unsignedInt(1)))
        reports += globalReports(ep: 0, cl: 0x003F, attrIDs: gkmAttrs, acceptedCmds: [0, 1, 3])

        // === Endpoint 1: Aggregator ===
        let ep1DescAttrs: [UInt32] = [0x0000, 0x0001, 0x0002, 0x0003, 0xFFF8, 0xFFF9, 0xFFFB, 0xFFFC, 0xFFFD]
        reports.append(report(ep: 1, cl: 0x001D, attr: 0x0000, value: .array([
            .structure([
                .init(tag: .contextSpecific(0), value: .unsignedInt(0x000E)),
                .init(tag: .contextSpecific(1), value: .unsignedInt(1))
            ])
        ])))
        reports.append(report(ep: 1, cl: 0x001D, attr: 0x0001, value: .array([.unsignedInt(0x001D)])))
        reports.append(report(ep: 1, cl: 0x001D, attr: 0x0002, value: .array([])))
        reports.append(report(ep: 1, cl: 0x001D, attr: 0x0003, value: .array([.unsignedInt(3)])))
        reports += globalReports(ep: 1, cl: 0x001D, attrIDs: ep1DescAttrs)

        // === Endpoint 3: Dimmable Light ===

        // OnOff (0x0006)
        let ooAttrs: [UInt32] = [0x0000, 0xFFF8, 0xFFF9, 0xFFFB, 0xFFFC, 0xFFFD]
        reports.append(report(ep: 3, cl: 0x0006, attr: 0x0000, value: .bool(false)))
        reports += globalReports(ep: 3, cl: 0x0006, attrIDs: ooAttrs, acceptedCmds: [0, 1, 2])

        // LevelControl (0x0008)
        let lcAttrs: [UInt32] = [0x0000, 0xFFF8, 0xFFF9, 0xFFFB, 0xFFFC, 0xFFFD]
        reports.append(report(ep: 3, cl: 0x0008, attr: 0x0000, value: .unsignedInt(254)))
        reports += globalReports(ep: 3, cl: 0x0008, attrIDs: lcAttrs, acceptedCmds: [0, 1, 2, 3, 4, 5, 6, 7])

        // Identify (0x0003), Groups (0x0004), BridgedDeviceBasicInfo (0x0039), Descriptor (0x001D)
        // kept minimal for test
        reports.append(report(ep: 3, cl: 0x0003, attr: 0x0000, value: .unsignedInt(0)))
        reports.append(report(ep: 3, cl: 0x0003, attr: 0x0001, value: .unsignedInt(0)))
        reports += globalReports(ep: 3, cl: 0x0003, attrIDs: [0x0000, 0x0001, 0xFFF8, 0xFFF9, 0xFFFB, 0xFFFC, 0xFFFD])

        reports.append(report(ep: 3, cl: 0x0004, attr: 0x0000, value: .unsignedInt(0)))
        reports += globalReports(ep: 3, cl: 0x0004, attrIDs: [0x0000, 0xFFF8, 0xFFF9, 0xFFFB, 0xFFFC, 0xFFFD])

        reports.append(report(ep: 3, cl: 0x0039, attr: 0x0005, value: .utf8String("Test Light")))
        reports.append(report(ep: 3, cl: 0x0039, attr: 0x0011, value: .bool(true)))
        reports += globalReports(ep: 3, cl: 0x0039, attrIDs: [0x0005, 0x0011, 0xFFF8, 0xFFF9, 0xFFFB, 0xFFFC, 0xFFFD])

        reports.append(report(ep: 3, cl: 0x001D, attr: 0x0000, value: .array([
            .structure([
                .init(tag: .contextSpecific(0), value: .unsignedInt(0x0013)),
                .init(tag: .contextSpecific(1), value: .unsignedInt(1))
            ]),
            .structure([
                .init(tag: .contextSpecific(0), value: .unsignedInt(0x0101)),
                .init(tag: .contextSpecific(1), value: .unsignedInt(1))
            ])
        ])))
        reports.append(report(ep: 3, cl: 0x001D, attr: 0x0001,
            value: .array([0x0003, 0x0004, 0x0006, 0x0008, 0x001D, 0x0039].map { .unsignedInt(UInt64($0)) })))
        reports.append(report(ep: 3, cl: 0x001D, attr: 0x0002, value: .array([])))
        reports.append(report(ep: 3, cl: 0x001D, attr: 0x0003, value: .array([])))
        reports += globalReports(ep: 3, cl: 0x001D, attrIDs: [0x0000, 0x0001, 0x0002, 0x0003, 0xFFF8, 0xFFF9, 0xFFFB, 0xFFFC, 0xFFFD])

        // Sort like the subscribe handler does
        return reports.sorted { a, b in
            let aPath = a.attributeData?.path ?? a.attributeStatus?.path ?? AttributePath()
            let bPath = b.attributeData?.path ?? b.attributeStatus?.path ?? AttributePath()
            let aEp = aPath.endpointID?.rawValue ?? 0
            let bEp = bPath.endpointID?.rawValue ?? 0
            if aEp != bEp { return aEp < bEp }
            let aCl = aPath.clusterID?.rawValue ?? 0
            let bCl = bPath.clusterID?.rawValue ?? 0
            if aCl != bCl { return aCl < bCl }
            let aAt = aPath.attributeID?.rawValue ?? 0
            let bAt = bPath.attributeID?.rawValue ?? 0
            return aAt < bAt
        }
    }

    // MARK: - Tests

    @Test("Chunked subscribe priming report TLV is well-formed per byte-level validation")
    func chunkTLVByteValidation() throws {
        let allReports = buildRealisticBridgeReports()
        let subID = SubscriptionID(rawValue: 42)
        let chunker = ReportDataChunker()

        let chunks = chunker.chunk(
            subscriptionID: subID,
            attributeReports: allReports,
            eventReports: [],
            suppressResponseOnFinal: false
        )

        #expect(chunks.count > 1, "Expected multiple chunks for realistic bridge (\(allReports.count) reports)")

        for (i, chunk) in chunks.enumerated() {
            let encoded = chunk.tlvEncode()

            // Byte-level validation
            if let error = validateTLVBytes(encoded) {
                Issue.record("Chunk \(i + 1)/\(chunks.count) has malformed TLV at byte level: \(error)")
                // Hex dump first 200 bytes for debugging
                let hexDump = encoded.prefix(200).enumerated().map { offset, byte in
                    String(format: "%02x", byte)
                }.joined(separator: " ")
                print("Chunk \(i + 1) hex (first 200B): \(hexDump)")
            }

            // Size check
            #expect(
                encoded.count <= MatterMessage.maxIMPayloadSize,
                "Chunk \(i + 1)/\(chunks.count) TLV size \(encoded.count) exceeds maxIMPayloadSize \(MatterMessage.maxIMPayloadSize)"
            )
        }
    }

    @Test("Chunked subscribe priming report round-trips through encode/decode")
    func chunkTLVRoundTrip() throws {
        let allReports = buildRealisticBridgeReports()
        let subID = SubscriptionID(rawValue: 42)
        let chunker = ReportDataChunker()

        let chunks = chunker.chunk(
            subscriptionID: subID,
            attributeReports: allReports,
            eventReports: [],
            suppressResponseOnFinal: false
        )

        var totalReportsDecoded = 0

        for (i, chunk) in chunks.enumerated() {
            let encoded = chunk.tlvEncode()

            // Decode back
            let decoded = try ReportData.fromTLV(encoded)
            #expect(decoded.subscriptionID == subID, "Chunk \(i + 1): subscriptionID mismatch")
            #expect(decoded.attributeReports.count == chunk.attributeReports.count,
                "Chunk \(i + 1): report count mismatch — encoded \(chunk.attributeReports.count), decoded \(decoded.attributeReports.count)")
            #expect(decoded.moreChunkedMessages == chunk.moreChunkedMessages,
                "Chunk \(i + 1): moreChunkedMessages mismatch")

            totalReportsDecoded += decoded.attributeReports.count
        }

        #expect(totalReportsDecoded == allReports.count,
            "Total decoded reports \(totalReportsDecoded) should match input \(allReports.count)")
    }

    @Test("Each chunk's attribute reports individually encode/decode correctly")
    func individualReportRoundTrip() throws {
        let allReports = buildRealisticBridgeReports()

        for (i, report) in allReports.enumerated() {
            let element = report.toTLVElement()
            let encoded = TLVEncoder.encode(element)

            // Byte-level validation
            if let error = validateTLVBytes(encoded) {
                let path = report.attributeData?.path
                Issue.record("Report \(i) (ep\(path?.endpointID?.rawValue ?? 0)/cl0x\(String(path?.clusterID?.rawValue ?? 0, radix: 16))/attr0x\(String(path?.attributeID?.rawValue ?? 0, radix: 16))) has malformed TLV: \(error)")
            }

            // Decode back
            let (_, decoded) = try TLVDecoder.decode(encoded)
            let roundTripped = try AttributeReportIB.fromTLVElement(decoded)
            #expect(roundTripped == report, "Report \(i) failed round-trip")
        }
    }

    @Test("AttributeDataIB uses STRUCTURE container type (0x35) matching matter.js")
    func attributeDataIBContainerType() {
        // Matter spec §10.6.4 says LIST; CHIP SDK uses LIST; matter.js uses STRUCTURE.
        // We use STRUCTURE to match matter.js (known-working with Apple Home).
        let dataIB = AttributeDataIB(
            dataVersion: DataVersion(rawValue: 1),
            path: AttributePath(
                endpointID: EndpointID(rawValue: 0),
                clusterID: ClusterID(rawValue: 0x0028),
                attributeID: AttributeID(rawValue: 0x0000)
            ),
            data: .unsignedInt(1)
        )

        let report = AttributeReportIB(attributeData: dataIB)
        let encoded = TLVEncoder.encode(report.toTLVElement())

        #expect(encoded[0] == 0x15, "AttributeReportIB should be anonymous structure (0x15)")

        let controlByte = encoded[1]
        let tagByte = encoded[2]

        // 0x35 = context-specific (0x20) | structure (0x15)
        #expect(controlByte == 0x35,
            "AttributeDataIB should use STRUCTURE container (0x35), got 0x\(String(controlByte, radix: 16))")
        #expect(tagByte == 0x01, "AttributeDataIB should be at context tag 1")
    }

    @Test("AttributeStatusIB uses STRUCTURE container type (0x35) matching matter.js")
    func attributeStatusIBContainerType() {
        let statusIB = AttributeStatusIB(
            path: AttributePath(
                endpointID: EndpointID(rawValue: 0),
                clusterID: ClusterID(rawValue: 0x0028),
                attributeID: AttributeID(rawValue: 0x0000)
            ),
            status: .success
        )

        let report = AttributeReportIB(attributeStatus: statusIB)
        let encoded = TLVEncoder.encode(report.toTLVElement())

        let controlByte = encoded[1]
        let tagByte = encoded[2]

        // 0x35 = context-specific STRUCTURE, tag 0x00
        #expect(controlByte == 0x35,
            "AttributeStatusIB should use STRUCTURE container (0x35), got 0x\(String(controlByte, radix: 16))")
        #expect(tagByte == 0x00, "AttributeStatusIB should be at context tag 0")
    }

    @Test("Individual BasicInfo attribute TLV hex dump for matter.js comparison")
    func basicInfoAttributeHexDump() {
        // These match the real BasicInformationHandler.initialAttributes() output
        let basicInfoAttrs: [(UInt32, String, TLVElement)] = [
            (0x0000, "dataModelRevision",    .unsignedInt(17)),
            (0x0001, "vendorName",           .utf8String("MatterSwift")),
            (0x0002, "vendorID",             .unsignedInt(0xFFF1)),
            (0x0003, "productName",          .utf8String("Bridge")),
            (0x0004, "productID",            .unsignedInt(0x8000)),
            (0x0005, "nodeLabel",            .utf8String("")),
            (0x0006, "location",             .utf8String("XX")),
            (0x0007, "hardwareVersion",      .unsignedInt(0)),
            (0x0008, "hardwareVersionString",.utf8String("1.0")),
            (0x0009, "softwareVersion",      .unsignedInt(1)),
            (0x000A, "softwareVersionString",.utf8String("1.0.0")),
            (0x000F, "serialNumber",         .utf8String("SM-0001")),
            (0x0012, "uniqueID",             .utf8String("swift-matter-001")),
            (0x0013, "capabilityMinima",     .structure([
                .init(tag: .contextSpecific(0), value: .unsignedInt(3)),
                .init(tag: .contextSpecific(1), value: .unsignedInt(3))
            ])),
        ]

        // Global attributes
        let allAttrIDs: [UInt32] = basicInfoAttrs.map { $0.0 } + [0xFFF8, 0xFFF9, 0xFFFB, 0xFFFC, 0xFFFD]
        let globalAttrs: [(UInt32, String, TLVElement)] = [
            (0xFFF8, "generatedCommandList", .array([])),
            (0xFFF9, "acceptedCommandList",  .array([])),
            (0xFFFB, "attributeList",        .array(allAttrIDs.map { .unsignedInt(UInt64($0)) })),
            (0xFFFC, "featureMap",           .unsignedInt(0)),
            (0xFFFD, "clusterRevision",      .unsignedInt(1)),
        ]

        let allAttrs = basicInfoAttrs + globalAttrs

        print("\n=== BasicInfo (0x0028) Individual Attribute TLV Hex ===")
        print("Format: AttributeReportIB { AttributeDataIB { dataVersion=1, path=ep0/0x28/attrID, data=value } }")
        print("")

        for (attrID, name, value) in allAttrs {
            let reportIB = AttributeReportIB(attributeData: AttributeDataIB(
                dataVersion: DataVersion(rawValue: 1),
                path: AttributePath(
                    endpointID: EndpointID(rawValue: 0),
                    clusterID: ClusterID(rawValue: 0x0028),
                    attributeID: AttributeID(rawValue: attrID)
                ),
                data: value
            ))

            let encoded = TLVEncoder.encode(reportIB.toTLVElement())
            let hex = encoded.map { String(format: "%02x", $0) }.joined(separator: " ")

            // Also validate TLV structure
            let valid = validateTLVBytes(encoded) == nil ? "OK" : "BAD: \(validateTLVBytes(encoded)!)"

            print("0x\(String(format: "%04X", attrID)) \(name) [\(encoded.count)B] \(valid)")
            print("  \(hex)")
        }

        // Also dump the data element alone (tag 2 inside AttributeDataIB) for each attribute
        print("\n=== Data elements only (context-tag 2 value inside AttributeDataIB) ===")
        for (attrID, name, value) in allAttrs {
            let dataEncoded = TLVEncoder.encode(value)
            let hex = dataEncoded.map { String(format: "%02x", $0) }.joined(separator: " ")
            print("0x\(String(format: "%04X", attrID)) \(name): \(hex)")
        }
    }

    @Test("Binary search: BasicInfo first-half vs second-half ReportData hex")
    func basicInfoBinarySearchChunks() {
        // All BasicInfo attributes matching the real BasicInformationHandler
        let allAttrIDs: [UInt32] = [0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005,
                                     0x0006, 0x0007, 0x0008, 0x0009, 0x000A, 0x000F,
                                     0x0012, 0x0013, 0xFFF8, 0xFFF9, 0xFFFB, 0xFFFC, 0xFFFD]
        let basicInfoAttrs: [(UInt32, TLVElement)] = [
            (0x0000, .unsignedInt(17)),
            (0x0001, .utf8String("MatterSwift")),
            (0x0002, .unsignedInt(0xFFF1)),
            (0x0003, .utf8String("Bridge")),
            (0x0004, .unsignedInt(0x8000)),
            (0x0005, .utf8String("")),
            (0x0006, .utf8String("XX")),
            (0x0007, .unsignedInt(0)),
            (0x0008, .utf8String("1.0")),
            (0x0009, .unsignedInt(1)),
            (0x000A, .utf8String("1.0.0")),
            (0x000F, .utf8String("SM-0001")),
            (0x0012, .utf8String("swift-matter-001")),
            (0x0013, .structure([
                .init(tag: .contextSpecific(0), value: .unsignedInt(3)),
                .init(tag: .contextSpecific(1), value: .unsignedInt(3))
            ])),
            (0xFFF8, .array([])),
            (0xFFF9, .array([])),
            (0xFFFB, .array(allAttrIDs.map { .unsignedInt(UInt64($0)) })),
            (0xFFFC, .unsignedInt(0)),
            (0xFFFD, .unsignedInt(1)),
        ]

        // Split into two halves for binary search
        // First half: 0x0-0x9 (primitive types only)
        let firstHalf = basicInfoAttrs.filter { $0.0 <= 0x0009 }
        // Second half: 0xA-0xFFFD (includes strings, struct, arrays)
        let secondHalf = basicInfoAttrs.filter { $0.0 > 0x0009 }

        func buildReportData(_ attrs: [(UInt32, TLVElement)], label: String) {
            let reports = attrs.map { attrID, value in
                AttributeReportIB(attributeData: AttributeDataIB(
                    dataVersion: DataVersion(rawValue: 1),
                    path: AttributePath(
                        endpointID: EndpointID(rawValue: 0),
                        clusterID: ClusterID(rawValue: 0x0028),
                        attributeID: AttributeID(rawValue: attrID)
                    ),
                    data: value
                ))
            }
            let rd = ReportData(
                subscriptionID: SubscriptionID(rawValue: 42),
                attributeReports: reports,
                eventReports: [],
                moreChunkedMessages: true,
                suppressResponse: false
            )
            let encoded = rd.tlvEncode()
            let hex = encoded.map { String(format: "%02x", $0) }.joined(separator: " ")
            let valid = validateTLVBytes(encoded) == nil ? "OK" : "BAD"
            let attrList = attrs.map { "0x\(String(format: "%04X", $0.0))" }.joined(separator: ", ")
            print("\n=== \(label) [\(encoded.count)B, \(valid)] ===")
            print("Attrs: \(attrList)")
            print("Hex:\n  \(hex)")
        }

        buildReportData(basicInfoAttrs, label: "ALL BasicInfo (full chunk 2)")
        buildReportData(firstHalf, label: "FIRST HALF (0x0-0x9)")
        buildReportData(secondHalf, label: "SECOND HALF (0xA-0xFFFD)")

        // Also dump subsets for further narrowing
        let justCapMinima = basicInfoAttrs.filter { $0.0 == 0x0013 }
        let justGlobals = basicInfoAttrs.filter { $0.0 >= 0xFFF8 }
        let justStrings = basicInfoAttrs.filter { [0x000A, 0x000F, 0x0012].contains($0.0) }

        buildReportData(justCapMinima, label: "ONLY capabilityMinima (0x13)")
        buildReportData(justGlobals, label: "ONLY globals (0xFFF8-0xFFFD)")
        buildReportData(justStrings, label: "ONLY strings (0xA, 0xF, 0x12)")
    }

    @Test("Chunk 2 diagnostic hex dump for manual inspection")
    func chunk2HexDump() {
        let allReports = buildRealisticBridgeReports()
        let subID = SubscriptionID(rawValue: 42)
        let chunker = ReportDataChunker()

        let chunks = chunker.chunk(
            subscriptionID: subID,
            attributeReports: allReports,
            eventReports: [],
            suppressResponseOnFinal: false
        )

        guard chunks.count >= 2 else {
            Issue.record("Expected at least 2 chunks, got \(chunks.count)")
            return
        }

        // Print chunk summaries
        for (i, chunk) in chunks.enumerated() {
            let encoded = chunk.tlvEncode()
            let attrs = chunk.attributeReports.compactMap { r -> String? in
                guard let data = r.attributeData else { return nil }
                let ep = data.path.endpointID?.rawValue ?? 0
                let cl = data.path.clusterID?.rawValue ?? 0
                let at = data.path.attributeID?.rawValue ?? 0
                return "ep\(ep)/0x\(String(cl, radix: 16, uppercase: true))/0x\(String(at, radix: 16, uppercase: true))"
            }
            print("=== Chunk \(i + 1)/\(chunks.count): \(encoded.count)B, \(attrs.count) attrs ===")
            print("Attributes: \(attrs.joined(separator: ", "))")

            // Full hex dump for chunks > 1
            if i >= 1 {
                let hex = encoded.enumerated().map { offset, byte in
                    let hex = String(format: "%02x", byte)
                    return (offset > 0 && offset % 32 == 0) ? "\n  \(hex)" : hex
                }.joined(separator: " ")
                print("Full hex:\n  \(hex)")
            }
        }
    }
}
