// OperationalCredentials.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

/// Operational Credentials cluster (0x003E).
///
/// Manages NOCs, fabrics, and trusted root certificates on the device.
/// Used during commissioning to install operational credentials.
public enum OperationalCredentialsCluster {

    // MARK: - Attribute IDs

    public enum Attribute {
        public static let nocs               = AttributeID(rawValue: 0x0000)
        public static let fabrics            = AttributeID(rawValue: 0x0001)
        public static let supportedFabrics   = AttributeID(rawValue: 0x0002)
        public static let commissionedFabrics = AttributeID(rawValue: 0x0003)
        public static let trustedRootCerts   = AttributeID(rawValue: 0x0004)
        public static let currentFabricIndex = AttributeID(rawValue: 0x0005)
    }

    // MARK: - Command IDs

    public enum Command {
        public static let attestationRequest  = CommandID(rawValue: 0x00)
        public static let attestationResponse = CommandID(rawValue: 0x01)
        public static let certificateChainRequest  = CommandID(rawValue: 0x02)
        public static let certificateChainResponse = CommandID(rawValue: 0x03)
        public static let csrRequest          = CommandID(rawValue: 0x04)
        public static let csrResponse         = CommandID(rawValue: 0x05)
        public static let addNOC              = CommandID(rawValue: 0x06)
        public static let updateNOC           = CommandID(rawValue: 0x07)
        public static let nocResponse         = CommandID(rawValue: 0x08)
        public static let updateFabricLabel   = CommandID(rawValue: 0x09)
        public static let removeFabric        = CommandID(rawValue: 0x0A)
        public static let addTrustedRootCert  = CommandID(rawValue: 0x0B)
    }

    // MARK: - NOC Response Status

    /// Status codes for NOCResponse command.
    public enum NOCStatus: UInt8, Sendable {
        case ok                    = 0x00
        case invalidPublicKey      = 0x01
        case invalidNodeOpID       = 0x02
        case invalidNOC            = 0x03
        case missingCSR            = 0x04
        case tableIsFull           = 0x05
        case invalidAdminSubject   = 0x06
        case fabricConflict        = 0x09
        case labelConflict         = 0x0A
        case invalidFabricIndex    = 0x0B
    }

    // MARK: - Fabric Descriptor

    /// FabricDescriptorStruct — describes a commissioned fabric.
    ///
    /// ```
    /// Structure {
    ///   1: rootPublicKey (octet string, 65 bytes)
    ///   2: vendorID (unsigned int)
    ///   3: fabricID (unsigned int)
    ///   4: nodeID (unsigned int)
    ///   5: label (string)
    ///   0xFE: fabricIndex (unsigned int)
    /// }
    /// ```
    public struct FabricDescriptor: Sendable, Equatable {

        private enum Tag {
            static let rootPublicKey: UInt8 = 1
            static let vendorID: UInt8 = 2
            static let fabricID: UInt8 = 3
            static let nodeID: UInt8 = 4
            static let label: UInt8 = 5
            static let fabricIndex: UInt8 = 0xFE
        }

        public let rootPublicKey: Data
        public let vendorID: UInt16
        public let fabricID: FabricID
        public let nodeID: NodeID
        public let label: String
        public let fabricIndex: FabricIndex

        public init(
            rootPublicKey: Data,
            vendorID: UInt16,
            fabricID: FabricID,
            nodeID: NodeID,
            label: String,
            fabricIndex: FabricIndex
        ) {
            self.rootPublicKey = rootPublicKey
            self.vendorID = vendorID
            self.fabricID = fabricID
            self.nodeID = nodeID
            self.label = label
            self.fabricIndex = fabricIndex
        }

        public func toTLVElement() -> TLVElement {
            .structure([
                .init(tag: .contextSpecific(Tag.rootPublicKey), value: .octetString(rootPublicKey)),
                .init(tag: .contextSpecific(Tag.vendorID), value: .unsignedInt(UInt64(vendorID))),
                .init(tag: .contextSpecific(Tag.fabricID), value: .unsignedInt(fabricID.rawValue)),
                .init(tag: .contextSpecific(Tag.nodeID), value: .unsignedInt(nodeID.rawValue)),
                .init(tag: .contextSpecific(Tag.label), value: .utf8String(label)),
                .init(tag: .contextSpecific(Tag.fabricIndex), value: .unsignedInt(UInt64(fabricIndex.rawValue)))
            ])
        }

        public static func fromTLVElement(_ element: TLVElement) throws -> FabricDescriptor {
            guard case .structure(let fields) = element else {
                throw FabricDescriptorError.invalidStructure
            }

            guard let rpk = fields.first(where: { $0.tag == .contextSpecific(Tag.rootPublicKey) })?.value.dataValue,
                  let vid = fields.first(where: { $0.tag == .contextSpecific(Tag.vendorID) })?.value.uintValue,
                  let fid = fields.first(where: { $0.tag == .contextSpecific(Tag.fabricID) })?.value.uintValue,
                  let nid = fields.first(where: { $0.tag == .contextSpecific(Tag.nodeID) })?.value.uintValue,
                  let lbl = fields.first(where: { $0.tag == .contextSpecific(Tag.label) })?.value.stringValue,
                  let fidx = fields.first(where: { $0.tag == .contextSpecific(Tag.fabricIndex) })?.value.uintValue else {
                throw FabricDescriptorError.missingField
            }

            return FabricDescriptor(
                rootPublicKey: rpk,
                vendorID: UInt16(vid),
                fabricID: FabricID(rawValue: fid),
                nodeID: NodeID(rawValue: nid),
                label: lbl,
                fabricIndex: FabricIndex(rawValue: UInt8(fidx))
            )
        }
    }

    public enum FabricDescriptorError: Error, Sendable {
        case invalidStructure
        case missingField
    }

    // MARK: - NOC Response

    /// Response to AddNOC/UpdateNOC/UpdateFabricLabel/RemoveFabric.
    ///
    /// ```
    /// Structure {
    ///   0: statusCode (unsigned int — NOCStatus)
    ///   1: fabricIndex (unsigned int, optional)
    ///   2: debugText (string, optional)
    /// }
    /// ```
    public struct NOCResponse: Sendable, Equatable {

        public let statusCode: NOCStatus
        public let fabricIndex: FabricIndex?
        public let debugText: String?

        public init(statusCode: NOCStatus, fabricIndex: FabricIndex? = nil, debugText: String? = nil) {
            self.statusCode = statusCode
            self.fabricIndex = fabricIndex
            self.debugText = debugText
        }

        public func toTLVElement() -> TLVElement {
            var fields: [TLVElement.TLVField] = [
                .init(tag: .contextSpecific(0), value: .unsignedInt(UInt64(statusCode.rawValue)))
            ]
            if let fi = fabricIndex {
                fields.append(.init(tag: .contextSpecific(1), value: .unsignedInt(UInt64(fi.rawValue))))
            }
            if let dt = debugText {
                fields.append(.init(tag: .contextSpecific(2), value: .utf8String(dt)))
            }
            return .structure(fields)
        }

        public static func fromTLVElement(_ element: TLVElement) throws -> NOCResponse {
            guard case .structure(let fields) = element else {
                throw FabricDescriptorError.invalidStructure
            }
            guard let sc = fields.first(where: { $0.tag == .contextSpecific(0) })?.value.uintValue,
                  let status = NOCStatus(rawValue: UInt8(sc)) else {
                throw FabricDescriptorError.missingField
            }
            let fi = fields.first(where: { $0.tag == .contextSpecific(1) })?.value.uintValue.map { FabricIndex(rawValue: UInt8($0)) }
            let dt = fields.first(where: { $0.tag == .contextSpecific(2) })?.value.stringValue
            return NOCResponse(statusCode: status, fabricIndex: fi, debugText: dt)
        }
    }

    // MARK: - CSR Request / Response

    /// CSRRequest command fields.
    ///
    /// ```
    /// Structure {
    ///   0: csrNonce (octet string, 32 bytes)
    ///   1: isForUpdateNOC (bool, optional)
    /// }
    /// ```
    public struct CSRRequest: Sendable, Equatable {

        public let csrNonce: Data
        public let isForUpdateNOC: Bool

        public init(csrNonce: Data, isForUpdateNOC: Bool = false) {
            self.csrNonce = csrNonce
            self.isForUpdateNOC = isForUpdateNOC
        }

        public func toTLVElement() -> TLVElement {
            var fields: [TLVElement.TLVField] = [
                .init(tag: .contextSpecific(0), value: .octetString(csrNonce))
            ]
            if isForUpdateNOC {
                fields.append(.init(tag: .contextSpecific(1), value: .bool(true)))
            }
            return .structure(fields)
        }

        public static func fromTLVElement(_ element: TLVElement) throws -> CSRRequest {
            guard case .structure(let fields) = element else {
                throw FabricDescriptorError.invalidStructure
            }
            guard let nonce = fields.first(where: { $0.tag == .contextSpecific(0) })?.value.dataValue else {
                throw FabricDescriptorError.missingField
            }
            let isUpdate = fields.first(where: { $0.tag == .contextSpecific(1) })?.value.boolValue ?? false
            return CSRRequest(csrNonce: nonce, isForUpdateNOC: isUpdate)
        }
    }

    /// CSRResponse command fields.
    ///
    /// ```
    /// Structure {
    ///   0: nocsrElements (octet string — TLV-encoded NOCSRElements)
    ///   1: attestationSignature (octet string, 64 bytes)
    /// }
    /// ```
    public struct CSRResponse: Sendable, Equatable {

        public let nocsrElements: Data
        public let attestationSignature: Data

        public init(nocsrElements: Data, attestationSignature: Data) {
            self.nocsrElements = nocsrElements
            self.attestationSignature = attestationSignature
        }

        public func toTLVElement() -> TLVElement {
            .structure([
                .init(tag: .contextSpecific(0), value: .octetString(nocsrElements)),
                .init(tag: .contextSpecific(1), value: .octetString(attestationSignature))
            ])
        }

        public static func fromTLVElement(_ element: TLVElement) throws -> CSRResponse {
            guard case .structure(let fields) = element else {
                throw FabricDescriptorError.invalidStructure
            }
            guard let elems = fields.first(where: { $0.tag == .contextSpecific(0) })?.value.dataValue,
                  let sig = fields.first(where: { $0.tag == .contextSpecific(1) })?.value.dataValue else {
                throw FabricDescriptorError.missingField
            }
            return CSRResponse(nocsrElements: elems, attestationSignature: sig)
        }
    }

    // MARK: - AddNOC Command

    /// AddNOC command fields.
    ///
    /// ```
    /// Structure {
    ///   0: nocValue (octet string — TLV-encoded NOC)
    ///   1: icacValue (octet string, optional — TLV-encoded ICAC)
    ///   2: ipkValue (octet string, 16 bytes — Identity Protection Key epoch key)
    ///   3: caseAdminSubject (unsigned int)
    ///   4: adminVendorId (unsigned int)
    /// }
    /// ```
    public struct AddNOCCommand: Sendable, Equatable {

        public let nocValue: Data
        public let icacValue: Data?
        public let ipkValue: Data
        public let caseAdminSubject: UInt64
        public let adminVendorId: UInt16

        public init(nocValue: Data, icacValue: Data? = nil, ipkValue: Data, caseAdminSubject: UInt64, adminVendorId: UInt16) {
            self.nocValue = nocValue
            self.icacValue = icacValue
            self.ipkValue = ipkValue
            self.caseAdminSubject = caseAdminSubject
            self.adminVendorId = adminVendorId
        }

        public func toTLVElement() -> TLVElement {
            var fields: [TLVElement.TLVField] = [
                .init(tag: .contextSpecific(0), value: .octetString(nocValue))
            ]
            if let icac = icacValue {
                fields.append(.init(tag: .contextSpecific(1), value: .octetString(icac)))
            }
            fields.append(.init(tag: .contextSpecific(2), value: .octetString(ipkValue)))
            fields.append(.init(tag: .contextSpecific(3), value: .unsignedInt(caseAdminSubject)))
            fields.append(.init(tag: .contextSpecific(4), value: .unsignedInt(UInt64(adminVendorId))))
            return .structure(fields)
        }

        public static func fromTLVElement(_ element: TLVElement) throws -> AddNOCCommand {
            guard case .structure(let fields) = element else {
                throw FabricDescriptorError.invalidStructure
            }
            guard let noc = fields.first(where: { $0.tag == .contextSpecific(0) })?.value.dataValue,
                  let ipk = fields.first(where: { $0.tag == .contextSpecific(2) })?.value.dataValue,
                  let cas = fields.first(where: { $0.tag == .contextSpecific(3) })?.value.uintValue,
                  let avid = fields.first(where: { $0.tag == .contextSpecific(4) })?.value.uintValue else {
                throw FabricDescriptorError.missingField
            }
            // Treat a present-but-empty ICAC field (0 bytes) as absent — some commissioners
            // (e.g. Apple Home) send tag 1 with a zero-length payload to mean "no ICAC".
            let icacRaw = fields.first(where: { $0.tag == .contextSpecific(1) })?.value.dataValue
            let icac = icacRaw.flatMap { $0.isEmpty ? nil : $0 }
            return AddNOCCommand(nocValue: noc, icacValue: icac, ipkValue: ipk, caseAdminSubject: cas, adminVendorId: UInt16(avid))
        }
    }
}
