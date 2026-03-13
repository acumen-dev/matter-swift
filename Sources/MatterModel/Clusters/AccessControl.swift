// AccessControl.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

/// Access Control cluster (0x001F).
///
/// Manages access control entries (ACLs) that determine which nodes
/// can perform which operations on which endpoints/clusters.
public enum AccessControlCluster {

    // MARK: - Attribute IDs

    public enum Attribute {
        public static let acl                    = AttributeID(rawValue: 0x0000)
        public static let `extension`            = AttributeID(rawValue: 0x0001)
        public static let subjectsPerAccessControlEntry = AttributeID(rawValue: 0x0002)
        public static let targetsPerAccessControlEntry  = AttributeID(rawValue: 0x0003)
        public static let accessControlEntriesPerFabric = AttributeID(rawValue: 0x0004)
    }

    // MARK: - Privilege

    /// Access control privilege levels.
    public enum Privilege: UInt8, Sendable, Equatable, Comparable {
        case view       = 1
        case proxied    = 2
        case operate    = 3
        case manage     = 4
        case administer = 5

        public static func < (lhs: Privilege, rhs: Privilege) -> Bool {
            lhs.rawValue < rhs.rawValue
        }
    }

    // MARK: - Auth Mode

    /// Authentication modes for access control.
    public enum AuthMode: UInt8, Sendable, Equatable {
        case pase  = 1
        case `case` = 2
        case group = 3
    }

    // MARK: - Access Control Target

    /// Target scope for an ACL entry.
    ///
    /// ```
    /// Structure {
    ///   0: cluster (unsigned int, optional)
    ///   1: endpoint (unsigned int, optional)
    ///   2: deviceType (unsigned int, optional)
    /// }
    /// ```
    public struct Target: Sendable, Equatable {

        public let cluster: ClusterID?
        public let endpoint: EndpointID?
        public let deviceType: DeviceTypeID?

        public init(cluster: ClusterID? = nil, endpoint: EndpointID? = nil, deviceType: DeviceTypeID? = nil) {
            self.cluster = cluster
            self.endpoint = endpoint
            self.deviceType = deviceType
        }

        public func toTLVElement() -> TLVElement {
            var fields: [TLVElement.TLVField] = []
            if let c = cluster { fields.append(.init(tag: .contextSpecific(0), value: .unsignedInt(UInt64(c.rawValue)))) }
            if let e = endpoint { fields.append(.init(tag: .contextSpecific(1), value: .unsignedInt(UInt64(e.rawValue)))) }
            if let d = deviceType { fields.append(.init(tag: .contextSpecific(2), value: .unsignedInt(UInt64(d.rawValue)))) }
            return .structure(fields)
        }

        public static func fromTLVElement(_ element: TLVElement) throws -> Target {
            guard case .structure(let fields) = element else {
                throw AccessControlError.invalidStructure
            }
            return Target(
                cluster: fields.first(where: { $0.tag == .contextSpecific(0) })?.value.uintValue.map { ClusterID(rawValue: UInt32($0)) },
                endpoint: fields.first(where: { $0.tag == .contextSpecific(1) })?.value.uintValue.map { EndpointID(rawValue: UInt16($0)) },
                deviceType: fields.first(where: { $0.tag == .contextSpecific(2) })?.value.uintValue.map { DeviceTypeID(rawValue: UInt32($0)) }
            )
        }
    }

    // MARK: - Access Control Entry

    /// An access control entry (ACL).
    ///
    /// ```
    /// Structure {
    ///   1: privilege (unsigned int — Privilege)
    ///   2: authMode (unsigned int — AuthMode)
    ///   3: subjects (array of unsigned int, optional)
    ///   4: targets (array of Target, optional)
    ///   0xFE: fabricIndex (unsigned int)
    /// }
    /// ```
    public struct AccessControlEntry: Sendable, Equatable {

        private enum Tag {
            static let privilege: UInt8 = 1
            static let authMode: UInt8 = 2
            static let subjects: UInt8 = 3
            static let targets: UInt8 = 4
            static let fabricIndex: UInt8 = 0xFE
        }

        public let privilege: Privilege
        public let authMode: AuthMode
        public let subjects: [UInt64]
        public let targets: [Target]?
        public let fabricIndex: FabricIndex

        public init(
            privilege: Privilege,
            authMode: AuthMode,
            subjects: [UInt64] = [],
            targets: [Target]? = nil,
            fabricIndex: FabricIndex
        ) {
            self.privilege = privilege
            self.authMode = authMode
            self.subjects = subjects
            self.targets = targets
            self.fabricIndex = fabricIndex
        }

        /// Convenience: create an ACE that grants administer privilege to a CASE subject.
        public static func adminACE(subjectNodeID: UInt64, fabricIndex: FabricIndex) -> AccessControlEntry {
            AccessControlEntry(
                privilege: .administer,
                authMode: .case,
                subjects: [subjectNodeID],
                fabricIndex: fabricIndex
            )
        }

        public func toTLVElement() -> TLVElement {
            var fields: [TLVElement.TLVField] = [
                .init(tag: .contextSpecific(Tag.privilege), value: .unsignedInt(UInt64(privilege.rawValue))),
                .init(tag: .contextSpecific(Tag.authMode), value: .unsignedInt(UInt64(authMode.rawValue)))
            ]

            if !subjects.isEmpty {
                fields.append(.init(
                    tag: .contextSpecific(Tag.subjects),
                    value: .array(subjects.map { .unsignedInt($0) })
                ))
            }

            if let tgts = targets {
                fields.append(.init(
                    tag: .contextSpecific(Tag.targets),
                    value: .array(tgts.map { $0.toTLVElement() })
                ))
            }

            fields.append(.init(tag: .contextSpecific(Tag.fabricIndex), value: .unsignedInt(UInt64(fabricIndex.rawValue))))

            return .structure(fields)
        }

        public static func fromTLVElement(_ element: TLVElement) throws -> AccessControlEntry {
            guard case .structure(let fields) = element else {
                throw AccessControlError.invalidStructure
            }

            guard let privVal = fields.first(where: { $0.tag == .contextSpecific(Tag.privilege) })?.value.uintValue,
                  let priv = Privilege(rawValue: UInt8(privVal)),
                  let amVal = fields.first(where: { $0.tag == .contextSpecific(Tag.authMode) })?.value.uintValue,
                  let am = AuthMode(rawValue: UInt8(amVal)),
                  let fi = fields.first(where: { $0.tag == .contextSpecific(Tag.fabricIndex) })?.value.uintValue else {
                throw AccessControlError.missingField
            }

            var subs: [UInt64] = []
            if let subsField = fields.first(where: { $0.tag == .contextSpecific(Tag.subjects) }),
               case .array(let elements) = subsField.value {
                subs = elements.compactMap { $0.uintValue }
            }

            var tgts: [Target]?
            if let tgtsField = fields.first(where: { $0.tag == .contextSpecific(Tag.targets) }),
               case .array(let elements) = tgtsField.value {
                tgts = try elements.map { try Target.fromTLVElement($0) }
            }

            return AccessControlEntry(
                privilege: priv,
                authMode: am,
                subjects: subs,
                targets: tgts,
                fabricIndex: FabricIndex(rawValue: UInt8(fi))
            )
        }
    }

    // MARK: - Errors

    public enum AccessControlError: Error, Sendable {
        case invalidStructure
        case missingField
    }
}
