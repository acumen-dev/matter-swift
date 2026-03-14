// GroupKeyManagement.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

/// Group Key Management cluster (0x003F).
///
/// Manages group key sets used for group communication. Group keys are used to
/// encrypt multicast messages addressed to a group of Matter devices.
public enum GroupKeyManagementCluster {

    // MARK: - Attribute IDs

    public enum Attribute {
        public static let groupKeyMap           = AttributeID(rawValue: 0x0000)
        public static let groupTable            = AttributeID(rawValue: 0x0001)
        public static let maxGroupsPerFabric    = AttributeID(rawValue: 0x0002)
        public static let maxGroupKeysPerFabric = AttributeID(rawValue: 0x0003)
    }

    // MARK: - Command IDs

    public enum Command {
        public static let keySetWrite                   = CommandID(rawValue: 0x00)
        public static let keySetRead                    = CommandID(rawValue: 0x01)
        public static let keySetReadResponse            = CommandID(rawValue: 0x02)
        public static let keySetRemove                  = CommandID(rawValue: 0x03)
        public static let keySetReadAllIndices          = CommandID(rawValue: 0x04)
        public static let keySetReadAllIndicesResponse  = CommandID(rawValue: 0x05)
    }

    // MARK: - Group Key Security Policy

    /// Security policy for a group key set.
    public enum GroupKeySecurityPolicy: UInt8, Sendable {
        /// Trust first: accept group messages without prior key establishment.
        case trustFirst = 0
        /// Cache and sync: require prior group key establishment before accepting messages.
        case cacheAndSync = 1
    }

    // MARK: - GroupKeySetStruct

    /// A group key set containing up to three epoch keys (for key rotation).
    ///
    /// ```
    /// Structure {
    ///   0: groupKeySetID (unsigned int)
    ///   1: groupKeySecurityPolicy (unsigned int — GroupKeySecurityPolicy)
    ///   2: epochKey0 (octet string, 16 bytes, nullable)
    ///   3: epochStartTime0 (unsigned int, nullable)
    ///   4: epochKey1 (octet string, 16 bytes, nullable)
    ///   5: epochStartTime1 (unsigned int, nullable)
    ///   6: epochKey2 (octet string, 16 bytes, nullable)
    ///   7: epochStartTime2 (unsigned int, nullable)
    /// }
    /// ```
    public struct GroupKeySetStruct: Sendable, Equatable {

        private enum Tag {
            static let groupKeySetID: UInt8 = 0
            static let groupKeySecurityPolicy: UInt8 = 1
            static let epochKey0: UInt8 = 2
            static let epochStartTime0: UInt8 = 3
            static let epochKey1: UInt8 = 4
            static let epochStartTime1: UInt8 = 5
            static let epochKey2: UInt8 = 6
            static let epochStartTime2: UInt8 = 7
        }

        public let groupKeySetID: UInt16
        public let groupKeySecurityPolicy: GroupKeySecurityPolicy
        public let epochKey0: Data?
        public let epochStartTime0: UInt64?
        public let epochKey1: Data?
        public let epochStartTime1: UInt64?
        public let epochKey2: Data?
        public let epochStartTime2: UInt64?

        public init(
            groupKeySetID: UInt16,
            groupKeySecurityPolicy: GroupKeySecurityPolicy,
            epochKey0: Data? = nil,
            epochStartTime0: UInt64? = nil,
            epochKey1: Data? = nil,
            epochStartTime1: UInt64? = nil,
            epochKey2: Data? = nil,
            epochStartTime2: UInt64? = nil
        ) {
            self.groupKeySetID = groupKeySetID
            self.groupKeySecurityPolicy = groupKeySecurityPolicy
            self.epochKey0 = epochKey0
            self.epochStartTime0 = epochStartTime0
            self.epochKey1 = epochKey1
            self.epochStartTime1 = epochStartTime1
            self.epochKey2 = epochKey2
            self.epochStartTime2 = epochStartTime2
        }

        /// Encode to TLV. When `redactKeys` is true, epoch keys are encoded as null.
        public func toTLVElement(redactKeys: Bool = false) -> TLVElement {
            var fields: [TLVElement.TLVField] = [
                .init(tag: .contextSpecific(Tag.groupKeySetID), value: .unsignedInt(UInt64(groupKeySetID))),
                .init(tag: .contextSpecific(Tag.groupKeySecurityPolicy), value: .unsignedInt(UInt64(groupKeySecurityPolicy.rawValue)))
            ]

            // Epoch key 0
            if redactKeys {
                fields.append(.init(tag: .contextSpecific(Tag.epochKey0), value: .null))
            } else if let key = epochKey0 {
                fields.append(.init(tag: .contextSpecific(Tag.epochKey0), value: .octetString(key)))
            } else {
                fields.append(.init(tag: .contextSpecific(Tag.epochKey0), value: .null))
            }

            if let t = epochStartTime0 {
                fields.append(.init(tag: .contextSpecific(Tag.epochStartTime0), value: .unsignedInt(t)))
            } else {
                fields.append(.init(tag: .contextSpecific(Tag.epochStartTime0), value: .null))
            }

            // Epoch key 1
            if redactKeys {
                fields.append(.init(tag: .contextSpecific(Tag.epochKey1), value: .null))
            } else if let key = epochKey1 {
                fields.append(.init(tag: .contextSpecific(Tag.epochKey1), value: .octetString(key)))
            } else {
                fields.append(.init(tag: .contextSpecific(Tag.epochKey1), value: .null))
            }

            if let t = epochStartTime1 {
                fields.append(.init(tag: .contextSpecific(Tag.epochStartTime1), value: .unsignedInt(t)))
            } else {
                fields.append(.init(tag: .contextSpecific(Tag.epochStartTime1), value: .null))
            }

            // Epoch key 2
            if redactKeys {
                fields.append(.init(tag: .contextSpecific(Tag.epochKey2), value: .null))
            } else if let key = epochKey2 {
                fields.append(.init(tag: .contextSpecific(Tag.epochKey2), value: .octetString(key)))
            } else {
                fields.append(.init(tag: .contextSpecific(Tag.epochKey2), value: .null))
            }

            if let t = epochStartTime2 {
                fields.append(.init(tag: .contextSpecific(Tag.epochStartTime2), value: .unsignedInt(t)))
            } else {
                fields.append(.init(tag: .contextSpecific(Tag.epochStartTime2), value: .null))
            }

            return .structure(fields)
        }

        /// Decode from TLV.
        public static func fromTLVElement(_ element: TLVElement) throws -> GroupKeySetStruct {
            guard case .structure(let fields) = element else {
                throw GroupKeyManagementError.invalidStructure
            }

            guard let idVal = fields.first(where: { $0.tag == .contextSpecific(Tag.groupKeySetID) })?.value.uintValue,
                  let policyVal = fields.first(where: { $0.tag == .contextSpecific(Tag.groupKeySecurityPolicy) })?.value.uintValue,
                  let policy = GroupKeySecurityPolicy(rawValue: UInt8(policyVal)) else {
                throw GroupKeyManagementError.missingField
            }

            let epochKey0 = fields.first(where: { $0.tag == .contextSpecific(Tag.epochKey0) }).flatMap { f -> Data? in
                if case .null = f.value { return nil }
                return f.value.dataValue
            }
            let epochStartTime0 = fields.first(where: { $0.tag == .contextSpecific(Tag.epochStartTime0) }).flatMap { f -> UInt64? in
                if case .null = f.value { return nil }
                return f.value.uintValue
            }
            let epochKey1 = fields.first(where: { $0.tag == .contextSpecific(Tag.epochKey1) }).flatMap { f -> Data? in
                if case .null = f.value { return nil }
                return f.value.dataValue
            }
            let epochStartTime1 = fields.first(where: { $0.tag == .contextSpecific(Tag.epochStartTime1) }).flatMap { f -> UInt64? in
                if case .null = f.value { return nil }
                return f.value.uintValue
            }
            let epochKey2 = fields.first(where: { $0.tag == .contextSpecific(Tag.epochKey2) }).flatMap { f -> Data? in
                if case .null = f.value { return nil }
                return f.value.dataValue
            }
            let epochStartTime2 = fields.first(where: { $0.tag == .contextSpecific(Tag.epochStartTime2) }).flatMap { f -> UInt64? in
                if case .null = f.value { return nil }
                return f.value.uintValue
            }

            return GroupKeySetStruct(
                groupKeySetID: UInt16(idVal),
                groupKeySecurityPolicy: policy,
                epochKey0: epochKey0,
                epochStartTime0: epochStartTime0,
                epochKey1: epochKey1,
                epochStartTime1: epochStartTime1,
                epochKey2: epochKey2,
                epochStartTime2: epochStartTime2
            )
        }
    }

    // MARK: - GroupKeyMapStruct

    /// Maps a group ID to a key set ID within a fabric.
    ///
    /// ```
    /// Structure {
    ///   0: groupID (unsigned int)
    ///   1: groupKeySetID (unsigned int)
    ///   0xFE: fabricIndex (unsigned int)
    /// }
    /// ```
    public struct GroupKeyMapStruct: Sendable, Equatable {

        private enum Tag {
            static let groupID: UInt8 = 0
            static let groupKeySetID: UInt8 = 1
            static let fabricIndex: UInt8 = 0xFE
        }

        public let groupID: UInt16
        public let groupKeySetID: UInt16
        public let fabricIndex: UInt8

        public init(groupID: UInt16, groupKeySetID: UInt16, fabricIndex: UInt8) {
            self.groupID = groupID
            self.groupKeySetID = groupKeySetID
            self.fabricIndex = fabricIndex
        }

        public func toTLVElement() -> TLVElement {
            .structure([
                .init(tag: .contextSpecific(Tag.groupID), value: .unsignedInt(UInt64(groupID))),
                .init(tag: .contextSpecific(Tag.groupKeySetID), value: .unsignedInt(UInt64(groupKeySetID))),
                .init(tag: .contextSpecific(Tag.fabricIndex), value: .unsignedInt(UInt64(fabricIndex)))
            ])
        }

        public static func fromTLVElement(_ element: TLVElement) throws -> GroupKeyMapStruct {
            guard case .structure(let fields) = element else {
                throw GroupKeyManagementError.invalidStructure
            }
            guard let gid = fields.first(where: { $0.tag == .contextSpecific(Tag.groupID) })?.value.uintValue,
                  let ksid = fields.first(where: { $0.tag == .contextSpecific(Tag.groupKeySetID) })?.value.uintValue,
                  let fi = fields.first(where: { $0.tag == .contextSpecific(Tag.fabricIndex) })?.value.uintValue else {
                throw GroupKeyManagementError.missingField
            }
            return GroupKeyMapStruct(
                groupID: UInt16(gid),
                groupKeySetID: UInt16(ksid),
                fabricIndex: UInt8(fi)
            )
        }
    }

    // MARK: - GroupInfoMapStruct

    /// Describes a group and its endpoint membership.
    ///
    /// ```
    /// Structure {
    ///   0: groupID (unsigned int)
    ///   1: endpoints (array of unsigned int)
    ///   2: groupName (string, optional)
    ///   0xFE: fabricIndex (unsigned int)
    /// }
    /// ```
    public struct GroupInfoMapStruct: Sendable, Equatable {

        private enum Tag {
            static let groupID: UInt8 = 0
            static let endpoints: UInt8 = 1
            static let groupName: UInt8 = 2
            static let fabricIndex: UInt8 = 0xFE
        }

        public let groupID: UInt16
        public let endpoints: [UInt16]
        public let groupName: String?
        public let fabricIndex: UInt8

        public init(groupID: UInt16, endpoints: [UInt16], groupName: String? = nil, fabricIndex: UInt8) {
            self.groupID = groupID
            self.endpoints = endpoints
            self.groupName = groupName
            self.fabricIndex = fabricIndex
        }

        public func toTLVElement() -> TLVElement {
            var fields: [TLVElement.TLVField] = [
                .init(tag: .contextSpecific(Tag.groupID), value: .unsignedInt(UInt64(groupID))),
                .init(tag: .contextSpecific(Tag.endpoints), value: .array(endpoints.map { .unsignedInt(UInt64($0)) }))
            ]
            if let name = groupName {
                fields.append(.init(tag: .contextSpecific(Tag.groupName), value: .utf8String(name)))
            }
            fields.append(.init(tag: .contextSpecific(Tag.fabricIndex), value: .unsignedInt(UInt64(fabricIndex))))
            return .structure(fields)
        }

        public static func fromTLVElement(_ element: TLVElement) throws -> GroupInfoMapStruct {
            guard case .structure(let fields) = element else {
                throw GroupKeyManagementError.invalidStructure
            }
            guard let gid = fields.first(where: { $0.tag == .contextSpecific(Tag.groupID) })?.value.uintValue,
                  let fi = fields.first(where: { $0.tag == .contextSpecific(Tag.fabricIndex) })?.value.uintValue else {
                throw GroupKeyManagementError.missingField
            }
            var eps: [UInt16] = []
            if let epsField = fields.first(where: { $0.tag == .contextSpecific(Tag.endpoints) }),
               case .array(let elements) = epsField.value {
                eps = elements.compactMap { $0.uintValue.map { UInt16($0) } }
            }
            let name = fields.first(where: { $0.tag == .contextSpecific(Tag.groupName) })?.value.stringValue
            return GroupInfoMapStruct(
                groupID: UInt16(gid),
                endpoints: eps,
                groupName: name,
                fabricIndex: UInt8(fi)
            )
        }
    }

    // MARK: - Errors

    public enum GroupKeyManagementError: Error, Sendable {
        case invalidStructure
        case missingField
        case keySetNotFound
    }
}
