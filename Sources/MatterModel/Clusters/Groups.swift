// Groups.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes

/// Groups cluster (0x0004).
///
/// Manages group membership for an endpoint. Groups allow a controller to address
/// multiple endpoints with a single multicast message (group-addressed message).
///
/// Commands write to the per-fabric `GroupMembershipTable` to add/remove/query
/// group membership. Responses carry a `status` field using `GroupStatus` codes.
public enum GroupsCluster {

    public static let id = ClusterID(rawValue: 0x0004)

    // MARK: - Attribute IDs

    public enum Attribute {
        /// NameSupport (UInt8, read-only).
        ///
        /// Bit 7: names-supported flag.
        /// This implementation sets it to 0 (group names NOT supported).
        public static let nameSupport = AttributeID(rawValue: 0x0000)
    }

    // MARK: - Command IDs (client → server)

    public enum Command {
        /// AddGroup: groupID (tag 0, UInt16) + groupName (tag 1, String).
        public static let addGroup              = CommandID(rawValue: 0x00)
        /// ViewGroup: groupID (tag 0, UInt16).
        public static let viewGroup             = CommandID(rawValue: 0x01)
        /// GetGroupMembership: groupList (tag 0, Array of UInt16). Empty = all groups.
        public static let getGroupMembership    = CommandID(rawValue: 0x02)
        /// RemoveGroup: groupID (tag 0, UInt16).
        public static let removeGroup           = CommandID(rawValue: 0x03)
        /// RemoveAllGroups: no fields. No response payload.
        public static let removeAllGroups       = CommandID(rawValue: 0x04)
        /// AddGroupIfIdentifying: groupID (tag 0, UInt16) + groupName (tag 1, String).
        /// Adds to group if endpoint is currently identifying. No response.
        public static let addGroupIfIdentifying = CommandID(rawValue: 0x05)
    }

    // MARK: - Response Command IDs (server → client)

    public enum ResponseCommand {
        /// AddGroupResponse: status (tag 0, UInt8) + groupID (tag 1, UInt16).
        public static let addGroupResponse           = CommandID(rawValue: 0x00)
        /// ViewGroupResponse: status (tag 0, UInt8) + groupID (tag 1, UInt16) + groupName (tag 2, String).
        public static let viewGroupResponse          = CommandID(rawValue: 0x01)
        /// GetGroupMembershipResponse: capacity (tag 0, UInt8 or null) + groupList (tag 1, Array of UInt16).
        public static let getGroupMembershipResponse = CommandID(rawValue: 0x02)
        /// RemoveGroupResponse: status (tag 0, UInt8) + groupID (tag 1, UInt16).
        public static let removeGroupResponse        = CommandID(rawValue: 0x03)
    }

    // MARK: - Status Codes

    /// Status codes returned in Groups cluster command responses.
    ///
    /// Success uses the general success code (0x00). The others are Groups-specific
    /// cluster-status values defined in the Matter spec §1.3.7.
    public enum GroupStatus: UInt8, Sendable {
        case success           = 0x00
        case resourceExhausted = 0x89
        case duplicate         = 0x8A
        case notFound          = 0x8B
        case invalidInState    = 0x8C
    }
}
