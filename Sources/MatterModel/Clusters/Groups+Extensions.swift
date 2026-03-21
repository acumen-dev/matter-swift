// Groups+Extensions.swift
// Copyright 2026 Monagle Pty Ltd

import MatterTypes

extension GroupsCluster {

    // MARK: - Response Commands

    /// Response command IDs sent from server to client.
    public enum ResponseCommand {
        /// AddGroupResponse (0x00)
        public static let addGroupResponse = CommandID(rawValue: 0x0000)
        /// ViewGroupResponse (0x01)
        public static let viewGroupResponse = CommandID(rawValue: 0x0001)
        /// GetGroupMembershipResponse (0x02)
        public static let getGroupMembershipResponse = CommandID(rawValue: 0x0002)
        /// RemoveGroupResponse (0x03)
        public static let removeGroupResponse = CommandID(rawValue: 0x0003)
    }

    // MARK: - Group Status

    /// Status codes used in Groups cluster command responses.
    public enum GroupStatus: UInt8, Sendable {
        /// Operation completed successfully.
        case success = 0x00
        /// The specified group was not found.
        case notFound = 0x8B
        /// No resources available to complete the operation.
        case resourceExhausted = 0x89
        /// The operation is not valid in the current state.
        case invalidInState = 0xCB
    }
}
