// AdminCommissioningHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// Cluster handler for the Administrator Commissioning cluster (0x003C).
///
/// Controls commissioning window management. For bridge devices, we support
/// the basic commissioning mode (advertised via mDNS with CM=1). Future
/// versions may add Enhanced Commissioning with PAKE verifier injection.
public struct AdminCommissioningHandler: ClusterHandler {

    public let clusterID = ClusterID.adminCommissioning

    // MARK: - Attribute IDs

    public enum Attribute {
        /// WindowStatus: 0 = not open, 1 = EnhancedWindowOpen, 2 = BasicWindowOpen.
        public static let windowStatus          = AttributeID(rawValue: 0x0000)
        /// AdminFabricIndex: fabric that opened the window, null if none.
        public static let adminFabricIndex      = AttributeID(rawValue: 0x0001)
        /// AdminVendorId: vendor that opened the window, null if none.
        public static let adminVendorId         = AttributeID(rawValue: 0x0002)
    }

    // MARK: - Command IDs

    public enum Command {
        public static let openCommissioningWindow       = CommandID(rawValue: 0x00)
        public static let openBasicCommissioningWindow  = CommandID(rawValue: 0x01)
        public static let revokeCommissioning           = CommandID(rawValue: 0x02)
    }

    public init() {}

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        [
            (Attribute.windowStatus, .unsignedInt(2)),       // BasicWindowOpen by default
            (Attribute.adminFabricIndex, .null),
            (Attribute.adminVendorId, .null),
        ]
    }

    public func handleCommand(
        commandID: CommandID,
        fields: TLVElement?,
        store: AttributeStore,
        endpointID: EndpointID
    ) throws -> TLVElement? {
        switch commandID {
        case Command.revokeCommissioning:
            store.set(endpoint: endpointID, cluster: clusterID, attribute: Attribute.windowStatus, value: .unsignedInt(0))
            return nil

        case Command.openBasicCommissioningWindow:
            store.set(endpoint: endpointID, cluster: clusterID, attribute: Attribute.windowStatus, value: .unsignedInt(2))
            return nil

        default:
            return nil
        }
    }
}
