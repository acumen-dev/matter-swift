// AdminCommissioningHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel
import MatterCrypto

/// Cluster handler for the Administrator Commissioning cluster (0x003C).
///
/// Manages commissioning window lifecycle. Supports both basic and enhanced
/// commissioning window modes, with timeout enforcement.
///
/// Per Matter spec §11.18:
/// - `OpenCommissioningWindow` (enhanced mode) opens a window with an injected PAKE verifier
/// - `OpenBasicCommissioningWindow` opens a time-limited window (180–900s)
/// - `RevokeCommissioning` closes an open window
/// - Only one window can be open at a time
public struct AdminCommissioningHandler: ClusterHandler, @unchecked Sendable {

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

    /// Shared commissioning state for window management.
    public let commissioningState: CommissioningState

    public init(commissioningState: CommissioningState) {
        self.commissioningState = commissioningState
    }

    /// Convenience init for backward compatibility (tests that don't need state).
    public init() {
        self.commissioningState = CommissioningState()
    }

    // MARK: - Timed Interaction

    /// OpenCommissioningWindow, OpenBasicCommissioningWindow, and RevokeCommissioning
    /// are security-sensitive and require a timed interaction per §11.18.
    public func requiresTimedInteraction(commandID: CommandID) -> Bool {
        commandID == Command.openCommissioningWindow
            || commandID == Command.openBasicCommissioningWindow
            || commandID == Command.revokeCommissioning
    }

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        [
            (Attribute.windowStatus, .unsignedInt(UInt64(commissioningState.windowStatus.rawValue))),
            (Attribute.adminFabricIndex, .null),
            (Attribute.adminVendorId, .null),
        ]
    }

    public func acceptedCommands() -> [CommandID] {
        [
            Command.openCommissioningWindow,
            Command.openBasicCommissioningWindow,
            Command.revokeCommissioning,
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
            return handleRevokeCommissioning(store: store, endpointID: endpointID)

        case Command.openBasicCommissioningWindow:
            return try handleOpenBasicCommissioningWindow(
                fields: fields,
                store: store,
                endpointID: endpointID
            )

        case Command.openCommissioningWindow:
            return try handleOpenCommissioningWindow(
                fields: fields,
                store: store,
                endpointID: endpointID
            )

        default:
            return nil
        }
    }

    // MARK: - OpenCommissioningWindow (Enhanced)

    /// Handle OpenCommissioningWindow command (enhanced mode, §11.18.8.1).
    ///
    /// Command fields:
    /// ```
    /// Structure {
    ///   0: commissioningTimeout (uint16, seconds)
    ///   1: PAKEPasscodeVerifier (octet string, 97 bytes: W0[32] || L[65])
    ///   2: discriminator (uint16, 12-bit)
    ///   3: iterations (uint32, PBKDF2 iteration count)
    ///   4: salt (octet string, 16–32 bytes)
    /// }
    /// ```
    private func handleOpenCommissioningWindow(
        fields: TLVElement?,
        store: AttributeStore,
        endpointID: EndpointID
    ) throws -> TLVElement? {
        // Reject if window already open
        guard !commissioningState.isWindowOpen else {
            return nil  // Busy — spec says return status BUSY
        }

        guard let fields,
              case .structure(let structFields) = fields else {
            return nil
        }

        // Parse commissioningTimeout (tag 0)
        guard let timeoutValue = structFields.first(where: { $0.tag == .contextSpecific(0) })?.value.uintValue else {
            return nil
        }
        let timeout = UInt16(min(max(timeoutValue, 180), 900))

        // Parse PAKEPasscodeVerifier (tag 1) — 97 bytes: W0[32] || L[65]
        guard let verifierData = structFields.first(where: { $0.tag == .contextSpecific(1) })?.value.dataValue,
              verifierData.count == 97 else {
            return nil
        }
        let w0 = Data(verifierData[0..<32])
        let L = Data(verifierData[32..<97])

        // Parse discriminator (tag 2)
        guard let discriminatorValue = structFields.first(where: { $0.tag == .contextSpecific(2) })?.value.uintValue else {
            return nil
        }
        let discriminator = UInt16(discriminatorValue & 0x0FFF)  // Mask to 12 bits

        // Parse iterations (tag 3)
        guard let iterationsValue = structFields.first(where: { $0.tag == .contextSpecific(3) })?.value.uintValue else {
            return nil
        }
        let iterations = UInt32(iterationsValue)

        // Parse salt (tag 4) — 16–32 bytes
        guard let salt = structFields.first(where: { $0.tag == .contextSpecific(4) })?.value.dataValue,
              salt.count >= 16 && salt.count <= 32 else {
            return nil
        }

        let injectedVerifier = InjectedPAKEVerifier(
            w0: w0,
            L: L,
            discriminator: discriminator,
            iterations: iterations,
            salt: salt
        )

        commissioningState.openEnhancedWindow(
            timeout: timeout,
            verifier: injectedVerifier,
            fabricIndex: commissioningState.windowAdminFabricIndex,
            vendorId: commissioningState.windowAdminVendorId
        )

        updateWindowAttributes(store: store, endpointID: endpointID)

        return nil
    }

    // MARK: - OpenBasicCommissioningWindow

    /// Handle OpenBasicCommissioningWindow command.
    ///
    /// Per Matter spec §11.18.8.2:
    /// - commissioningTimeout: uint16, seconds (180–900)
    /// - Fails if a window is already open (busy)
    private func handleOpenBasicCommissioningWindow(
        fields: TLVElement?,
        store: AttributeStore,
        endpointID: EndpointID
    ) throws -> TLVElement? {
        // Reject if window already open
        guard !commissioningState.isWindowOpen else {
            return nil  // Busy — spec says return status BUSY
        }

        // Parse commissioningTimeout from fields
        // Structure { 0: commissioningTimeout (uint16) }
        var timeout: UInt16 = 180  // Default minimum
        if let fields,
           case .structure(let structFields) = fields,
           let timeoutField = structFields.first(where: { $0.tag == .contextSpecific(0) }),
           let timeoutValue = timeoutField.value.uintValue {
            timeout = UInt16(min(max(timeoutValue, 180), 900))
        }

        commissioningState.openBasicWindow(
            timeout: timeout,
            fabricIndex: commissioningState.windowAdminFabricIndex,
            vendorId: commissioningState.windowAdminVendorId
        )

        updateWindowAttributes(store: store, endpointID: endpointID)

        return nil
    }

    // MARK: - RevokeCommissioning

    /// Handle RevokeCommissioning command.
    ///
    /// Closes the commissioning window and clears admin attributes.
    private func handleRevokeCommissioning(
        store: AttributeStore,
        endpointID: EndpointID
    ) -> TLVElement? {
        commissioningState.closeWindow()
        updateWindowAttributes(store: store, endpointID: endpointID)
        return nil
    }

    // MARK: - Attribute Sync

    /// Update cluster attributes to reflect current window state.
    public func updateWindowAttributes(store: AttributeStore, endpointID: EndpointID) {
        store.set(
            endpoint: endpointID,
            cluster: clusterID,
            attribute: Attribute.windowStatus,
            value: .unsignedInt(UInt64(commissioningState.windowStatus.rawValue))
        )

        if let fabricIndex = commissioningState.windowAdminFabricIndex {
            store.set(
                endpoint: endpointID,
                cluster: clusterID,
                attribute: Attribute.adminFabricIndex,
                value: .unsignedInt(UInt64(fabricIndex.rawValue))
            )
        } else {
            store.set(
                endpoint: endpointID,
                cluster: clusterID,
                attribute: Attribute.adminFabricIndex,
                value: .null
            )
        }

        if let vendorId = commissioningState.windowAdminVendorId {
            store.set(
                endpoint: endpointID,
                cluster: clusterID,
                attribute: Attribute.adminVendorId,
                value: .unsignedInt(UInt64(vendorId))
            )
        } else {
            store.set(
                endpoint: endpointID,
                cluster: clusterID,
                attribute: Attribute.adminVendorId,
                value: .null
            )
        }
    }
}
