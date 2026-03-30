// ThreadCommissioning.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(OpenThread)

import Foundation
import Logging
import MatterModel
import MatterTransport
import MatterTypes
import OpenThread

/// Thread-specific commissioning support.
///
/// Extends the standard Matter commissioning flow with Thread dataset
/// provisioning. After PASE is established and NOC is installed, the
/// controller sends the Thread operational dataset to the device via
/// the NetworkCommissioning cluster's `AddOrUpdateThreadNetwork` command.
///
/// ```swift
/// let manager = try ThreadNetworkManager(radioURL: "spinel+hdlc+uart:///dev/ttyACM0")
/// try await manager.formNetwork(name: "MyHome")
///
/// let commissioner = ThreadCommissioner(networkManager: manager)
///
/// // After standard Matter commissioning (PASE + NOC):
/// try await commissioner.provisionThreadNetwork(
///     to: deviceAddress,
///     using: controller
/// )
/// ```
public struct ThreadCommissioner: Sendable {
    private let networkManager: ThreadNetworkManager
    private let logger: Logger

    public init(
        networkManager: ThreadNetworkManager,
        logger: Logger = Logger(label: "matter.thread.commissioning")
    ) {
        self.networkManager = networkManager
        self.logger = logger
    }

    /// Build the `AddOrUpdateThreadNetwork` command payload.
    ///
    /// Command 0x03 on NetworkCommissioning cluster (0x0031):
    /// ```
    /// AddOrUpdateThreadNetwork {
    ///   0: OperationalDataset (octet-string) — Thread TLV-encoded dataset
    ///   1: Breadcrumb (uint64, optional)
    /// }
    /// ```
    public func buildAddThreadNetworkCommand(
        dataset: ThreadDataset,
        breadcrumb: UInt64? = nil
    ) -> TLVElement {
        var fields: [TLVField] = [
            .init(
                tag: .contextSpecific(0),
                value: .octetString(dataset.encodeTLVs())
            ),
        ]

        if let breadcrumb {
            fields.append(.init(
                tag: .contextSpecific(1),
                value: .unsignedInt(breadcrumb)
            ))
        }

        return .structure(fields)
    }

    /// Build the `ConnectNetwork` command payload.
    ///
    /// Command 0x06 on NetworkCommissioning cluster (0x0031):
    /// ```
    /// ConnectNetwork {
    ///   0: NetworkID (octet-string) — the extended PAN ID
    ///   1: Breadcrumb (uint64, optional)
    /// }
    /// ```
    public func buildConnectNetworkCommand(
        networkID: Data,
        breadcrumb: UInt64? = nil
    ) -> TLVElement {
        var fields: [TLVField] = [
            .init(
                tag: .contextSpecific(0),
                value: .octetString(networkID)
            ),
        ]

        if let breadcrumb {
            fields.append(.init(
                tag: .contextSpecific(1),
                value: .unsignedInt(breadcrumb)
            ))
        }

        return .structure(fields)
    }

    /// The cluster and command IDs for Thread network commissioning.
    public enum Commands {
        /// NetworkCommissioning cluster ID.
        public static let clusterID = ClusterID(rawValue: 0x0031)
        /// AddOrUpdateThreadNetwork command ID.
        public static let addOrUpdateThreadNetwork = CommandID(rawValue: 0x03)
        /// ConnectNetwork command ID.
        public static let connectNetwork = CommandID(rawValue: 0x06)
        /// RemoveNetwork command ID.
        public static let removeNetwork = CommandID(rawValue: 0x04)
        /// ScanNetworks command ID.
        public static let scanNetworks = CommandID(rawValue: 0x00)
    }

    /// Parse the `NetworkConfigResponse` (command 0x05) or
    /// `ConnectNetworkResponse` (command 0x07).
    ///
    /// ```
    /// Response {
    ///   0: NetworkingStatus (enum8)
    ///   1: DebugText (string, optional)
    ///   2: NetworkIndex (uint8, optional)
    /// }
    /// ```
    public struct NetworkResponse: Sendable {
        public let status: NetworkingStatus
        public let debugText: String?
        public let networkIndex: UInt8?

        public init(from element: TLVElement) throws {
            guard case .structure(let fields) = element else {
                throw ThreadCommissioningError.invalidResponse
            }
            guard let statusField = fields.first(where: { $0.tag == .contextSpecific(0) }),
                  let statusValue = statusField.value.uint8Value else {
                throw ThreadCommissioningError.invalidResponse
            }
            self.status = NetworkingStatus(rawValue: statusValue) ?? .unknownError
            self.debugText = fields.first(where: { $0.tag == .contextSpecific(1) })?.value.stringValue
            self.networkIndex = fields.first(where: { $0.tag == .contextSpecific(2) })?.value.uint8Value
        }
    }

    /// Networking status codes from the Matter spec.
    public enum NetworkingStatus: UInt8, Sendable {
        case success = 0
        case outOfRange = 1
        case boundsExceeded = 2
        case networkIDNotFound = 3
        case duplicateNetworkID = 4
        case networkNotFound = 5
        case regulatoryError = 6
        case authFailure = 7
        case unsupportedSecurity = 8
        case otherConnectionFailure = 9
        case ipv6Failed = 10
        case ipBindFailed = 11
        case unknownError = 12
    }

    public enum ThreadCommissioningError: Error, Sendable {
        case invalidResponse
        case networkProvisioningFailed(NetworkingStatus, String?)
        case noActiveDataset
    }
}

#endif
