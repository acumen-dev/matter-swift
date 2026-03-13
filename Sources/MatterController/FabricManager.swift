// FabricManager.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import MatterTypes
import MatterCrypto

/// Manages the controller's fabric identity.
///
/// Holds the root CA key pair, generates Node Operational Certificates (NOCs)
/// for commissioned devices, and allocates node IDs.
///
/// ```swift
/// let fabricManager = try FabricManager(
///     rootKey: P256.Signing.PrivateKey(),
///     fabricID: FabricID(rawValue: 1),
///     controllerNodeID: NodeID(rawValue: 1),
///     vendorID: .test
/// )
/// let nodeID = await fabricManager.allocateNodeID()
/// let noc = try await fabricManager.generateNOC(
///     nodePublicKey: deviceKey.publicKey,
///     nodeID: nodeID
/// )
/// ```
public actor FabricManager {

    // MARK: - Properties

    /// The controller's fabric info (RCAC, NOC, keys).
    public nonisolated let controllerFabricInfo: FabricInfo

    /// The root CA certificate.
    public nonisolated var rcac: MatterCertificate { controllerFabricInfo.rcac }

    /// The fabric index assigned to this controller.
    public nonisolated var fabricIndex: FabricIndex { controllerFabricInfo.fabricIndex }

    /// The vendor ID for this controller.
    public nonisolated let vendorID: VendorID

    /// The IPK epoch key (default: 16 bytes of zeros per Matter spec).
    public nonisolated let ipkEpochKey: Data

    /// The root CA signing key.
    private let rootKey: P256.Signing.PrivateKey

    /// Counter for allocating node IDs.
    private var nextNodeIDValue: UInt64

    // MARK: - Init

    /// Create a fabric manager with a new or existing root CA.
    ///
    /// Generates an RCAC and a self-signed NOC for the controller node.
    ///
    /// - Parameters:
    ///   - rootKey: P-256 key pair for the root CA.
    ///   - fabricID: Fabric identifier.
    ///   - controllerNodeID: Node ID for this controller.
    ///   - vendorID: Vendor ID for NOC issuance.
    ///   - fabricIndex: Fabric index (default: 1).
    ///   - ipkEpochKey: IPK epoch key (default: 16 bytes of zeros).
    public init(
        rootKey: P256.Signing.PrivateKey,
        fabricID: FabricID,
        controllerNodeID: NodeID,
        vendorID: VendorID,
        fabricIndex: FabricIndex = FabricIndex(rawValue: 1),
        ipkEpochKey: Data = Data(repeating: 0, count: 16)
    ) throws {
        self.rootKey = rootKey
        self.vendorID = vendorID
        self.ipkEpochKey = ipkEpochKey

        // Generate RCAC
        let rcac = try MatterCertificate.generateRCAC(
            key: rootKey,
            fabricID: fabricID
        )

        // Generate controller NOC
        let controllerKey = P256.Signing.PrivateKey()
        let noc = try MatterCertificate.generateNOC(
            signerKey: rootKey,
            issuerDN: rcac.subject,
            nodePublicKey: controllerKey.publicKey,
            nodeID: controllerNodeID,
            fabricID: fabricID
        )

        self.controllerFabricInfo = FabricInfo(
            fabricIndex: fabricIndex,
            fabricID: fabricID,
            nodeID: controllerNodeID,
            rcac: rcac,
            noc: noc,
            operationalKey: controllerKey
        )

        // Start allocating node IDs after the controller's own ID
        self.nextNodeIDValue = controllerNodeID.rawValue + 1
    }

    /// Restore a fabric manager from persisted state.
    ///
    /// Reconstructs the root CA key, controller certificates, and fabric info
    /// from a `StoredControllerIdentity` without generating new certificates.
    ///
    /// - Parameters:
    ///   - stored: The persisted controller identity.
    ///   - nextNodeID: The next node ID to allocate.
    public init(stored: StoredControllerIdentity, nextNodeID: UInt64) throws {
        self.rootKey = try P256.Signing.PrivateKey(rawRepresentation: stored.rootKeyRaw)
        self.vendorID = VendorID(rawValue: stored.vendorID)
        self.ipkEpochKey = stored.ipkEpochKey

        let rcac = try MatterCertificate.fromTLV(stored.rcacTLV)
        let noc = try MatterCertificate.fromTLV(stored.nocTLV)
        let operationalKey = try P256.Signing.PrivateKey(rawRepresentation: stored.operationalKeyRaw)

        self.controllerFabricInfo = FabricInfo(
            fabricIndex: FabricIndex(rawValue: stored.fabricIndex),
            fabricID: FabricID(rawValue: stored.fabricID),
            nodeID: NodeID(rawValue: stored.controllerNodeID),
            rcac: rcac,
            noc: noc,
            operationalKey: operationalKey
        )

        self.nextNodeIDValue = nextNodeID
    }

    // MARK: - Persistence

    /// Export the current state as a `StoredControllerIdentity` for persistence.
    public nonisolated func toStoredIdentity() -> StoredControllerIdentity {
        StoredControllerIdentity(
            rootKeyRaw: rootKey.rawRepresentation,
            fabricIndex: controllerFabricInfo.fabricIndex.rawValue,
            fabricID: controllerFabricInfo.fabricID.rawValue,
            controllerNodeID: controllerFabricInfo.nodeID.rawValue,
            rcacTLV: controllerFabricInfo.rcac.tlvEncode(),
            nocTLV: controllerFabricInfo.noc.tlvEncode(),
            operationalKeyRaw: controllerFabricInfo.operationalKey.rawRepresentation,
            vendorID: vendorID.rawValue,
            ipkEpochKey: ipkEpochKey
        )
    }

    /// The current next node ID value (for persistence).
    public var nextNodeID: UInt64 {
        nextNodeIDValue
    }

    // MARK: - Node ID Allocation

    /// Allocate the next available node ID.
    ///
    /// Node IDs are sequentially allocated starting from
    /// `controllerNodeID + 1`.
    public func allocateNodeID() -> NodeID {
        let id = NodeID(rawValue: nextNodeIDValue)
        nextNodeIDValue += 1
        return id
    }

    // MARK: - NOC Generation

    /// Generate a Node Operational Certificate for a commissioned device.
    ///
    /// The NOC is signed by the root CA and chains back to the RCAC.
    ///
    /// - Parameters:
    ///   - nodePublicKey: The device's operational public key (from CSR).
    ///   - nodeID: The node ID to assign to the device.
    /// - Returns: A Matter-encoded NOC.
    public func generateNOC(
        nodePublicKey: P256.Signing.PublicKey,
        nodeID: NodeID
    ) throws -> MatterCertificate {
        try MatterCertificate.generateNOC(
            signerKey: rootKey,
            issuerDN: rcac.subject,
            nodePublicKey: nodePublicKey,
            nodeID: nodeID,
            fabricID: controllerFabricInfo.fabricID
        )
    }

    // MARK: - IPK

    /// Derive the Identity Protection Key for this fabric.
    ///
    /// Convenience wrapper around `FabricInfo.deriveIPK()`.
    public nonisolated func deriveIPK() -> Data {
        controllerFabricInfo.deriveIPK(epochKey: ipkEpochKey)
    }

    /// The compressed fabric identifier for this fabric.
    public nonisolated func compressedFabricID() -> UInt64 {
        controllerFabricInfo.compressedFabricID()
    }
}
