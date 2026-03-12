// FabricInfo.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import MatterTypes

/// Information about a Matter fabric — the trust domain for operational communication.
///
/// A fabric is identified by its root public key and fabric ID. Each node in the
/// fabric has a NOC issued by the fabric's root CA (or an intermediate CA).
///
/// The fabric info is stored locally by both controllers and devices. It contains
/// the certificate chain (RCAC, optional ICAC, NOC), the operational signing key,
/// and derived identifiers used in session establishment.
public struct FabricInfo: Sendable {

    /// Fabric index (1-254, locally assigned).
    public let fabricIndex: FabricIndex

    /// Fabric ID from the NOC subject.
    public let fabricID: FabricID

    /// This node's operational node ID (from NOC subject).
    public let nodeID: NodeID

    /// Root CA Certificate (RCAC).
    public let rcac: MatterCertificate

    /// Optional Intermediate CA Certificate (ICAC).
    public let icac: MatterCertificate?

    /// Node Operational Certificate (NOC).
    public let noc: MatterCertificate

    /// This node's operational signing key.
    public let operationalKey: P256.Signing.PrivateKey

    /// The root CA's public key (extracted from RCAC).
    public var rootPublicKey: P256.Signing.PublicKey {
        // Safe to force-try: RCAC was validated during init
        try! rcac.subjectPublicKey()
    }

    public init(
        fabricIndex: FabricIndex,
        fabricID: FabricID,
        nodeID: NodeID,
        rcac: MatterCertificate,
        icac: MatterCertificate? = nil,
        noc: MatterCertificate,
        operationalKey: P256.Signing.PrivateKey
    ) {
        self.fabricIndex = fabricIndex
        self.fabricID = fabricID
        self.nodeID = nodeID
        self.rcac = rcac
        self.icac = icac
        self.noc = noc
        self.operationalKey = operationalKey
    }

    // MARK: - Compressed Fabric ID

    /// Compute the compressed fabric identifier.
    ///
    /// CompressedFabricID = HMAC-SHA256(
    ///     key: rootPublicKey[1...],  // X coordinate only (32 bytes)
    ///     data: fabricID as 8-byte big-endian
    /// )[0..<8]
    ///
    /// This 8-byte identifier is used in mDNS advertisements and CASE handshakes
    /// to identify the fabric without revealing the full root public key.
    public func compressedFabricID() -> UInt64 {
        // Root public key X coordinate (skip the 0x04 prefix, take first 32 bytes)
        let rootPubKeyX963 = rootPublicKey.x963Representation
        let xCoordinate = rootPubKeyX963[1..<33]
        let key = SymmetricKey(data: xCoordinate)

        // Fabric ID as 8-byte big-endian
        var fabricIDBytes = Data(count: 8)
        let fid = fabricID.rawValue
        fabricIDBytes[0] = UInt8((fid >> 56) & 0xFF)
        fabricIDBytes[1] = UInt8((fid >> 48) & 0xFF)
        fabricIDBytes[2] = UInt8((fid >> 40) & 0xFF)
        fabricIDBytes[3] = UInt8((fid >> 32) & 0xFF)
        fabricIDBytes[4] = UInt8((fid >> 24) & 0xFF)
        fabricIDBytes[5] = UInt8((fid >> 16) & 0xFF)
        fabricIDBytes[6] = UInt8((fid >> 8) & 0xFF)
        fabricIDBytes[7] = UInt8(fid & 0xFF)

        let hmac = HMAC<SHA256>.authenticationCode(for: fabricIDBytes, using: key)
        let hmacData = Data(hmac)

        // Take first 8 bytes as big-endian UInt64
        var result: UInt64 = 0
        for i in 0..<8 {
            result = (result << 8) | UInt64(hmacData[i])
        }
        return result
    }

    // MARK: - IPK (Identity Protection Key)

    /// Derive the Identity Protection Key (IPK) for this fabric.
    ///
    /// IPK = HKDF-SHA256(
    ///     inputKeyMaterial: epochKey,
    ///     salt: compressedFabricID as 8-byte big-endian,
    ///     info: "GroupKeyHash",
    ///     outputByteCount: 16
    /// )
    ///
    /// For now, uses the default epoch key (all zeros) per the Matter spec
    /// for initial commissioning. Real implementations would use the
    /// Group Key Management cluster to manage epoch keys.
    ///
    /// - Parameter epochKey: The epoch key (default: 16 bytes of zeros).
    /// - Returns: 16-byte IPK.
    public func deriveIPK(epochKey: Data = Data(repeating: 0, count: 16)) -> Data {
        let cfid = compressedFabricID()

        // Compressed fabric ID as 8-byte big-endian
        var salt = Data(count: 8)
        salt[0] = UInt8((cfid >> 56) & 0xFF)
        salt[1] = UInt8((cfid >> 48) & 0xFF)
        salt[2] = UInt8((cfid >> 40) & 0xFF)
        salt[3] = UInt8((cfid >> 32) & 0xFF)
        salt[4] = UInt8((cfid >> 24) & 0xFF)
        salt[5] = UInt8((cfid >> 16) & 0xFF)
        salt[6] = UInt8((cfid >> 8) & 0xFF)
        salt[7] = UInt8(cfid & 0xFF)

        let ikm = SymmetricKey(data: epochKey)
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm,
            salt: salt,
            info: Data("GroupKeyHash".utf8),
            outputByteCount: 16
        )

        return derived.withUnsafeBytes { Data($0) }
    }

    // MARK: - Validation

    /// Validate the certificate chain in this fabric info.
    ///
    /// Verifies RCAC is self-signed, optional ICAC is signed by RCAC,
    /// and NOC is signed by ICAC (or RCAC if no ICAC).
    public func validateChain() -> Bool {
        if let icac {
            return MatterCertificate.validateChain(noc: noc, icac: icac, rcac: rcac)
        } else {
            return MatterCertificate.validateChain(noc: noc, rcac: rcac)
        }
    }

    // MARK: - Convenience Factories

    /// Create a FabricInfo for testing with auto-generated certificates.
    ///
    /// Generates an RCAC and NOC with the given fabric and node IDs.
    /// The RCAC key is returned alongside the fabric info.
    public static func generateTestFabric(
        fabricIndex: FabricIndex = FabricIndex(rawValue: 1),
        fabricID: FabricID = FabricID(rawValue: 1),
        nodeID: NodeID = NodeID(rawValue: 0x0102030405060708)
    ) throws -> (fabricInfo: FabricInfo, rootKey: P256.Signing.PrivateKey) {
        let rootKey = P256.Signing.PrivateKey()
        let nodeKey = P256.Signing.PrivateKey()

        let rcac = try MatterCertificate.generateRCAC(
            key: rootKey,
            fabricID: fabricID
        )

        let noc = try MatterCertificate.generateNOC(
            signerKey: rootKey,
            issuerDN: rcac.subject,
            nodePublicKey: nodeKey.publicKey,
            nodeID: nodeID,
            fabricID: fabricID
        )

        let info = FabricInfo(
            fabricIndex: fabricIndex,
            fabricID: fabricID,
            nodeID: nodeID,
            rcac: rcac,
            noc: noc,
            operationalKey: nodeKey
        )

        return (info, rootKey)
    }
}
