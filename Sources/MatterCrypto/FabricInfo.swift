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

    /// Raw TLV bytes of the NOC, as received during commissioning.
    ///
    /// Stored separately from `noc` so that CASE Sigma2 can forward the exact bytes
    /// Apple Home provided without any re-encoding roundtrip. CASE uses these bytes
    /// directly in Sigma2's `TBSData2` and `Sigma2Decrypted`.
    public let rawNOC: Data?

    /// Raw TLV bytes of the ICAC, as received during commissioning.
    ///
    /// Stored separately from `icac` so that CASE Sigma2 can forward the exact bytes
    /// Apple Home provided — even if `MatterCertificate.fromTLV()` failed to parse them.
    /// When non-nil, CASE uses these bytes directly in Sigma2's `TBSData2` and
    /// `Sigma2Decrypted` rather than re-encoding `icac`.
    public let rawICAC: Data?

    /// Node Operational Certificate (NOC).
    public let noc: MatterCertificate

    /// This node's operational signing key.
    public let operationalKey: P256.Signing.PrivateKey

    /// IPK epoch key for this fabric (16 bytes).
    ///
    /// Received from the commissioner in the AddNOC command's `IPKValue` field.
    /// Used to derive the Identity Protection Key via HKDF-SHA256. Defaults to
    /// all-zeros for backward compatibility with test fabrics that don't set one.
    public let ipkEpochKey: Data

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
        rawICAC: Data? = nil,
        noc: MatterCertificate,
        rawNOC: Data? = nil,
        operationalKey: P256.Signing.PrivateKey,
        ipkEpochKey: Data = Data(repeating: 0, count: 16)
    ) {
        self.fabricIndex = fabricIndex
        self.fabricID = fabricID
        self.nodeID = nodeID
        self.rcac = rcac
        self.icac = icac
        self.rawICAC = rawICAC ?? icac?.tlvEncode()
        self.noc = noc
        self.rawNOC = rawNOC
        self.operationalKey = operationalKey
        self.ipkEpochKey = ipkEpochKey
    }

    // MARK: - Compressed Fabric ID

    /// Compute the compressed fabric identifier per Matter spec §4.3.1.2.2.
    ///
    /// CompressedFabricID = Crypto_KDF(
    ///     InputKey = rootPublicKey (raw 64-byte X‖Y, without the 0x04 uncompressed prefix),
    ///     Salt     = fabricID,     // 8-byte big-endian
    ///     Info     = "CompressedFabric",
    ///     Length   = 8
    /// )
    ///
    /// Crypto_KDF is HKDF-SHA256. This 8-byte identifier is used in mDNS
    /// operational instance names and CASE handshake destination IDs.
    ///
    /// - Note: The spec wording "RootPublicKey.X" is misleading. The CHIP SDK uses
    ///   the full 64-byte raw key (X‖Y without the 0x04 prefix) as HKDF IKM, not just
    ///   the 32-byte X coordinate. Using only X produces a CFID that does not match
    ///   Apple Home / homed.
    public func compressedFabricID() -> UInt64 {
        // IKM = full 64-byte raw public key (X‖Y), skipping the 0x04 uncompressed prefix.
        // The CHIP SDK uses all 64 bytes, not just the 32-byte X coordinate.
        let rootPubKeyX963 = rootPublicKey.x963Representation
        let rawKey = rootPubKeyX963[1...]   // 64 bytes: X‖Y, without the 0x04 prefix
        let ikm = SymmetricKey(data: rawKey)

        // Fabric ID as 8-byte big-endian salt
        var salt = Data(count: 8)
        let fid = fabricID.rawValue
        salt[0] = UInt8((fid >> 56) & 0xFF)
        salt[1] = UInt8((fid >> 48) & 0xFF)
        salt[2] = UInt8((fid >> 40) & 0xFF)
        salt[3] = UInt8((fid >> 32) & 0xFF)
        salt[4] = UInt8((fid >> 24) & 0xFF)
        salt[5] = UInt8((fid >> 16) & 0xFF)
        salt[6] = UInt8((fid >> 8) & 0xFF)
        salt[7] = UInt8(fid & 0xFF)

        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm,
            salt: salt,
            info: Data("CompressedFabric".utf8),
            outputByteCount: 8
        )

        // Interpret the 8-byte output as a big-endian UInt64
        var result: UInt64 = 0
        derived.withUnsafeBytes { bytes in
            for i in 0..<8 {
                result = (result << 8) | UInt64(bytes[i])
            }
        }
        return result
    }

    // MARK: - IPK (Identity Protection Key)

    /// Derive the Identity Protection Key (IPK) for this fabric.
    ///
    /// IPK = HKDF-SHA256(
    ///     inputKeyMaterial: epochKey,
    ///     salt: compressedFabricID as 8-byte big-endian,
    ///     info: "GroupKey v1.0",
    ///     outputByteCount: 16
    /// )
    ///
    /// The epoch key for production fabrics is the `IPKValue` from the AddNOC
    /// command, stored in `FabricInfo.ipkEpochKey`. All-zeros is the correct
    /// default for test fabrics generated without a commissioner.
    ///
    /// - Parameter epochKey: The epoch key. Defaults to `self.ipkEpochKey` when `nil`;
    ///   pass an explicit value only in tests or when probing with a specific key.
    /// - Returns: 16-byte IPK.
    public func deriveIPK(epochKey: Data? = nil) -> Data {
        let cfid = compressedFabricID()
        let epochKey = epochKey ?? self.ipkEpochKey

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
            info: Data("GroupKey v1.0".utf8),
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
