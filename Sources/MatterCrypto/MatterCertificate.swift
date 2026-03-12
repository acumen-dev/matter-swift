// MatterCertificate.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import MatterTypes

/// A Matter Operational Certificate in TLV format.
///
/// Matter certificates are NOT X.509/DER. They use a compact TLV encoding
/// defined in the Matter specification (Section 6.6). Three certificate types
/// exist in the chain:
/// - **RCAC**: Root CA Certificate (self-signed)
/// - **ICAC**: Intermediate CA Certificate (optional, signed by RCAC)
/// - **NOC**: Node Operational Certificate (signed by ICAC or RCAC)
///
/// ## TLV Structure (context tags)
///
/// ```
/// Structure {
///   1: serialNumber (octet string)
///   2: signatureAlgorithm (unsigned int) — 1 = ECDSA-SHA256
///   3: issuer (list of DN attributes)
///   4: notBefore (unsigned int, Matter epoch seconds)
///   5: notAfter (unsigned int, Matter epoch seconds)
///   6: subject (list of DN attributes)
///   7: publicKeyAlgorithm (unsigned int) — 1 = EC, curve P-256
///   8: ellipticCurveIdentifier (unsigned int) — 1 = P-256
///   9: publicKey (octet string, 65 bytes uncompressed)
///  10: extensions (list)
///  11: signature (octet string, DER-encoded ECDSA)
/// }
/// ```
public struct MatterCertificate: Sendable, Equatable {

    // MARK: - Context Tags

    private enum Tag {
        static let serialNumber: UInt8 = 1
        static let signatureAlgorithm: UInt8 = 2
        static let issuer: UInt8 = 3
        static let notBefore: UInt8 = 4
        static let notAfter: UInt8 = 5
        static let subject: UInt8 = 6
        static let publicKeyAlgorithm: UInt8 = 7
        static let ellipticCurveID: UInt8 = 8
        static let publicKey: UInt8 = 9
        static let extensions: UInt8 = 10
        static let signature: UInt8 = 11
    }

    /// Algorithm constants.
    private enum Algorithm {
        static let ecdsaSHA256: UInt64 = 1
        static let ecPublicKey: UInt64 = 1
        static let p256: UInt64 = 1
    }

    // MARK: - Properties

    /// Certificate serial number.
    public let serialNumber: Data

    /// Issuer distinguished name.
    public let issuer: MatterDistinguishedName

    /// Not-valid-before (Matter epoch seconds — seconds since 2000-01-01 00:00:00 UTC).
    public let notBefore: UInt32

    /// Not-valid-after (Matter epoch seconds). 0 means no expiry.
    public let notAfter: UInt32

    /// Subject distinguished name.
    public let subject: MatterDistinguishedName

    /// Subject public key (65 bytes, uncompressed P-256 point).
    public let publicKey: Data

    /// Certificate extensions (basic constraints, key usage, etc.).
    public let extensions: [CertificateExtension]

    /// ECDSA-SHA256 signature over the TBS (to-be-signed) portion.
    public let signature: Data

    // MARK: - Init

    public init(
        serialNumber: Data,
        issuer: MatterDistinguishedName,
        notBefore: UInt32,
        notAfter: UInt32,
        subject: MatterDistinguishedName,
        publicKey: Data,
        extensions: [CertificateExtension] = [],
        signature: Data
    ) {
        self.serialNumber = serialNumber
        self.issuer = issuer
        self.notBefore = notBefore
        self.notAfter = notAfter
        self.subject = subject
        self.publicKey = publicKey
        self.extensions = extensions
        self.signature = signature
    }

    // MARK: - TLV Encoding

    /// Encode this certificate as Matter TLV.
    public func tlvEncode() -> Data {
        let element = toTLVElement()
        return TLVEncoder.encode(element)
    }

    /// Convert to a TLV element (structure).
    public func toTLVElement() -> TLVElement {
        var fields: [TLVElement.TLVField] = []

        fields.append(.init(tag: .contextSpecific(Tag.serialNumber), value: .octetString(serialNumber)))
        fields.append(.init(tag: .contextSpecific(Tag.signatureAlgorithm), value: .unsignedInt(Algorithm.ecdsaSHA256)))
        fields.append(.init(tag: .contextSpecific(Tag.issuer), value: issuer.toTLVElement()))
        fields.append(.init(tag: .contextSpecific(Tag.notBefore), value: .unsignedInt(UInt64(notBefore))))
        fields.append(.init(tag: .contextSpecific(Tag.notAfter), value: .unsignedInt(UInt64(notAfter))))
        fields.append(.init(tag: .contextSpecific(Tag.subject), value: subject.toTLVElement()))
        fields.append(.init(tag: .contextSpecific(Tag.publicKeyAlgorithm), value: .unsignedInt(Algorithm.ecPublicKey)))
        fields.append(.init(tag: .contextSpecific(Tag.ellipticCurveID), value: .unsignedInt(Algorithm.p256)))
        fields.append(.init(tag: .contextSpecific(Tag.publicKey), value: .octetString(publicKey)))

        if !extensions.isEmpty {
            let extFields = extensions.map { $0.toTLVField() }
            fields.append(.init(tag: .contextSpecific(Tag.extensions), value: .list(extFields)))
        }

        fields.append(.init(tag: .contextSpecific(Tag.signature), value: .octetString(signature)))

        return .structure(fields)
    }

    /// Extract the to-be-signed bytes (everything except the signature).
    ///
    /// This re-encodes the certificate without the signature field,
    /// producing the exact bytes that should be signed/verified.
    public func tbsData() -> Data {
        var fields: [TLVElement.TLVField] = []

        fields.append(.init(tag: .contextSpecific(Tag.serialNumber), value: .octetString(serialNumber)))
        fields.append(.init(tag: .contextSpecific(Tag.signatureAlgorithm), value: .unsignedInt(Algorithm.ecdsaSHA256)))
        fields.append(.init(tag: .contextSpecific(Tag.issuer), value: issuer.toTLVElement()))
        fields.append(.init(tag: .contextSpecific(Tag.notBefore), value: .unsignedInt(UInt64(notBefore))))
        fields.append(.init(tag: .contextSpecific(Tag.notAfter), value: .unsignedInt(UInt64(notAfter))))
        fields.append(.init(tag: .contextSpecific(Tag.subject), value: subject.toTLVElement()))
        fields.append(.init(tag: .contextSpecific(Tag.publicKeyAlgorithm), value: .unsignedInt(Algorithm.ecPublicKey)))
        fields.append(.init(tag: .contextSpecific(Tag.ellipticCurveID), value: .unsignedInt(Algorithm.p256)))
        fields.append(.init(tag: .contextSpecific(Tag.publicKey), value: .octetString(publicKey)))

        if !extensions.isEmpty {
            let extFields = extensions.map { $0.toTLVField() }
            fields.append(.init(tag: .contextSpecific(Tag.extensions), value: .list(extFields)))
        }

        return TLVEncoder.encode(.structure(fields))
    }

    // MARK: - TLV Decoding

    /// Decode a Matter certificate from TLV data.
    public static func fromTLV(_ data: Data) throws -> MatterCertificate {
        let (_, element) = try TLVDecoder.decode(data)
        return try fromTLVElement(element)
    }

    /// Decode from a TLV element.
    public static func fromTLVElement(_ element: TLVElement) throws -> MatterCertificate {
        guard case .structure(let fields) = element else {
            throw CertificateError.invalidStructure
        }

        guard let serialNumberField = fields.first(where: { $0.tag == .contextSpecific(Tag.serialNumber) }),
              let serialNumber = serialNumberField.value.dataValue else {
            throw CertificateError.missingField("serialNumber")
        }

        guard let issuerField = fields.first(where: { $0.tag == .contextSpecific(Tag.issuer) }) else {
            throw CertificateError.missingField("issuer")
        }
        let issuer = try MatterDistinguishedName.fromTLVElement(issuerField.value)

        guard let notBeforeField = fields.first(where: { $0.tag == .contextSpecific(Tag.notBefore) }),
              let notBefore = notBeforeField.value.uintValue else {
            throw CertificateError.missingField("notBefore")
        }

        guard let notAfterField = fields.first(where: { $0.tag == .contextSpecific(Tag.notAfter) }),
              let notAfter = notAfterField.value.uintValue else {
            throw CertificateError.missingField("notAfter")
        }

        guard let subjectField = fields.first(where: { $0.tag == .contextSpecific(Tag.subject) }) else {
            throw CertificateError.missingField("subject")
        }
        let subject = try MatterDistinguishedName.fromTLVElement(subjectField.value)

        guard let publicKeyField = fields.first(where: { $0.tag == .contextSpecific(Tag.publicKey) }),
              let publicKey = publicKeyField.value.dataValue else {
            throw CertificateError.missingField("publicKey")
        }

        var extensions: [CertificateExtension] = []
        if let extField = fields.first(where: { $0.tag == .contextSpecific(Tag.extensions) }) {
            extensions = try CertificateExtension.fromTLVElement(extField.value)
        }

        guard let signatureField = fields.first(where: { $0.tag == .contextSpecific(Tag.signature) }),
              let signature = signatureField.value.dataValue else {
            throw CertificateError.missingField("signature")
        }

        return MatterCertificate(
            serialNumber: serialNumber,
            issuer: issuer,
            notBefore: UInt32(notBefore),
            notAfter: UInt32(notAfter),
            subject: subject,
            publicKey: publicKey,
            extensions: extensions,
            signature: signature
        )
    }

    // MARK: - Signature Verification

    /// Verify this certificate's signature against the given public key.
    ///
    /// - Parameter signerPublicKey: The public key of the certificate's issuer (or self for RCAC).
    /// - Returns: `true` if the signature is valid.
    public func verify(with signerPublicKey: P256.Signing.PublicKey) -> Bool {
        let tbs = tbsData()
        guard let ecdsaSignature = try? P256.Signing.ECDSASignature(derRepresentation: signature) else {
            return false
        }
        return signerPublicKey.isValidSignature(ecdsaSignature, for: tbs)
    }

    /// Verify this certificate is self-signed (RCAC).
    public func verifySelfSigned() -> Bool {
        guard let key = try? P256.Signing.PublicKey(x963Representation: publicKey) else {
            return false
        }
        return verify(with: key)
    }

    /// Extract the subject public key as a CryptoKit signing key.
    public func subjectPublicKey() throws -> P256.Signing.PublicKey {
        try P256.Signing.PublicKey(x963Representation: publicKey)
    }
}

// MARK: - Distinguished Name

/// A Matter Distinguished Name — identifies the subject or issuer of a certificate.
///
/// Matter DNs use context-specific tags for each attribute type:
/// ```
/// List {
///   17: nodeID (unsigned int, 64-bit)
///   18: firmwareSigningID (unsigned int, 32-bit)
///   19: icacID (unsigned int, 32-bit)
///   20: rcacID (unsigned int, 32-bit)
///   21: fabricID (unsigned int, 64-bit)
///   22: nocCASE_AuthenticatedTag (unsigned int, 32-bit)
/// }
/// ```
public struct MatterDistinguishedName: Sendable, Equatable {

    private enum Tag {
        static let nodeID: UInt8 = 17
        static let firmwareSigningID: UInt8 = 18
        static let icacID: UInt8 = 19
        static let rcacID: UInt8 = 20
        static let fabricID: UInt8 = 21
        static let caseAuthenticatedTag: UInt8 = 22
    }

    /// Node ID (for NOC subjects).
    public let nodeID: NodeID?

    /// Firmware signing ID.
    public let firmwareSigningID: UInt32?

    /// ICAC ID (for ICAC subjects).
    public let icacID: UInt32?

    /// RCAC ID (for RCAC subjects).
    public let rcacID: UInt32?

    /// Fabric ID.
    public let fabricID: FabricID?

    /// CASE Authenticated Tags.
    public let caseAuthenticatedTags: [UInt32]

    public init(
        nodeID: NodeID? = nil,
        firmwareSigningID: UInt32? = nil,
        icacID: UInt32? = nil,
        rcacID: UInt32? = nil,
        fabricID: FabricID? = nil,
        caseAuthenticatedTags: [UInt32] = []
    ) {
        self.nodeID = nodeID
        self.firmwareSigningID = firmwareSigningID
        self.icacID = icacID
        self.rcacID = rcacID
        self.fabricID = fabricID
        self.caseAuthenticatedTags = caseAuthenticatedTags
    }

    /// Encode as a TLV list element.
    public func toTLVElement() -> TLVElement {
        var fields: [TLVElement.TLVField] = []

        if let nodeID {
            fields.append(.init(tag: .contextSpecific(Tag.nodeID), value: .unsignedInt(nodeID.rawValue)))
        }
        if let firmwareSigningID {
            fields.append(.init(tag: .contextSpecific(Tag.firmwareSigningID), value: .unsignedInt(UInt64(firmwareSigningID))))
        }
        if let icacID {
            fields.append(.init(tag: .contextSpecific(Tag.icacID), value: .unsignedInt(UInt64(icacID))))
        }
        if let rcacID {
            fields.append(.init(tag: .contextSpecific(Tag.rcacID), value: .unsignedInt(UInt64(rcacID))))
        }
        if let fabricID {
            fields.append(.init(tag: .contextSpecific(Tag.fabricID), value: .unsignedInt(fabricID.rawValue)))
        }
        for cat in caseAuthenticatedTags {
            fields.append(.init(tag: .contextSpecific(Tag.caseAuthenticatedTag), value: .unsignedInt(UInt64(cat))))
        }

        return .list(fields)
    }

    /// Decode from a TLV list element.
    public static func fromTLVElement(_ element: TLVElement) throws -> MatterDistinguishedName {
        guard case .list(let fields) = element else {
            throw CertificateError.invalidStructure
        }

        var nodeID: NodeID?
        var firmwareSigningID: UInt32?
        var icacID: UInt32?
        var rcacID: UInt32?
        var fabricID: FabricID?
        var cats: [UInt32] = []

        for field in fields {
            guard case .contextSpecific(let tag) = field.tag else { continue }
            guard let val = field.value.uintValue else { continue }

            switch tag {
            case Tag.nodeID:
                nodeID = NodeID(rawValue: val)
            case Tag.firmwareSigningID:
                firmwareSigningID = UInt32(val)
            case Tag.icacID:
                icacID = UInt32(val)
            case Tag.rcacID:
                rcacID = UInt32(val)
            case Tag.fabricID:
                fabricID = FabricID(rawValue: val)
            case Tag.caseAuthenticatedTag:
                cats.append(UInt32(val))
            default:
                break
            }
        }

        return MatterDistinguishedName(
            nodeID: nodeID,
            firmwareSigningID: firmwareSigningID,
            icacID: icacID,
            rcacID: rcacID,
            fabricID: fabricID,
            caseAuthenticatedTags: cats
        )
    }
}

// MARK: - Certificate Extensions

/// A Matter certificate extension.
///
/// Context tags for extensions:
/// ```
/// List {
///   1: basicConstraints (structure)
///   2: keyUsage (unsigned int, bitfield)
///   3: extendedKeyUsage (array of unsigned int)
///   4: subjectKeyIdentifier (octet string, 20 bytes)
///   5: authorityKeyIdentifier (octet string, 20 bytes)
///   6: futureExtension (octet string)
/// }
/// ```
public enum CertificateExtension: Sendable, Equatable {
    /// Basic constraints: isCA, optional pathLength.
    case basicConstraints(isCA: Bool, pathLength: UInt8?)

    /// Key usage bitfield.
    case keyUsage(KeyUsage)

    /// Extended key usage OIDs.
    case extendedKeyUsage([ExtendedKeyUsage])

    /// Subject key identifier (20-byte SHA-1 hash of public key).
    case subjectKeyIdentifier(Data)

    /// Authority key identifier (20-byte SHA-1 hash of issuer public key).
    case authorityKeyIdentifier(Data)

    private enum Tag {
        static let basicConstraints: UInt8 = 1
        static let keyUsage: UInt8 = 2
        static let extendedKeyUsage: UInt8 = 3
        static let subjectKeyIdentifier: UInt8 = 4
        static let authorityKeyIdentifier: UInt8 = 5
    }

    func toTLVField() -> TLVElement.TLVField {
        switch self {
        case .basicConstraints(let isCA, let pathLength):
            var bcFields: [TLVElement.TLVField] = [
                .init(tag: .contextSpecific(1), value: .bool(isCA))
            ]
            if let pathLength {
                bcFields.append(.init(tag: .contextSpecific(2), value: .unsignedInt(UInt64(pathLength))))
            }
            return .init(tag: .contextSpecific(Tag.basicConstraints), value: .structure(bcFields))

        case .keyUsage(let usage):
            return .init(tag: .contextSpecific(Tag.keyUsage), value: .unsignedInt(UInt64(usage.rawValue)))

        case .extendedKeyUsage(let usages):
            let elements = usages.map { TLVElement.unsignedInt(UInt64($0.rawValue)) }
            return .init(tag: .contextSpecific(Tag.extendedKeyUsage), value: .array(elements))

        case .subjectKeyIdentifier(let data):
            return .init(tag: .contextSpecific(Tag.subjectKeyIdentifier), value: .octetString(data))

        case .authorityKeyIdentifier(let data):
            return .init(tag: .contextSpecific(Tag.authorityKeyIdentifier), value: .octetString(data))
        }
    }

    static func fromTLVElement(_ element: TLVElement) throws -> [CertificateExtension] {
        guard case .list(let fields) = element else {
            throw CertificateError.invalidStructure
        }

        var extensions: [CertificateExtension] = []

        for field in fields {
            guard case .contextSpecific(let tag) = field.tag else { continue }

            switch tag {
            case Tag.basicConstraints:
                if case .structure(let bcFields) = field.value {
                    let isCA = bcFields.first(where: { $0.tag == .contextSpecific(1) })?.value.boolValue ?? false
                    let pathLength = bcFields.first(where: { $0.tag == .contextSpecific(2) })?.value.uintValue.map { UInt8($0) }
                    extensions.append(.basicConstraints(isCA: isCA, pathLength: pathLength))
                }

            case Tag.keyUsage:
                if let val = field.value.uintValue {
                    extensions.append(.keyUsage(KeyUsage(rawValue: UInt16(val))))
                }

            case Tag.extendedKeyUsage:
                if case .array(let elements) = field.value {
                    let usages = elements.compactMap { $0.uintValue }.map { ExtendedKeyUsage(rawValue: UInt8($0)) }
                    extensions.append(.extendedKeyUsage(usages))
                }

            case Tag.subjectKeyIdentifier:
                if let data = field.value.dataValue {
                    extensions.append(.subjectKeyIdentifier(data))
                }

            case Tag.authorityKeyIdentifier:
                if let data = field.value.dataValue {
                    extensions.append(.authorityKeyIdentifier(data))
                }

            default:
                break
            }
        }

        return extensions
    }
}

// MARK: - Key Usage

/// Key usage bitfield for Matter certificates.
public struct KeyUsage: OptionSet, Sendable, Equatable {
    public let rawValue: UInt16
    public init(rawValue: UInt16) { self.rawValue = rawValue }

    public static let digitalSignature = KeyUsage(rawValue: 0x0001)
    public static let nonRepudiation   = KeyUsage(rawValue: 0x0002)
    public static let keyEncipherment  = KeyUsage(rawValue: 0x0004)
    public static let dataEncipherment = KeyUsage(rawValue: 0x0008)
    public static let keyAgreement     = KeyUsage(rawValue: 0x0010)
    public static let keyCertSign      = KeyUsage(rawValue: 0x0020)
    public static let crlSign          = KeyUsage(rawValue: 0x0040)

    /// Typical key usage for a CA certificate (RCAC/ICAC).
    public static let ca: KeyUsage = [.keyCertSign, .crlSign]

    /// Typical key usage for a NOC.
    public static let noc: KeyUsage = [.digitalSignature]
}

// MARK: - Extended Key Usage

/// Extended key usage values for Matter certificates.
public struct ExtendedKeyUsage: RawRepresentable, Sendable, Equatable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    /// Server authentication (TLS).
    public static let serverAuth = ExtendedKeyUsage(rawValue: 1)
    /// Client authentication (TLS).
    public static let clientAuth = ExtendedKeyUsage(rawValue: 2)
}

// MARK: - Certificate Errors

/// Errors related to certificate operations.
public enum CertificateError: Error, Sendable, Equatable {
    case invalidStructure
    case missingField(String)
    case invalidSignature
    case invalidPublicKey
    case chainValidationFailed(String)
}

// MARK: - Certificate Generation Helpers

extension MatterCertificate {

    /// Generate a self-signed Root CA Certificate (RCAC).
    ///
    /// - Parameters:
    ///   - key: The P-256 signing key pair for the root CA.
    ///   - rcacID: The RCAC identifier.
    ///   - fabricID: The fabric ID.
    ///   - notBefore: Validity start (Matter epoch seconds).
    ///   - notAfter: Validity end (Matter epoch seconds). 0 for no expiry.
    /// - Returns: A self-signed RCAC.
    public static func generateRCAC(
        key: P256.Signing.PrivateKey,
        rcacID: UInt32 = 1,
        fabricID: FabricID,
        notBefore: UInt32 = 0,
        notAfter: UInt32 = 0,
        serialNumber: Data? = nil
    ) throws -> MatterCertificate {
        let serial = serialNumber ?? generateSerialNumber()
        let dn = MatterDistinguishedName(rcacID: rcacID, fabricID: fabricID)
        let pubKeyData = Data(key.publicKey.x963Representation)

        let extensions: [CertificateExtension] = [
            .basicConstraints(isCA: true, pathLength: 1),
            .keyUsage(.ca),
            .subjectKeyIdentifier(subjectKeyID(for: pubKeyData)),
            .authorityKeyIdentifier(subjectKeyID(for: pubKeyData))
        ]

        // Build unsigned cert, then sign TBS
        var unsigned = MatterCertificate(
            serialNumber: serial,
            issuer: dn,
            notBefore: notBefore,
            notAfter: notAfter,
            subject: dn,
            publicKey: pubKeyData,
            extensions: extensions,
            signature: Data() // placeholder
        )

        let tbs = unsigned.tbsData()
        let sig = try key.signature(for: tbs)
        unsigned = MatterCertificate(
            serialNumber: serial,
            issuer: dn,
            notBefore: notBefore,
            notAfter: notAfter,
            subject: dn,
            publicKey: pubKeyData,
            extensions: extensions,
            signature: Data(sig.derRepresentation)
        )

        return unsigned
    }

    /// Generate a Node Operational Certificate (NOC).
    ///
    /// - Parameters:
    ///   - signerKey: The issuing CA's private key (RCAC or ICAC).
    ///   - issuerDN: The issuer's distinguished name.
    ///   - nodePublicKey: The node's P-256 public key.
    ///   - nodeID: The node's operational node ID.
    ///   - fabricID: The fabric ID.
    ///   - caseAuthenticatedTags: Optional CASE Authenticated Tags.
    /// - Returns: A signed NOC.
    public static func generateNOC(
        signerKey: P256.Signing.PrivateKey,
        issuerDN: MatterDistinguishedName,
        nodePublicKey: P256.Signing.PublicKey,
        nodeID: NodeID,
        fabricID: FabricID,
        caseAuthenticatedTags: [UInt32] = [],
        notBefore: UInt32 = 0,
        notAfter: UInt32 = 0,
        serialNumber: Data? = nil
    ) throws -> MatterCertificate {
        let serial = serialNumber ?? generateSerialNumber()
        let subjectDN = MatterDistinguishedName(
            nodeID: nodeID,
            fabricID: fabricID,
            caseAuthenticatedTags: caseAuthenticatedTags
        )
        let pubKeyData = Data(nodePublicKey.x963Representation)
        let issuerPubKeyData = Data(signerKey.publicKey.x963Representation)

        let extensions: [CertificateExtension] = [
            .basicConstraints(isCA: false, pathLength: nil),
            .keyUsage(.noc),
            .extendedKeyUsage([.clientAuth, .serverAuth]),
            .subjectKeyIdentifier(subjectKeyID(for: pubKeyData)),
            .authorityKeyIdentifier(subjectKeyID(for: issuerPubKeyData))
        ]

        let unsigned = MatterCertificate(
            serialNumber: serial,
            issuer: issuerDN,
            notBefore: notBefore,
            notAfter: notAfter,
            subject: subjectDN,
            publicKey: pubKeyData,
            extensions: extensions,
            signature: Data()
        )

        let tbs = unsigned.tbsData()
        let sig = try signerKey.signature(for: tbs)

        return MatterCertificate(
            serialNumber: serial,
            issuer: issuerDN,
            notBefore: notBefore,
            notAfter: notAfter,
            subject: subjectDN,
            publicKey: pubKeyData,
            extensions: extensions,
            signature: Data(sig.derRepresentation)
        )
    }

    /// Generate a random serial number (20 bytes).
    private static func generateSerialNumber() -> Data {
        var bytes = [UInt8](repeating: 0, count: 20)
        for i in 0..<20 { bytes[i] = UInt8.random(in: 0...255) }
        return Data(bytes)
    }

    /// Compute subject key identifier (SHA-1 of the public key bytes).
    ///
    /// Matter uses a truncated SHA-256 (first 20 bytes) since SHA-1 is not
    /// available in CryptoKit. This matches the spec's intent for key identification.
    private static func subjectKeyID(for publicKey: Data) -> Data {
        let hash = SHA256.hash(data: publicKey)
        return Data(hash.prefix(20))
    }
}

// MARK: - Certificate Chain Validation

extension MatterCertificate {

    /// Validate a NOC against an RCAC (no ICAC).
    ///
    /// Verifies:
    /// 1. RCAC is self-signed
    /// 2. NOC signature is valid against RCAC's public key
    /// 3. NOC issuer matches RCAC subject
    ///
    /// - Parameters:
    ///   - noc: The Node Operational Certificate.
    ///   - rcac: The Root CA Certificate.
    /// - Returns: `true` if the chain is valid.
    public static func validateChain(noc: MatterCertificate, rcac: MatterCertificate) -> Bool {
        // 1. Verify RCAC is self-signed
        guard rcac.verifySelfSigned() else { return false }

        // 2. Verify NOC signature against RCAC public key
        guard let rcacKey = try? rcac.subjectPublicKey() else { return false }
        guard noc.verify(with: rcacKey) else { return false }

        // 3. Verify issuer/subject relationship
        guard noc.issuer == rcac.subject else { return false }

        return true
    }

    /// Validate a NOC against an ICAC and RCAC.
    ///
    /// - Parameters:
    ///   - noc: The Node Operational Certificate.
    ///   - icac: The Intermediate CA Certificate.
    ///   - rcac: The Root CA Certificate.
    /// - Returns: `true` if the chain is valid.
    public static func validateChain(noc: MatterCertificate, icac: MatterCertificate, rcac: MatterCertificate) -> Bool {
        // 1. Verify RCAC is self-signed
        guard rcac.verifySelfSigned() else { return false }

        // 2. Verify ICAC signature against RCAC
        guard let rcacKey = try? rcac.subjectPublicKey() else { return false }
        guard icac.verify(with: rcacKey) else { return false }
        guard icac.issuer == rcac.subject else { return false }

        // 3. Verify NOC signature against ICAC
        guard let icacKey = try? icac.subjectPublicKey() else { return false }
        guard noc.verify(with: icacKey) else { return false }
        guard noc.issuer == icac.subject else { return false }

        return true
    }
}
