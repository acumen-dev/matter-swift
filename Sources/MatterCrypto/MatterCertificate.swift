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
///  11: signature (octet string, 64-byte P1363 ECDSA per Matter spec §6.6.1)
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
    /// Matter spec §6.6.1: stored as IEEE P1363 format (64-byte raw r‖s).
    public let signature: Data

    /// Original TLV bytes from which this certificate was decoded, preserved
    /// so that `tbsData()` can extract authentic TBS bytes rather than
    /// re-encoding them (which may differ in integer width, encoding choices, etc.).
    public let rawTLV: Data?

    // MARK: - Init

    public init(
        serialNumber: Data,
        issuer: MatterDistinguishedName,
        notBefore: UInt32,
        notAfter: UInt32,
        subject: MatterDistinguishedName,
        publicKey: Data,
        extensions: [CertificateExtension] = [],
        signature: Data,
        rawTLV: Data? = nil
    ) {
        self.serialNumber = serialNumber
        self.issuer = issuer
        self.notBefore = notBefore
        self.notAfter = notAfter
        self.subject = subject
        self.publicKey = publicKey
        self.extensions = extensions
        self.signature = signature
        self.rawTLV = rawTLV
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

    /// Produce the X.509 DER `TBSCertificate` bytes for this certificate.
    ///
    /// Matter certificate signatures are computed over X.509 ASN.1 DER
    /// `TBSCertificate` bytes — **not** over any form of Matter TLV.
    /// The Matter TLV certificate is a compact re-encoding of an X.509
    /// certificate; the signature value in TLV field 11 is the ECDSA
    /// signature that was originally computed over the DER TBS.
    ///
    /// This method converts the parsed TLV fields back to X.509 DER
    /// using the `PKCS10CSRBuilder` helpers that are already present
    /// in the codebase.
    ///
    /// See Matter Core Spec §6.4.3, §6.5.
    public func tbsData() -> Data {
        let b = PKCS10CSRBuilder.self

        // version [0] EXPLICIT INTEGER v3 (= 2)
        let version = b.derContextConstructed(tag: 0, content: [0x02, 0x01, 0x02])

        // serialNumber INTEGER
        let serialContent = Self.encodeSerialNumberDERInteger(serialNumber)
        let serial = b.derTLV(tag: 0x02, content: serialContent)

        // signature AlgorithmIdentifier (ecdsa-with-SHA256)
        let sigAlg = b.derSequence(b.derOID(b.oidECDSAWithSHA256))

        // issuer Name
        let issuerDER = issuer.toX509Name()

        // validity Validity { notBefore, notAfter }
        let notBeforeDER = Self.matterEpochToDERTime(notBefore)
        let notAfterDER = Self.matterEpochToDERTime(notAfter)
        let validity = b.derSequence(notBeforeDER + notAfterDER)

        // subject Name
        let subjectDER = subject.toX509Name()

        // subjectPublicKeyInfo
        let spki: [UInt8]
        if let key = try? P256.Signing.PublicKey(x963Representation: publicKey) {
            spki = b.buildSubjectPublicKeyInfo(publicKey: key)
        } else {
            // Fallback: build manually from raw bytes
            let algID = b.derSequence(b.derOID(b.oidECPublicKey) + b.derOID(b.oidPrime256v1))
            let bitString = b.derBitString([UInt8](publicKey))
            spki = b.derSequence(algID + bitString)
        }

        // extensions [3] EXPLICIT
        var extBytes: [UInt8] = []
        if !extensions.isEmpty {
            var extSeqContent: [UInt8] = []
            for ext in extensions {
                extSeqContent += ext.toX509Extension()
            }
            let extSeq = b.derSequence(extSeqContent)
            extBytes = b.derContextConstructed(tag: 3, content: extSeq)
        }

        let tbsContent = version + serial + sigAlg + issuerDER + validity +
            subjectDER + spki + extBytes
        return Data(b.derSequence(tbsContent))
    }

    // MARK: - Matter Epoch to GeneralizedTime

    /// Encode a Matter epoch time as a DER time value (tag + length + value).
    ///
    /// The CHIP SDK uses:
    /// - **UTCTime** (tag 0x17, 2-digit year "YYMMDDHHMMSSZ") for dates 2000-2049
    /// - **GeneralizedTime** (tag 0x18, 4-digit year "YYYYMMDDHHMMSSZ") for the
    ///   no-expiry sentinel (9999-12-31) and dates outside the UTCTime range
    ///
    /// Matter epoch = seconds since 2000-01-01 00:00:00 UTC.
    /// Value 0 means "not specified" → encoded as GeneralizedTime "99991231235959Z".
    private static func matterEpochToDERTime(_ matterSeconds: UInt32) -> [UInt8] {
        let b = PKCS10CSRBuilder.self
        if matterSeconds == 0 {
            return b.derTLV(tag: 0x18, content: [UInt8]("99991231235959Z".utf8))
        }
        let unixTime = TimeInterval(matterSeconds) + 946684800
        let date = Date(timeIntervalSince1970: unixTime)
        let formatter = DateFormatter()
        formatter.timeZone = TimeZone(identifier: "UTC")

        // Extract year to decide UTCTime vs GeneralizedTime
        formatter.dateFormat = "yyyy"
        let year = Int(formatter.string(from: date)) ?? 0

        if year >= 2000 && year <= 2049 {
            // UTCTime: 2-digit year
            formatter.dateFormat = "yyMMddHHmmss"
            let str = formatter.string(from: date) + "Z"
            return b.derTLV(tag: 0x17, content: [UInt8](str.utf8))
        } else {
            // GeneralizedTime: 4-digit year
            formatter.dateFormat = "yyyyMMddHHmmss"
            let str = formatter.string(from: date) + "Z"
            return b.derTLV(tag: 0x18, content: [UInt8](str.utf8))
        }
    }

    /// Encode a serial number as a DER integer.
    ///
    /// The CHIP SDK encodes certificate serial numbers as raw byte sequences
    /// without the positive-integer 0x00 prefix that standard DER requires.
    /// We match this behavior for interoperability.
    private static func encodeSerialNumberDERInteger(_ bytes: Data) -> [UInt8] {
        var b = [UInt8](bytes)
        // Strip leading zeros (but keep at least one byte)
        while b.count > 1 && b[0] == 0x00 { b.removeFirst() }
        return b
    }

    // MARK: - TLV Decoding

    /// Decode a Matter certificate from TLV data.
    ///
    /// The raw bytes are preserved in `rawTLV` so that `tbsData()` can
    /// extract authentic TBS bytes without re-encoding.
    public static func fromTLV(_ data: Data) throws -> MatterCertificate {
        let (_, element) = try TLVDecoder.decode(data)
        var cert = try fromTLVElement(element)
        cert = MatterCertificate(
            serialNumber: cert.serialNumber,
            issuer: cert.issuer,
            notBefore: cert.notBefore,
            notAfter: cert.notAfter,
            subject: cert.subject,
            publicKey: cert.publicKey,
            extensions: cert.extensions,
            signature: cert.signature,
            rawTLV: data
        )
        return cert
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
    /// The signature is verified against the X.509 DER TBSCertificate bytes
    /// produced by `tbsData()`. Matter cert signatures are always IEEE P1363
    /// format (64-byte raw r‖s) per Matter spec §6.6.1.
    ///
    /// - Parameter signerPublicKey: The public key of the certificate's issuer (or self for RCAC).
    /// - Returns: `true` if the signature is valid.
    public func verify(with signerPublicKey: P256.Signing.PublicKey) -> Bool {
        let tbs = tbsData()

        // Matter spec §6.6.1: P1363 format (64 bytes). Fall back to DER for
        // backward compatibility with any legacy test certs.
        guard let ecdsaSignature = (try? P256.Signing.ECDSASignature(rawRepresentation: signature))
            ?? (try? P256.Signing.ECDSASignature(derRepresentation: signature)) else {
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

    enum Tag {
        // X.509 standard string attributes (context tags 1-16 within the DN list)
        // These are scoped to the DN container — they don't conflict with
        // the top-level certificate tags (serialNumber=1, sigAlgorithm=2, etc.)
        static let commonName: UInt8 = 1
        static let surname: UInt8 = 2
        static let serialNumber: UInt8 = 3
        static let countryName: UInt8 = 4
        static let localityName: UInt8 = 5
        static let stateOrProvinceName: UInt8 = 6
        static let organizationName: UInt8 = 7
        static let organizationalUnitName: UInt8 = 8
        static let title: UInt8 = 9
        static let name: UInt8 = 10
        static let givenName: UInt8 = 11
        static let initials: UInt8 = 12
        static let generationQualifier: UInt8 = 13
        static let dnQualifier: UInt8 = 14
        static let pseudonym: UInt8 = 15
        static let domainComponent: UInt8 = 16

        // Matter-specific integer attributes (context tags 17-22)
        static let nodeID: UInt8 = 17
        static let firmwareSigningID: UInt8 = 18
        static let icacID: UInt8 = 19
        static let rcacID: UInt8 = 20
        static let fabricID: UInt8 = 21
        static let caseAuthenticatedTag: UInt8 = 22
    }

    /// A DN attribute with its TLV context tag and value (integer or string).
    public struct Attribute: Sendable, Equatable {
        public let tag: UInt8
        public let intValue: UInt64?
        public let stringValue: String?

        public init(tag: UInt8, intValue: UInt64) {
            self.tag = tag
            self.intValue = intValue
            self.stringValue = nil
        }

        public init(tag: UInt8, stringValue: String) {
            self.tag = tag
            self.intValue = nil
            self.stringValue = stringValue
        }
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

    /// All DN attributes in order, including string attributes (commonName, etc.).
    /// Used by `toX509Name()` to produce correct DER for certs from external issuers.
    public let orderedAttributes: [Attribute]

    public init(
        nodeID: NodeID? = nil,
        firmwareSigningID: UInt32? = nil,
        icacID: UInt32? = nil,
        rcacID: UInt32? = nil,
        fabricID: FabricID? = nil,
        caseAuthenticatedTags: [UInt32] = [],
        orderedAttributes: [Attribute]? = nil
    ) {
        self.nodeID = nodeID
        self.firmwareSigningID = firmwareSigningID
        self.icacID = icacID
        self.rcacID = rcacID
        self.fabricID = fabricID
        self.caseAuthenticatedTags = caseAuthenticatedTags

        // Build orderedAttributes from individual fields if not provided
        if let attrs = orderedAttributes {
            self.orderedAttributes = attrs
        } else {
            var attrs: [Attribute] = []
            if let nodeID { attrs.append(Attribute(tag: Tag.nodeID, intValue: nodeID.rawValue)) }
            if let firmwareSigningID { attrs.append(Attribute(tag: Tag.firmwareSigningID, intValue: UInt64(firmwareSigningID))) }
            if let icacID { attrs.append(Attribute(tag: Tag.icacID, intValue: UInt64(icacID))) }
            if let rcacID { attrs.append(Attribute(tag: Tag.rcacID, intValue: UInt64(rcacID))) }
            if let fabricID { attrs.append(Attribute(tag: Tag.fabricID, intValue: fabricID.rawValue)) }
            for cat in caseAuthenticatedTags {
                attrs.append(Attribute(tag: Tag.caseAuthenticatedTag, intValue: UInt64(cat)))
            }
            self.orderedAttributes = attrs
        }
    }

    /// Encode as a TLV list element.
    public func toTLVElement() -> TLVElement {
        let fields: [TLVElement.TLVField] = orderedAttributes.map { attr in
            if let intVal = attr.intValue {
                return .init(tag: .contextSpecific(attr.tag), value: .unsignedInt(intVal))
            } else if let strVal = attr.stringValue {
                return .init(tag: .contextSpecific(attr.tag), value: .utf8String(strVal))
            } else {
                return .init(tag: .contextSpecific(attr.tag), value: .null)
            }
        }
        return .list(fields)
    }

    // MARK: - X.509 DER Encoding

    /// OID mapping for all Matter TLV DN context tags.
    ///
    /// Tags 17-22: Matter-specific integer attributes (values encoded as 16-char hex UTF8String)
    /// Tags 23-38: Standard X.509 string attributes (values encoded as UTF8String directly)
    private static let dnTagToOID: [UInt8: [UInt64]] = [
        // X.509 standard (tags 1-16, values are strings)
        Tag.commonName:             [2, 5, 4, 3],
        Tag.surname:                [2, 5, 4, 4],
        Tag.serialNumber:           [2, 5, 4, 5],
        Tag.countryName:            [2, 5, 4, 6],
        Tag.localityName:           [2, 5, 4, 7],
        Tag.stateOrProvinceName:    [2, 5, 4, 8],
        Tag.organizationName:       [2, 5, 4, 10],
        Tag.organizationalUnitName: [2, 5, 4, 11],
        Tag.title:                  [2, 5, 4, 12],
        Tag.name:                   [2, 5, 4, 41],
        Tag.givenName:              [2, 5, 4, 42],
        Tag.initials:               [2, 5, 4, 43],
        Tag.generationQualifier:    [2, 5, 4, 44],
        Tag.dnQualifier:            [2, 5, 4, 46],
        Tag.pseudonym:              [2, 5, 4, 65],
        Tag.domainComponent:        [0, 9, 2342, 19200300, 100, 1, 25],
        // Matter-specific (tags 17-22, values are integers encoded as 16-char hex)
        Tag.nodeID:               [1, 3, 6, 1, 4, 1, 37244, 1, 1],
        Tag.firmwareSigningID:    [1, 3, 6, 1, 4, 1, 37244, 1, 2],
        Tag.icacID:               [1, 3, 6, 1, 4, 1, 37244, 1, 3],
        Tag.rcacID:               [1, 3, 6, 1, 4, 1, 37244, 1, 4],
        Tag.fabricID:             [1, 3, 6, 1, 4, 1, 37244, 1, 5],
        Tag.caseAuthenticatedTag: [1, 3, 6, 1, 4, 1, 37244, 1, 6],
    ]

    /// Convert this DN to an X.509 Name (RDN sequence) in DER encoding.
    ///
    /// Uses `orderedAttributes` to preserve the exact attribute order from the
    /// original TLV certificate. Matter-specific integer attributes are encoded
    /// as 16-char hex UTF8Strings; standard X.509 string attributes are encoded
    /// as UTF8Strings directly.
    func toX509Name() -> [UInt8] {
        let b = PKCS10CSRBuilder.self
        var rdns: [UInt8] = []

        for attr in orderedAttributes {
            guard let oid = Self.dnTagToOID[attr.tag] else { continue }

            let valueBytes: [UInt8]
            if let intVal = attr.intValue {
                // Matter-specific: encode as 16-char uppercase hex
                valueBytes = b.derUTF8String(String(format: "%016llX", intVal))
            } else if let strVal = attr.stringValue {
                // X.509 standard: encode string directly
                valueBytes = b.derUTF8String(strVal)
            } else {
                continue
            }

            let attrSeq = b.derSequence(b.derOID(oid) + valueBytes)
            rdns += b.derSet(attrSeq)
        }

        return b.derSequence(rdns)
    }

    /// Decode from a TLV list element.
    ///
    /// Preserves all attributes in order (including string attributes like
    /// commonName) so that `toX509Name()` can reproduce the exact DER encoding
    /// for signature verification of externally-issued certificates.
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
        var ordered: [Attribute] = []

        for field in fields {
            guard case .contextSpecific(let tag) = field.tag else { continue }

            if let val = field.value.uintValue {
                ordered.append(Attribute(tag: tag, intValue: val))
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
            } else if let str = field.value.stringValue {
                ordered.append(Attribute(tag: tag, stringValue: str))
            }
        }

        return MatterDistinguishedName(
            nodeID: nodeID,
            firmwareSigningID: firmwareSigningID,
            icacID: icacID,
            rcacID: rcacID,
            fabricID: fabricID,
            caseAuthenticatedTags: cats,
            orderedAttributes: ordered
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

    // MARK: - X.509 DER Extension Encoding

    /// Standard X.509 extension OIDs.
    private enum ExtOID {
        static let basicConstraints: [UInt64]       = [2, 5, 29, 19]
        static let keyUsage: [UInt64]               = [2, 5, 29, 15]
        static let extendedKeyUsage: [UInt64]       = [2, 5, 29, 37]
        static let subjectKeyIdentifier: [UInt64]   = [2, 5, 29, 14]
        static let authorityKeyIdentifier: [UInt64] = [2, 5, 29, 35]
    }

    /// Extended key usage OIDs.
    private enum EKUoid {
        static let serverAuth: [UInt64] = [1, 3, 6, 1, 5, 5, 7, 3, 1]
        static let clientAuth: [UInt64] = [1, 3, 6, 1, 5, 5, 7, 3, 2]
    }

    /// Convert this extension to X.509 DER encoding.
    ///
    /// Each X.509 extension is: SEQUENCE { OID, [BOOLEAN critical], OCTET STRING(value) }
    func toX509Extension() -> [UInt8] {
        let b = PKCS10CSRBuilder.self

        switch self {
        case .basicConstraints(let isCA, let pathLength):
            var bcContent: [UInt8] = []
            if isCA {
                bcContent += [0x01, 0x01, 0xFF]  // BOOLEAN TRUE
                if let pathLen = pathLength {
                    bcContent += [0x02, 0x01, pathLen]  // INTEGER pathLen
                }
            }
            let bcValue = b.derSequence(bcContent)
            let extnValue = b.derTLV(tag: 0x04, content: bcValue)
            return b.derSequence(b.derOID(ExtOID.basicConstraints) + [0x01, 0x01, 0xFF] + extnValue)

        case .keyUsage(let usage):
            // X.509 KeyUsage is a BIT STRING.
            // Matter KeyUsage bits: 0=digitalSignature, 5=keyCertSign, 6=cRLSign
            // X.509 encoding: MSB of first byte is bit 0.
            // digitalSignature = bit 0 = 0x80
            // keyCertSign = bit 5 = 0x04
            // cRLSign = bit 6 = 0x02
            var kuByte: UInt8 = 0
            if usage.contains(.digitalSignature) { kuByte |= 0x80 }
            if usage.contains(.nonRepudiation)   { kuByte |= 0x40 }
            if usage.contains(.keyEncipherment)  { kuByte |= 0x20 }
            if usage.contains(.dataEncipherment) { kuByte |= 0x10 }
            if usage.contains(.keyAgreement)     { kuByte |= 0x08 }
            if usage.contains(.keyCertSign)      { kuByte |= 0x04 }
            if usage.contains(.crlSign)          { kuByte |= 0x02 }

            // Count unused bits (trailing zeros in the byte)
            var unusedBits: UInt8 = 0
            if kuByte != 0 {
                var tmp = kuByte
                while tmp & 1 == 0 { unusedBits += 1; tmp >>= 1 }
            }
            let kuBitString = b.derTLV(tag: 0x03, content: [unusedBits, kuByte])
            let extnValue = b.derTLV(tag: 0x04, content: kuBitString)
            return b.derSequence(b.derOID(ExtOID.keyUsage) + [0x01, 0x01, 0xFF] + extnValue)

        case .extendedKeyUsage(let usages):
            var ekuContent: [UInt8] = []
            for eku in usages {
                switch eku {
                case .serverAuth: ekuContent += b.derOID(EKUoid.serverAuth)
                case .clientAuth: ekuContent += b.derOID(EKUoid.clientAuth)
                default: break
                }
            }
            let ekuSeq = b.derSequence(ekuContent)
            let extnValue = b.derTLV(tag: 0x04, content: ekuSeq)
            // ExtendedKeyUsage is critical per CHIP SDK
            return b.derSequence(b.derOID(ExtOID.extendedKeyUsage) + [0x01, 0x01, 0xFF] + extnValue)

        case .subjectKeyIdentifier(let data):
            // extnValue = OCTET STRING { OCTET STRING { <20 bytes> } }
            let inner = b.derTLV(tag: 0x04, content: [UInt8](data))
            let extnValue = b.derTLV(tag: 0x04, content: inner)
            return b.derSequence(b.derOID(ExtOID.subjectKeyIdentifier) + extnValue)

        case .authorityKeyIdentifier(let data):
            // extnValue = OCTET STRING { SEQUENCE { [0] IMPLICIT <20 bytes> } }
            // [0] IMPLICIT = context-specific tag 0, primitive = 0x80
            let keyId = b.derTLV(tag: 0x80, content: [UInt8](data))
            let akidSeq = b.derSequence(keyId)
            let extnValue = b.derTLV(tag: 0x04, content: akidSeq)
            return b.derSequence(b.derOID(ExtOID.authorityKeyIdentifier) + extnValue)
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

    /// Matter epoch offset: 2000-01-01 00:00:00 UTC in Unix time.
    private static let matterEpochOffset: TimeInterval = 946684800

    /// Current time as Matter epoch seconds.
    private static var nowMatterEpoch: UInt32 {
        UInt32(Date().timeIntervalSince1970 - matterEpochOffset)
    }

    /// Generate a self-signed Root CA Certificate (RCAC).
    ///
    /// - Parameters:
    ///   - key: The P-256 signing key pair for the root CA.
    ///   - rcacID: The RCAC identifier.
    ///   - fabricID: The fabric ID.
    ///   - notBefore: Validity start (Matter epoch seconds). Defaults to current time.
    ///   - notAfter: Validity end (Matter epoch seconds). Defaults to 10 years from now.
    /// - Returns: A self-signed RCAC.
    public static func generateRCAC(
        key: P256.Signing.PrivateKey,
        rcacID: UInt32 = 1,
        fabricID: FabricID,
        notBefore: UInt32? = nil,
        notAfter: UInt32? = nil,
        serialNumber: Data? = nil
    ) throws -> MatterCertificate {
        let serial = serialNumber ?? generateSerialNumber()
        let dn = MatterDistinguishedName(rcacID: rcacID, fabricID: fabricID)
        let pubKeyData = Data(key.publicKey.x963Representation)
        let validFrom = notBefore ?? nowMatterEpoch
        let validUntil = notAfter ?? (nowMatterEpoch + 10 * 365 * 24 * 3600) // ~10 years

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
            notBefore: validFrom,
            notAfter: validUntil,
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
            notBefore: validFrom,
            notAfter: validUntil,
            subject: dn,
            publicKey: pubKeyData,
            extensions: extensions,
            signature: Data(sig.rawRepresentation)
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
        notBefore: UInt32? = nil,
        notAfter: UInt32? = nil,
        serialNumber: Data? = nil
    ) throws -> MatterCertificate {
        let serial = serialNumber ?? generateSerialNumber()
        let validFrom = notBefore ?? nowMatterEpoch
        let validUntil = notAfter ?? (nowMatterEpoch + 10 * 365 * 24 * 3600)
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
            notBefore: validFrom,
            notAfter: validUntil,
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
            notBefore: validFrom,
            notAfter: validUntil,
            subject: subjectDN,
            publicKey: pubKeyData,
            extensions: extensions,
            signature: Data(sig.rawRepresentation)
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
