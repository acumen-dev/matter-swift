// CertificationDeclaration.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import MatterTypes
import SwiftASN1

// MARK: - CDVerification

/// The outcome of ``CertificationDeclaration/verifySignature(cmsDER:keys:)``.
public enum CDVerification: Sendable, Equatable {
    case valid
    /// No key in the list has the signer's subject key identifier.
    case unknownSigningKey
    /// The signer's key is known but the signature does not verify.
    case invalidSignature
}

// MARK: - CertificationDeclarationError

/// Why a Certification Declaration could not be parsed.
public enum CertificationDeclarationError: Error, Sendable, Equatable, CustomStringConvertible {
    /// The CMS SignedData envelope is not the shape Matter uses.
    case malformedEnvelope(String)
    /// The TLV payload is not a well-formed Certification Declaration.
    case malformedContent(String)

    public var description: String {
        switch self {
        case .malformedEnvelope(let detail): "malformed CMS envelope: \(detail)"
        case .malformedContent(let detail): "malformed CD content: \(detail)"
        }
    }
}

// MARK: - CertificationDeclaration

/// A Matter Certification Declaration: a TLV payload in a CMS SignedData envelope.
///
/// The envelope is parsed exactly as connectedhomeip v1.4.0.0 `CMS_Sign` writes it
/// (src/credentials/CertificationDeclaration.cpp), and any other shape is rejected:
///
/// ```
/// ContentInfo ::= SEQUENCE { id-signedData, [0] EXPLICIT SignedData }
/// SignedData ::= SEQUENCE {
///   version INTEGER (3),
///   digestAlgorithms SET { sha256 },
///   encapContentInfo SEQUENCE { pkcs7-data (1.2.840.113549.1.7.1), [0] EXPLICIT OCTET STRING },
///   signerInfos SET { SignerInfo } }               -- no certificates, no CRLs
/// SignerInfo ::= SEQUENCE {
///   version INTEGER (3), sid [0] IMPLICIT SubjectKeyIdentifier,
///   digestAlgorithm sha256, signatureAlgorithm ecdsa-with-SHA256,
///   signature OCTET STRING (DER Ecdsa-Sig-Value) } -- no signed or unsigned attributes
/// ```
///
/// With no signed attributes the signature covers the eContent octets. Algorithm identifiers
/// may carry absent or NULL parameters. Upstream reads the same fields but tolerates trailing
/// elements inside each sequence; this parser does not.
///
/// The payload is decoded as upstream `DecodeCertificationElements` (the
/// `CertificationElementsWithoutPIDs` form the verifier uses): an anonymous structure of
/// context tags 0 to 8 in order, each an unsigned integer of its field's width (tag 4 a UTF-8
/// string of exactly 19 bytes), then optionally tags 9 and 10 together, then optionally tag 11
/// (an array of 20-byte key identifiers); anything after that is skipped. Unlike upstream, a
/// product ID above 0xFFFF is malformed rather than unmatched, and the TLV reader accepts a
/// container that ends at the end of the data without an end-of-container marker.
public struct CertificationDeclaration: Sendable, Equatable {

    public let formatVersion: UInt8
    public let vendorID: UInt16
    public let productIDs: [UInt16]
    public let deviceTypeID: UInt32
    public let certificateID: String
    public let securityLevel: UInt8
    public let securityInformation: UInt16
    public let versionNumber: UInt16
    public let certificationType: UInt8
    /// `dac_origin_vendor_id`; present exactly when ``dacOriginProductID`` is.
    public let dacOriginVendorID: UInt16?
    /// `dac_origin_product_id`; present exactly when ``dacOriginVendorID`` is.
    public let dacOriginProductID: UInt16?
    /// `authorized_paa_list`: PAA subject key identifiers. `nil` when absent; an empty list is
    /// present and authorises no PAA.
    public let authorizedPAAs: [Data]?
    /// The SubjectKeyIdentifier naming the signer's certificate.
    public let signerKeyIdentifier: Data

    /// Parses the CMS SignedData envelope and the TLV payload; does not verify.
    public init(cmsDER: Data) throws {
        let envelope = try Envelope(cmsDER)
        let content = try Self.decodeContent(envelope.content)
        self.formatVersion = content.formatVersion
        self.vendorID = content.vendorID
        self.productIDs = content.productIDs
        self.deviceTypeID = content.deviceTypeID
        self.certificateID = content.certificateID
        self.securityLevel = content.securityLevel
        self.securityInformation = content.securityInformation
        self.versionNumber = content.versionNumber
        self.certificationType = content.certificationType
        self.dacOriginVendorID = content.dacOriginVendorID
        self.dacOriginProductID = content.dacOriginProductID
        self.authorizedPAAs = content.authorizedPAAs
        self.signerKeyIdentifier = envelope.signerKeyIdentifier
    }

    /// Verifies the CMS signature with the trusted key matching `signerKeyIdentifier`.
    ///
    /// `cmsDER` must be the bytes this value was parsed from; bytes that no longer parse, or
    /// that name another signer, give `.invalidSignature`.
    public func verifySignature(cmsDER: Data, keys: [CDSigningKey]) -> CDVerification {
        let candidates = keys.filter { $0.keyIdentifier == signerKeyIdentifier }
        guard !candidates.isEmpty else { return .unknownSigningKey }
        guard let envelope = try? Envelope(cmsDER),
              envelope.signerKeyIdentifier == signerKeyIdentifier
        else { return .invalidSignature }
        let verified = candidates.contains { $0.publicKey.isValidSignature(envelope.signature, for: envelope.content) }
        return verified ? .valid : .invalidSignature
    }
}

// MARK: - Envelope

extension CertificationDeclaration {

    static let signedDataOID: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 7, 2]
    static let pkcs7DataOID: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 7, 1]
    static let sha256OID: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 2, 1]
    static let ecdsaWithSHA256OID: ASN1ObjectIdentifier = [1, 2, 840, 10045, 4, 3, 2]

    private static let contextZero = ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)

    /// The parts of the CMS SignedData a Matter CD carries.
    struct Envelope {
        let content: Data
        let signerKeyIdentifier: Data
        let signature: P256.Signing.ECDSASignature

        init(_ der: Data) throws {
            let root: ASN1Node
            do {
                root = try DER.parse(Array(der))
            } catch {
                throw CertificationDeclarationError.malformedEnvelope("not DER")
            }
            // ContentInfo
            let contentInfo = try Self.children(root, .sequence, count: 2, "ContentInfo")
            try Self.expectOID(contentInfo[0], signedDataOID, "contentType is not id-signedData")
            let explicit = try Self.children(contentInfo[1], contextZero, count: 1, "ContentInfo content")

            // SignedData
            let signedData = try Self.children(explicit[0], .sequence, count: 4, "SignedData")
            try Self.expectVersion3(signedData[0], "SignedData")
            let digestAlgorithms = try Self.children(signedData[1], .set, count: 1, "digestAlgorithms")
            try Self.expectAlgorithm(digestAlgorithms[0], sha256OID, "digestAlgorithms is not {sha256}")

            // EncapsulatedContentInfo
            let encapsulated = try Self.children(signedData[2], .sequence, count: 2, "encapContentInfo")
            try Self.expectOID(encapsulated[0], pkcs7DataOID, "eContentType is not pkcs7-data")
            let eContent = try Self.children(encapsulated[1], contextZero, count: 1, "eContent")
            let content = try Self.octets(eContent[0], .octetString, "eContent")

            // SignerInfo
            let signerInfos = try Self.children(signedData[3], .set, count: 1, "signerInfos")
            let signerInfo = try Self.children(signerInfos[0], .sequence, count: 5, "SignerInfo")
            try Self.expectVersion3(signerInfo[0], "SignerInfo")
            let keyIdentifier = try Self.octets(signerInfo[1], contextZero, "sid is not a subjectKeyIdentifier")
            try Self.expectAlgorithm(signerInfo[2], sha256OID, "SignerInfo digestAlgorithm is not sha256")
            try Self.expectAlgorithm(signerInfo[3], ecdsaWithSHA256OID, "signatureAlgorithm is not ecdsa-with-SHA256")
            let signatureDER = try Self.octets(signerInfo[4], .octetString, "signature")
            guard let signature = try? P256.Signing.ECDSASignature(derRepresentation: signatureDER) else {
                throw CertificationDeclarationError.malformedEnvelope("signature is not a DER ECDSA signature")
            }

            self.content = content
            self.signerKeyIdentifier = keyIdentifier
            self.signature = signature
        }

        // MARK: Helpers

        private static func children(
            _ node: ASN1Node, _ identifier: ASN1Identifier, count: Int, _ what: String
        ) throws -> [ASN1Node] {
            guard node.identifier == identifier, case .constructed(let collection) = node.content else {
                throw CertificationDeclarationError.malformedEnvelope("\(what) has the wrong type")
            }
            let nodes = Array(collection)
            guard nodes.count == count else {
                throw CertificationDeclarationError.malformedEnvelope("\(what) has \(nodes.count) elements, expected \(count)")
            }
            return nodes
        }

        private static func octets(_ node: ASN1Node, _ identifier: ASN1Identifier, _ what: String) throws -> Data {
            guard node.identifier == identifier, case .primitive(let bytes) = node.content else {
                throw CertificationDeclarationError.malformedEnvelope("\(what) is not an octet string")
            }
            return Data(bytes)
        }

        private static func expectOID(_ node: ASN1Node, _ expected: ASN1ObjectIdentifier, _ failure: String) throws {
            guard (try? ASN1ObjectIdentifier(derEncoded: node)) == expected else {
                throw CertificationDeclarationError.malformedEnvelope(failure)
            }
        }

        private static func expectVersion3(_ node: ASN1Node, _ what: String) throws {
            guard (try? Int(derEncoded: node)) == 3 else {
                throw CertificationDeclarationError.malformedEnvelope("\(what) version is not 3")
            }
        }

        /// AlgorithmIdentifier ::= SEQUENCE { algorithm, parameters ANY OPTIONAL }, accepting
        /// absent or NULL parameters.
        private static func expectAlgorithm(
            _ node: ASN1Node, _ expected: ASN1ObjectIdentifier, _ failure: String
        ) throws {
            guard node.identifier == .sequence, case .constructed(let collection) = node.content else {
                throw CertificationDeclarationError.malformedEnvelope(failure)
            }
            let nodes = Array(collection)
            guard let first = nodes.first, nodes.count <= 2 else {
                throw CertificationDeclarationError.malformedEnvelope(failure)
            }
            try Self.expectOID(first, expected, failure)
            if nodes.count == 2 {
                guard (try? ASN1Null(derEncoded: nodes[1])) != nil else {
                    throw CertificationDeclarationError.malformedEnvelope(failure)
                }
            }
        }
    }
}

// MARK: - Content

extension CertificationDeclaration {

    /// connectedhomeip `kCertificateIdLength`.
    static let certificateIDLength = 19

    /// connectedhomeip `kKeyIdentifierLength`.
    static let keyIdentifierLength = 20

    /// connectedhomeip `kMaxCMSSignedCDMessage` (183 + `kCertificationElements_TLVEncodedMaxLength`
    /// 607), the bound `DecodeCertificationElements` puts on the TLV payload.
    static let maxContentLength = 790

    private struct Content {
        var formatVersion: UInt8 = 0
        var vendorID: UInt16 = 0
        var productIDs: [UInt16] = []
        var deviceTypeID: UInt32 = 0
        var certificateID = ""
        var securityLevel: UInt8 = 0
        var securityInformation: UInt16 = 0
        var versionNumber: UInt16 = 0
        var certificationType: UInt8 = 0
        var dacOriginVendorID: UInt16?
        var dacOriginProductID: UInt16?
        var authorizedPAAs: [Data]?
    }

    private static func malformed(_ detail: String) -> CertificationDeclarationError {
        .malformedContent(detail)
    }

    private static func decodeContent(_ data: Data) throws -> Content {
        guard data.count <= maxContentLength else {
            throw malformed("payload is \(data.count) bytes, more than \(maxContentLength)")
        }
        var decoder = TLVDecoder(data: data)
        let top: (tag: TLVTag, element: TLVElement)?
        let trailing: (tag: TLVTag, element: TLVElement)?
        do {
            top = try decoder.decodeElement()
            trailing = try decoder.decodeElement()
        } catch {
            throw malformed("not TLV")
        }
        guard let top, top.tag == .anonymous, case .structure(let fields) = top.element else {
            throw malformed("not an anonymous structure")
        }
        guard trailing == nil else { throw malformed("data follows the structure") }

        var content = Content()
        var index = 0

        /// The next field, which must have context tag `tag`.
        func next(_ tag: UInt8, _ what: String) throws -> TLVElement {
            guard index < fields.count, fields[index].tag == .contextSpecific(tag) else {
                throw malformed("\(what) (tag \(tag)) is missing or out of order")
            }
            index += 1
            return fields[index - 1].value
        }

        func unsigned<T: FixedWidthInteger & UnsignedInteger>(_ element: TLVElement, _: T.Type, _ what: String) throws -> T {
            guard case .unsignedInt(let value) = element, let narrowed = T(exactly: value) else {
                throw malformed("\(what) is not an unsigned integer that fits \(T.bitWidth) bits")
            }
            return narrowed
        }

        content.formatVersion = try unsigned(next(0, "format_version"), UInt8.self, "format_version")
        content.vendorID = try unsigned(next(1, "vendor_id"), UInt16.self, "vendor_id")
        guard case .array(let products) = try next(2, "product_id_array") else {
            throw malformed("product_id_array is not an array")
        }
        content.productIDs = try products.map { try unsigned($0, UInt16.self, "a product ID") }
        content.deviceTypeID = try unsigned(next(3, "device_type_id"), UInt32.self, "device_type_id")
        guard case .utf8String(let certificateID) = try next(4, "certificate_id"),
              certificateID.utf8.count == certificateIDLength,
              !certificateID.utf8.contains(0)
        else {
            throw malformed("certificate_id is not a UTF-8 string of \(certificateIDLength) bytes")
        }
        content.certificateID = certificateID
        content.securityLevel = try unsigned(next(5, "security_level"), UInt8.self, "security_level")
        content.securityInformation = try unsigned(next(6, "security_information"), UInt16.self, "security_information")
        content.versionNumber = try unsigned(next(7, "version_number"), UInt16.self, "version_number")
        content.certificationType = try unsigned(next(8, "certification_type"), UInt8.self, "certification_type")

        // Optional fields, as upstream: tag 9 brings tag 10 with it; a tag 10 on its own is an error.
        if index < fields.count, fields[index].tag == .contextSpecific(9) {
            content.dacOriginVendorID = try unsigned(next(9, "dac_origin_vendor_id"), UInt16.self, "dac_origin_vendor_id")
            content.dacOriginProductID = try unsigned(next(10, "dac_origin_product_id"), UInt16.self, "dac_origin_product_id")
        }
        if index < fields.count, fields[index].tag == .contextSpecific(10) {
            throw malformed("dac_origin_product_id without dac_origin_vendor_id")
        }
        if index < fields.count, fields[index].tag == .contextSpecific(11) {
            guard case .array(let entries) = fields[index].value else {
                throw malformed("authorized_paa_list is not an array")
            }
            content.authorizedPAAs = try entries.map { entry in
                guard case .octetString(let keyID) = entry, keyID.count == keyIdentifierLength else {
                    throw malformed("an authorized_paa_list entry is not a \(keyIdentifierLength)-byte string")
                }
                return keyID
            }
            index += 1
        }
        // Upstream skips whatever follows.
        return content
    }
}
