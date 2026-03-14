// DeviceAttestationCredentials.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import MatterTypes

/// Device Attestation Credentials for a Matter device.
///
/// Holds the Device Attestation Certificate (DAC), DAC private key,
/// Product Attestation Intermediate certificate (PAI), and the
/// Certification Declaration (CD).
///
/// During commissioning, the commissioner sends an AttestationRequest.
/// The device responds with attestation elements (including the CD and nonce),
/// signed by the DAC key, allowing the commissioner to verify the device's
/// authenticity.
///
/// ## Certificate Chain
///
/// ```
/// PAA (Product Attestation Authority — root, owned by CSA)
///  └── PAI (Product Attestation Intermediate — per vendor)
///       └── DAC (Device Attestation Certificate — per device)
/// ```
///
/// For test/development, we generate a self-signed PAI (acting as PAA+PAI),
/// and a DAC signed by the PAI key.
public struct DeviceAttestationCredentials: Sendable {

    /// DER-encoded X.509 Device Attestation Certificate.
    public let dacCertificate: Data

    /// DAC private key (P-256).
    public let dacPrivateKey: P256.Signing.PrivateKey

    /// DER-encoded X.509 Product Attestation Intermediate certificate.
    public let paiCertificate: Data

    /// Certification Declaration (TLV-encoded for test use).
    public let certificationDeclaration: Data

    public init(
        dacCertificate: Data,
        dacPrivateKey: P256.Signing.PrivateKey,
        paiCertificate: Data,
        certificationDeclaration: Data
    ) {
        self.dacCertificate = dacCertificate
        self.dacPrivateKey = dacPrivateKey
        self.paiCertificate = paiCertificate
        self.certificationDeclaration = certificationDeclaration
    }

    // MARK: - Test Credentials Factory

    /// Generate test/development attestation credentials.
    ///
    /// Creates a self-signed PAI certificate and a DAC signed by the PAI key.
    /// The Certification Declaration is a TLV-encoded structure for development use.
    ///
    /// - Warning: These credentials are for development and testing only.
    ///   Production devices must use credentials issued by the CSA.
    ///
    /// - Parameters:
    ///   - vendorID: Matter vendor ID (default 0xFFF1 — test vendor).
    ///   - productID: Matter product ID (default 0x8000 — test product).
    /// - Returns: Test `DeviceAttestationCredentials`.
    public static func testCredentials(
        vendorID: UInt16 = 0xFFF1,
        productID: UInt16 = 0x8000
    ) throws -> DeviceAttestationCredentials {
        // Generate PAI key and self-signed PAI certificate
        let paiKey = P256.Signing.PrivateKey()
        let paiCert = try buildX509Certificate(
            subjectCN: "Matter Test PAI",
            subjectO: "Test",
            issuerCN: "Matter Test PAI",
            issuerO: "Test",
            publicKey: paiKey.publicKey,
            signerKey: paiKey,
            isCA: true,
            serialNumber: generateSerialNumber()
        )

        // Generate DAC key and DAC certificate signed by PAI
        let dacKey = P256.Signing.PrivateKey()
        let dacCert = try buildX509Certificate(
            subjectCN: "Matter Test DAC",
            subjectO: "Test",
            issuerCN: "Matter Test PAI",
            issuerO: "Test",
            publicKey: dacKey.publicKey,
            signerKey: paiKey,
            isCA: false,
            serialNumber: generateSerialNumber()
        )

        // Build test Certification Declaration TLV
        let cd = buildTestCertificationDeclaration(vendorID: vendorID, productID: productID)

        return DeviceAttestationCredentials(
            dacCertificate: dacCert,
            dacPrivateKey: dacKey,
            paiCertificate: paiCert,
            certificationDeclaration: cd
        )
    }

    // MARK: - X.509 DER Certificate Builder

    /// Build a minimal DER-encoded X.509 v3 certificate.
    ///
    /// Uses manual DER encoding based on PKCS10CSRBuilder helpers.
    /// Produces a valid ASN.1 structure that can be parsed by standard X.509 tools.
    private static func buildX509Certificate(
        subjectCN: String,
        subjectO: String,
        issuerCN: String,
        issuerO: String,
        publicKey: P256.Signing.PublicKey,
        signerKey: P256.Signing.PrivateKey,
        isCA: Bool,
        serialNumber: Data
    ) throws -> Data {
        // Build TBSCertificate (the part that gets signed)
        let tbs = buildTBSCertificate(
            subjectCN: subjectCN,
            subjectO: subjectO,
            issuerCN: issuerCN,
            issuerO: issuerO,
            publicKey: publicKey,
            isCA: isCA,
            serialNumber: serialNumber
        )

        // Sign the TBSCertificate with the signer key
        let signature = try signerKey.signature(for: tbs)
        let derSig = Data(signature.derRepresentation)

        // Build outer Certificate structure
        // SEQUENCE { TBSCertificate, AlgorithmIdentifier, BIT STRING(signature) }
        let sigAlg = PKCS10CSRBuilder.derSequence(
            PKCS10CSRBuilder.derOID(PKCS10CSRBuilder.oidECDSAWithSHA256)
        )
        let sigBitString = PKCS10CSRBuilder.derBitString([UInt8](derSig))

        let certContent = [UInt8](tbs) + sigAlg + sigBitString
        return Data(PKCS10CSRBuilder.derSequence(certContent))
    }

    /// Build the TBSCertificate structure for X.509.
    private static func buildTBSCertificate(
        subjectCN: String,
        subjectO: String,
        issuerCN: String,
        issuerO: String,
        publicKey: P256.Signing.PublicKey,
        isCA: Bool,
        serialNumber: Data
    ) -> Data {
        // version [0] EXPLICIT INTEGER v3 (2)
        let version = PKCS10CSRBuilder.derContextConstructed(tag: 0, content: [0x02, 0x01, 0x02])

        // serialNumber INTEGER
        let serialContent = encodePositiveInteger(serialNumber)
        let serial = PKCS10CSRBuilder.derTLV(tag: 0x02, content: serialContent)

        // signature AlgorithmIdentifier (ecdsa-with-SHA256)
        let sigAlg = PKCS10CSRBuilder.derSequence(
            PKCS10CSRBuilder.derOID(PKCS10CSRBuilder.oidECDSAWithSHA256)
        )

        // issuer Name
        let issuer = buildX509Name(cn: issuerCN, o: issuerO)

        // validity (2024-01-01 to 2034-01-01 in UTCTime format)
        let notBefore = PKCS10CSRBuilder.derTLV(tag: 0x17, content: [UInt8]("240101000000Z".utf8))
        let notAfter  = PKCS10CSRBuilder.derTLV(tag: 0x17, content: [UInt8]("340101000000Z".utf8))
        let validity  = PKCS10CSRBuilder.derSequence(notBefore + notAfter)

        // subject Name
        let subject = buildX509Name(cn: subjectCN, o: subjectO)

        // subjectPublicKeyInfo
        let spki = [UInt8](PKCS10CSRBuilder.buildSubjectPublicKeyInfo(publicKey: publicKey))

        // extensions [3] EXPLICIT
        let extensions = buildX509Extensions(isCA: isCA)
        let extensionsExplicit = PKCS10CSRBuilder.derContextConstructed(tag: 3, content: extensions)

        let tbsContent = version + serial + sigAlg + issuer + validity + subject + spki + extensionsExplicit
        return Data(PKCS10CSRBuilder.derSequence(tbsContent))
    }

    /// Build an X.509 Name (RDN sequence) with O and CN.
    private static func buildX509Name(cn: String, o: String) -> [UInt8] {
        // organizationName (2.5.4.10)
        let orgAttr = PKCS10CSRBuilder.derSequence(
            PKCS10CSRBuilder.derOID(PKCS10CSRBuilder.oidOrganizationName) +
            PKCS10CSRBuilder.derUTF8String(o)
        )
        let orgRDN = PKCS10CSRBuilder.derSet(orgAttr)

        // commonName (2.5.4.3)
        let cnAttr = PKCS10CSRBuilder.derSequence(
            PKCS10CSRBuilder.derOID(PKCS10CSRBuilder.oidCommonName) +
            PKCS10CSRBuilder.derUTF8String(cn)
        )
        let cnRDN = PKCS10CSRBuilder.derSet(cnAttr)

        return PKCS10CSRBuilder.derSequence(orgRDN + cnRDN)
    }

    /// Build X.509 v3 extensions (BasicConstraints, KeyUsage).
    private static func buildX509Extensions(isCA: Bool) -> [UInt8] {
        // BasicConstraints OID: 2.5.29.19
        let bcOID: [UInt64] = [2, 5, 29, 19]

        // BasicConstraints value: SEQUENCE { BOOLEAN(cA) } if CA, else SEQUENCE {} if end-entity
        let bcValue: [UInt8]
        if isCA {
            // SEQUENCE { BOOLEAN TRUE }
            bcValue = PKCS10CSRBuilder.derSequence([0x01, 0x01, 0xFF])
        } else {
            // SEQUENCE {} (empty — no pathLenConstraint, cA defaults to false)
            bcValue = PKCS10CSRBuilder.derSequence([])
        }

        // Wrap in OCTET STRING (the extnValue in X.509 extension encoding)
        let bcOctetString = PKCS10CSRBuilder.derTLV(tag: 0x04, content: bcValue)

        // BasicConstraints extension: SEQUENCE { OID, BOOLEAN(critical)=TRUE, OCTET STRING(value) }
        let bcExtension = PKCS10CSRBuilder.derSequence(
            PKCS10CSRBuilder.derOID(bcOID) +
            [0x01, 0x01, 0xFF] +   // BOOLEAN TRUE (critical)
            bcOctetString
        )

        // KeyUsage OID: 2.5.29.15
        let kuOID: [UInt64] = [2, 5, 29, 15]

        // KeyUsage BIT STRING:
        // For CA: keyCertSign (bit 5) + digitalSignature (bit 0) = 0xA0, 1 unused bit
        // For end-entity: digitalSignature (bit 0) = 0x80, 0 unused bits  (within 0xA0 = bits 0,5... no wait)
        // X.509 KeyUsage: bit 0=digitalSignature, bit 5=keyCertSign, bit 6=cRLSign
        // Encoded big-endian: first bit of first byte is bit 0 (MSB)
        // digitalSignature = bit 0 in ASN.1 NAMED BIT STRING = 0x80 (MSB of first data byte)
        // keyCertSign = bit 5 = 0x04 in first byte
        // cRLSign = bit 6 = 0x02 in first byte
        let kuBitStringContent: [UInt8]
        if isCA {
            // keyCertSign (bit 5) | cRLSign (bit 6) = 0x06, 1 unused bit
            kuBitStringContent = [0x01, 0x06]
        } else {
            // digitalSignature (bit 0) = 0x80, 0 unused bits
            kuBitStringContent = [0x00, 0x80]
        }
        let kuBitString = PKCS10CSRBuilder.derTLV(tag: 0x03, content: kuBitStringContent)
        let kuOctetString = PKCS10CSRBuilder.derTLV(tag: 0x04, content: kuBitString)

        let kuExtension = PKCS10CSRBuilder.derSequence(
            PKCS10CSRBuilder.derOID(kuOID) +
            [0x01, 0x01, 0xFF] +   // BOOLEAN TRUE (critical)
            kuOctetString
        )

        // Extensions wrapper: SEQUENCE of extensions
        return PKCS10CSRBuilder.derSequence(bcExtension + kuExtension)
    }

    /// Encode a byte array as a positive DER integer (add 0x00 prefix if high bit set).
    private static func encodePositiveInteger(_ bytes: Data) -> [UInt8] {
        var b = [UInt8](bytes)
        // Strip leading zeros (but keep at least one byte)
        while b.count > 1 && b[0] == 0x00 { b.removeFirst() }
        // If high bit set, prepend 0x00 to indicate positive
        if b[0] & 0x80 != 0 { b.insert(0x00, at: 0) }
        return b
    }

    /// Generate a random 20-byte serial number.
    private static func generateSerialNumber() -> Data {
        var bytes = [UInt8](repeating: 0, count: 20)
        for i in 0..<20 { bytes[i] = UInt8.random(in: 0...255) }
        // Clear high bit to ensure positive integer
        bytes[0] &= 0x7F
        return Data(bytes)
    }

    // MARK: - Certification Declaration

    /// Build a minimal test Certification Declaration TLV.
    ///
    /// The CD is a TLV-encoded structure containing vendor ID, product ID,
    /// and other metadata. For test use, this is a plain TLV payload
    /// (not CMS-wrapped). Real commissioners validate the full CMS signature chain.
    ///
    /// Structure per Matter spec §6.3.1:
    /// ```
    /// Structure {
    ///   1: formatVersion (unsigned int) = 1
    ///   2: vendorId (unsigned int)
    ///   3: [productId] (array of unsigned int)
    ///   4: deviceTypeId (unsigned int) = 0x0016 (matter-bridge)
    ///   5: certificateId (string) = "ZIG20142ZB330001-24"
    ///   6: securityLevel (unsigned int) = 0
    ///   7: securityInformation (unsigned int) = 0
    ///   8: versionNumber (unsigned int) = 1
    ///   9: certificationType (unsigned int) = 0 (development)
    /// }
    /// ```
    private static func buildTestCertificationDeclaration(
        vendorID: UInt16,
        productID: UInt16
    ) -> Data {
        let element = TLVElement.structure([
            .init(tag: .contextSpecific(1), value: .unsignedInt(1)),
            .init(tag: .contextSpecific(2), value: .unsignedInt(UInt64(vendorID))),
            .init(tag: .contextSpecific(3), value: .array([.unsignedInt(UInt64(productID))])),
            .init(tag: .contextSpecific(4), value: .unsignedInt(0x0016)),
            .init(tag: .contextSpecific(5), value: .utf8String("ZIG20142ZB330001-24")),
            .init(tag: .contextSpecific(6), value: .unsignedInt(0)),
            .init(tag: .contextSpecific(7), value: .unsignedInt(0)),
            .init(tag: .contextSpecific(8), value: .unsignedInt(1)),
            .init(tag: .contextSpecific(9), value: .unsignedInt(0)),
        ])
        return TLVEncoder.encode(element)
    }
}
