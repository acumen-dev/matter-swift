// DeviceAttestationCredentials.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import MatterTypes

/// Device Attestation Credentials for a Matter device.
///
/// Holds the Device Attestation Certificate (DAC), DAC private key,
/// Product Attestation Intermediate certificate (PAI), the
/// Certification Declaration (CD), and, for test credentials, the certificate of the
/// dedicated key that signed the CD (``cdSigningCertificate``).
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
/// For test/development, we generate a full PAA → PAI → DAC chain, plus a dedicated
/// CD signing key (``cdSigningCertificate``) that signs the Certification Declaration.
public struct DeviceAttestationCredentials: Sendable {

    /// DER-encoded X.509 Device Attestation Certificate.
    public let dacCertificate: Data

    /// DAC private key (P-256).
    public let dacPrivateKey: P256.Signing.PrivateKey

    /// DER-encoded X.509 Product Attestation Intermediate certificate.
    public let paiCertificate: Data

    /// DER-encoded X.509 Product Attestation Authority certificate.
    public let paaCertificate: Data

    /// Certification Declaration: a DER CMS SignedData (§6.3.5) wrapping the TLV payload.
    public let certificationDeclaration: Data

    /// DER-encoded self-signed P-256 certificate (with a SubjectKeyIdentifier) of the key that
    /// signed ``certificationDeclaration``. A commissioner that trusts this certificate's key as
    /// a CD signer accepts the CD. `nil` when the CD is signed by a key whose certificate the
    /// device does not hold, as with a CSA-issued CD; `testCredentials` always sets it.
    public let cdSigningCertificate: Data?

    public init(
        dacCertificate: Data,
        dacPrivateKey: P256.Signing.PrivateKey,
        paiCertificate: Data,
        paaCertificate: Data,
        certificationDeclaration: Data,
        cdSigningCertificate: Data? = nil
    ) {
        self.dacCertificate = dacCertificate
        self.dacPrivateKey = dacPrivateKey
        self.paiCertificate = paiCertificate
        self.paaCertificate = paaCertificate
        self.certificationDeclaration = certificationDeclaration
        self.cdSigningCertificate = cdSigningCertificate
    }

    // MARK: - Test Credentials Factory

    /// Generate test/development attestation credentials.
    ///
    /// Creates a full PAA → PAI → DAC certificate chain. All certificates
    /// include the mandatory Matter VID/PID OIDs in their Subject DNs per
    /// Matter Core Specification §6.3.5. The Certification Declaration is signed by a
    /// dedicated CD signing key, not a chain key; its certificate is returned in
    /// ``cdSigningCertificate``, which a test trust store uses to trust the CD signer.
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
        // Generate self-signed PAA (Product Attestation Authority — the root).
        let paaKey = P256.Signing.PrivateKey()
        let paaCert = try buildX509Certificate(
            subjectCN: "Matter Test PAA",
            subjectO: "Test",
            subjectVID: nil,
            subjectPID: nil,
            issuerCN: "Matter Test PAA",
            issuerO: "Test",
            issuerVID: nil,
            publicKey: paaKey.publicKey,
            signerKey: paaKey,
            isCA: true,
            pathLenConstraint: 1,
            serialNumber: generateSerialNumber()
        )

        // Generate PAI signed by PAA.
        //
        // Per Matter spec §6.3.5.3, the PAI Subject DN MUST include:
        //   - commonName (2.5.4.3)
        //   - matterVendorId (1.3.6.1.4.1.37244.2.1) as 4-char uppercase hex
        // BasicConstraints: cA=TRUE, pathLenConstraint=0 (can sign DACs, not further CAs)
        let paiKey = P256.Signing.PrivateKey()
        let paiCert = try buildX509Certificate(
            subjectCN: "Matter Test PAI",
            subjectO: "Test",
            subjectVID: vendorID,
            subjectPID: nil,
            issuerCN: "Matter Test PAA",
            issuerO: "Test",
            issuerVID: nil,
            publicKey: paiKey.publicKey,
            signerKey: paaKey,
            isCA: true,
            pathLenConstraint: 0,
            serialNumber: generateSerialNumber()
        )

        // Generate DAC signed by PAI.
        //
        // Per Matter spec §6.3.5.4, the DAC Subject DN MUST include:
        //   - commonName (2.5.4.3)
        //   - matterVendorId (1.3.6.1.4.1.37244.2.1) as 4-char uppercase hex
        //   - matterProductId (1.3.6.1.4.1.37244.2.2) as 4-char uppercase hex
        // Issuer DN must match the PAI Subject DN exactly.
        let dacKey = P256.Signing.PrivateKey()
        let dacCert = try buildX509Certificate(
            subjectCN: "Matter Test DAC",
            subjectO: "Test",
            subjectVID: vendorID,
            subjectPID: productID,
            issuerCN: "Matter Test PAI",
            issuerO: "Test",
            issuerVID: vendorID,
            publicKey: dacKey.publicKey,
            signerKey: paiKey,
            isCA: false,
            pathLenConstraint: nil,
            serialNumber: generateSerialNumber()
        )

        // The CD is signed by its own key, as in production where the CSA signs CDs. The
        // commissioner trusts that key through its trust store, not through the PAI.
        let cdKey = P256.Signing.PrivateKey()
        let cdCert = try buildX509Certificate(
            subjectCN: "Matter Test CD Signing Authority",
            subjectO: "Test",
            subjectVID: nil,
            subjectPID: nil,
            issuerCN: "Matter Test CD Signing Authority",
            issuerO: "Test",
            issuerVID: nil,
            publicKey: cdKey.publicKey,
            signerKey: cdKey,
            isCA: true,
            pathLenConstraint: nil,
            serialNumber: generateSerialNumber()
        )

        // Build test Certification Declaration TLV wrapped in CMS SignedData (§6.3.5)
        let cd = try buildTestCertificationDeclaration(
            vendorID: vendorID,
            productID: productID,
            cdKey: cdKey
        )

        return DeviceAttestationCredentials(
            dacCertificate: dacCert,
            dacPrivateKey: dacKey,
            paiCertificate: paiCert,
            paaCertificate: paaCert,
            certificationDeclaration: cd,
            cdSigningCertificate: cdCert
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
        subjectVID: UInt16?,
        subjectPID: UInt16?,
        issuerCN: String,
        issuerO: String,
        issuerVID: UInt16?,
        publicKey: P256.Signing.PublicKey,
        signerKey: P256.Signing.PrivateKey,
        isCA: Bool,
        pathLenConstraint: Int?,
        serialNumber: Data
    ) throws -> Data {
        // Build TBSCertificate (the part that gets signed)
        let tbs = buildTBSCertificate(
            subjectCN: subjectCN,
            subjectO: subjectO,
            subjectVID: subjectVID,
            subjectPID: subjectPID,
            issuerCN: issuerCN,
            issuerO: issuerO,
            issuerVID: issuerVID,
            publicKey: publicKey,
            signerPublicKey: signerKey.publicKey,
            isCA: isCA,
            pathLenConstraint: pathLenConstraint,
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
        subjectVID: UInt16?,
        subjectPID: UInt16?,
        issuerCN: String,
        issuerO: String,
        issuerVID: UInt16?,
        publicKey: P256.Signing.PublicKey,
        signerPublicKey: P256.Signing.PublicKey,
        isCA: Bool,
        pathLenConstraint: Int?,
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
        let issuer = buildX509Name(cn: issuerCN, o: issuerO, matterVID: issuerVID)

        // validity (2024-01-01 to 2034-01-01 in UTCTime format)
        let notBefore = PKCS10CSRBuilder.derTLV(tag: 0x17, content: [UInt8]("240101000000Z".utf8))
        let notAfter  = PKCS10CSRBuilder.derTLV(tag: 0x17, content: [UInt8]("340101000000Z".utf8))
        let validity  = PKCS10CSRBuilder.derSequence(notBefore + notAfter)

        // subject Name — includes Matter VID (and PID for DAC)
        let subject = buildX509Name(cn: subjectCN, o: subjectO,
                                    matterVID: subjectVID, matterPID: subjectPID)

        // subjectPublicKeyInfo
        let spki = [UInt8](PKCS10CSRBuilder.buildSubjectPublicKeyInfo(publicKey: publicKey))

        // extensions [3] EXPLICIT
        let extensions = buildX509Extensions(
            isCA: isCA,
            pathLenConstraint: pathLenConstraint,
            subjectPublicKey: publicKey,
            issuerPublicKey: signerPublicKey
        )
        let extensionsExplicit = PKCS10CSRBuilder.derContextConstructed(tag: 3, content: extensions)

        let tbsContent = version + serial + sigAlg + issuer + validity + subject + spki + extensionsExplicit
        return Data(PKCS10CSRBuilder.derSequence(tbsContent))
    }

    /// Build an X.509 Name (RDN sequence) with O, CN, and optional Matter VID/PID OID attributes.
    ///
    /// Matter spec §6.3.5 requires PAI Subject to include `matterVendorId` (OID 1.3.6.1.4.1.37244.2.1)
    /// and DAC Subject to include both `matterVendorId` and `matterProductId` (OID 1.3.6.1.4.1.37244.2.2).
    /// Values are encoded as 4-character uppercase hex strings (e.g. "FFF1" for VID 0xFFF1).
    private static func buildX509Name(
        cn: String,
        o: String,
        matterVID: UInt16? = nil,
        matterPID: UInt16? = nil
    ) -> [UInt8] {
        let b = PKCS10CSRBuilder.self

        // organizationName (2.5.4.10)
        let orgAttr = b.derSequence(b.derOID(b.oidOrganizationName) + b.derUTF8String(o))
        let orgRDN = b.derSet(orgAttr)

        // commonName (2.5.4.3)
        let cnAttr = b.derSequence(b.derOID(b.oidCommonName) + b.derUTF8String(cn))
        let cnRDN = b.derSet(cnAttr)

        var rdns = orgRDN + cnRDN

        // matterVendorId (1.3.6.1.4.1.37244.2.1) — mandatory for PAI and DAC
        if let vid = matterVID {
            let vidStr = String(format: "%04X", vid)
            let vidAttr = b.derSequence(
                b.derOID([1, 3, 6, 1, 4, 1, 37244, 2, 1]) + b.derUTF8String(vidStr))
            rdns += b.derSet(vidAttr)
        }

        // matterProductId (1.3.6.1.4.1.37244.2.2) — mandatory for DAC
        if let pid = matterPID {
            let pidStr = String(format: "%04X", pid)
            let pidAttr = b.derSequence(
                b.derOID([1, 3, 6, 1, 4, 1, 37244, 2, 2]) + b.derUTF8String(pidStr))
            rdns += b.derSet(pidAttr)
        }

        return b.derSequence(rdns)
    }

    /// Build X.509 v3 extensions (BasicConstraints, KeyUsage, SKID, AKID).
    ///
    /// For CA certificates:
    ///   - BasicConstraints: critical, cA=TRUE, optional pathLenConstraint
    ///   - PAI must have pathLenConstraint=0 (can sign DACs, not further intermediates)
    ///
    /// For end-entity certificates (DAC):
    ///   - BasicConstraints: critical, empty (cA defaults to FALSE)
    private static func buildX509Extensions(
        isCA: Bool,
        pathLenConstraint: Int? = nil,
        subjectPublicKey: P256.Signing.PublicKey,
        issuerPublicKey: P256.Signing.PublicKey
    ) -> [UInt8] {
        // BasicConstraints OID: 2.5.29.19
        let bcOID: [UInt64] = [2, 5, 29, 19]

        // BasicConstraints value
        let bcValue: [UInt8]
        if isCA {
            if let pathLen = pathLenConstraint {
                // SEQUENCE { BOOLEAN TRUE, INTEGER pathLen }
                // pathLen is encoded as a single byte (0..127 is sufficient for Matter)
                let pathLenBytes: [UInt8] = [0x02, 0x01, UInt8(pathLen)]
                bcValue = PKCS10CSRBuilder.derSequence([0x01, 0x01, 0xFF] + pathLenBytes)
            } else {
                // SEQUENCE { BOOLEAN TRUE }
                bcValue = PKCS10CSRBuilder.derSequence([0x01, 0x01, 0xFF])
            }
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
        // X.509 KeyUsage: bit 0=digitalSignature, bit 5=keyCertSign, bit 6=cRLSign
        // Encoded big-endian: MSB of first byte is bit 0
        // digitalSignature = bit 0 = 0x80 in first byte
        // keyCertSign = bit 5 = 0x04 in first byte
        // cRLSign = bit 6 = 0x02 in first byte
        let kuBitStringContent: [UInt8]
        if isCA {
            // keyCertSign (bit 5) | cRLSign (bit 6) = 0x06, 1 unused bit
            kuBitStringContent = [0x01, 0x06]
        } else {
            // digitalSignature (bit 0) = 0x80; DER named bit lists drop trailing zero bits,
            // so 7 bits are unused.
            kuBitStringContent = [0x07, 0x80]
        }
        let kuBitString = PKCS10CSRBuilder.derTLV(tag: 0x03, content: kuBitStringContent)
        let kuOctetString = PKCS10CSRBuilder.derTLV(tag: 0x04, content: kuBitString)

        let kuExtension = PKCS10CSRBuilder.derSequence(
            PKCS10CSRBuilder.derOID(kuOID) +
            [0x01, 0x01, 0xFF] +   // BOOLEAN TRUE (critical)
            kuOctetString
        )

        // SubjectKeyIdentifier: truncated SHA-256 of the subject public key (20 bytes)
        let skidOID: [UInt64] = [2, 5, 29, 14]
        let subjectKeyHash = Array(SHA256.hash(data: subjectPublicKey.x963Representation).prefix(20))
        let skidInner = PKCS10CSRBuilder.derTLV(tag: 0x04, content: subjectKeyHash)
        let skidOctetString = PKCS10CSRBuilder.derTLV(tag: 0x04, content: skidInner)
        let skidExtension = PKCS10CSRBuilder.derSequence(
            PKCS10CSRBuilder.derOID(skidOID) + skidOctetString
        )

        // AuthorityKeyIdentifier: SEQUENCE { [0] IMPLICIT <issuer key hash> }
        let akidOID: [UInt64] = [2, 5, 29, 35]
        let issuerKeyHash = Array(SHA256.hash(data: issuerPublicKey.x963Representation).prefix(20))
        let akidKeyId = PKCS10CSRBuilder.derTLV(tag: 0x80, content: issuerKeyHash)
        let akidSeq = PKCS10CSRBuilder.derSequence(akidKeyId)
        let akidOctetString = PKCS10CSRBuilder.derTLV(tag: 0x04, content: akidSeq)
        let akidExtension = PKCS10CSRBuilder.derSequence(
            PKCS10CSRBuilder.derOID(akidOID) + akidOctetString
        )

        // Extensions wrapper: SEQUENCE of extensions
        return PKCS10CSRBuilder.derSequence(bcExtension + kuExtension + skidExtension + akidExtension)
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

    /// Build a test Certification Declaration TLV, wrapped in a CMS SignedData envelope.
    ///
    /// Per Matter spec §6.3.5, the certificationDeclaration field in attestationElements
    /// SHALL be a CMS SignedData structure. The inner
    /// TLV payload (§6.3.1) is signed by the CD signing key; the signer is named by the key's
    /// SubjectKeyIdentifier, as in connectedhomeip's `CMS_Sign`.
    private static func buildTestCertificationDeclaration(
        vendorID: UInt16,
        productID: UInt16,
        cdKey: P256.Signing.PrivateKey
    ) throws -> Data {
        // Inner TLV payload per §6.3.1: tags 0...8, in order.
        let tlvPayload = TLVEncoder.encode(TLVElement.structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(1)),                          // format_version
            .init(tag: .contextSpecific(1), value: .unsignedInt(UInt64(vendorID))),
            .init(tag: .contextSpecific(2), value: .array([.unsignedInt(UInt64(productID))])),
            .init(tag: .contextSpecific(3), value: .unsignedInt(0x000E)),                     // device_type_id: Aggregator/Bridge
            .init(tag: .contextSpecific(4), value: .utf8String("ZIG20142ZB330001-24")),      // certificate_id (19 bytes)
            .init(tag: .contextSpecific(5), value: .unsignedInt(0)),                          // security_level
            .init(tag: .contextSpecific(6), value: .unsignedInt(0)),                          // security_information
            .init(tag: .contextSpecific(7), value: .unsignedInt(1)),                          // version_number
            .init(tag: .contextSpecific(8), value: .unsignedInt(0)),                          // certification_type
        ]))

        return try buildCMSCertificationDeclaration(tlvPayload: tlvPayload, cdKey: cdKey)
    }

    // MARK: - CMS SignedData Builder

    /// Wrap a raw TLV Certification Declaration in a CMS SignedData envelope.
    ///
    /// Produces a DER-encoded ContentInfo containing a SignedData:
    /// - eContentType: 1.2.840.113549.1.7.1 (pkcs7-data), as connectedhomeip's `CMS_Sign` writes
    /// - eContent: [0] EXPLICIT OCTET STRING(tlvPayload)
    /// - no certificates field
    /// - signerInfos: version 3, ECDSA-SHA256 signature over the raw TLV, identified by the
    ///   signing key's SubjectKeyIdentifier as `[0] IMPLICIT`.
    private static func buildCMSCertificationDeclaration(
        tlvPayload: Data,
        cdKey: P256.Signing.PrivateKey
    ) throws -> Data {
        // Same derivation as the SubjectKeyIdentifier in buildX509Extensions.
        let keyIdentifier = Array(SHA256.hash(data: cdKey.publicKey.x963Representation).prefix(20))

        // CMS without signedAttrs: signature covers the eContent bytes directly.
        // CMS ECDSA signatures are DER-encoded (not raw r‖s).
        let sig = try cdKey.signature(for: tlvPayload)
        let derSig = [UInt8](sig.derRepresentation)

        // OID constants
        let oidSignedData:     [UInt64] = [1, 2, 840, 113549, 1, 7, 2]      // id-signedData
        let oidSHA256:         [UInt64] = [2, 16, 840, 1, 101, 3, 4, 2, 1]  // sha-256
        let oidECDSAwSHA256:   [UInt64] = [1, 2, 840, 10045, 4, 3, 2]       // ecdsa-with-SHA256
        let oidData:           [UInt64] = [1, 2, 840, 113549, 1, 7, 1]      // pkcs7-data

        let b = PKCS10CSRBuilder.self

        // digestAlgorithms SET { SEQUENCE { sha-256 } }; parameters absent (RFC 5754 §2)
        let digestAlgorithms = b.derSet(
            b.derSequence(b.derOID(oidSHA256))
        )

        // encapContentInfo SEQUENCE { OID, [0] EXPLICIT OCTET STRING }
        let eContentOctetString = b.derTLV(tag: 0x04, content: [UInt8](tlvPayload))
        let eContentExplicit    = b.derContextConstructed(tag: 0, content: eContentOctetString)
        let encapContentInfo    = b.derSequence(b.derOID(oidData) + eContentExplicit)

        // SignerIdentifier [0] IMPLICIT SubjectKeyIdentifier
        let subjectKeyIdentifier = b.derTLV(tag: 0x80, content: keyIdentifier)

        // SignerInfo SEQUENCE { version 3, sid, digestAlg, sigAlg, signature }
        // Version 3 because the sid is a SubjectKeyIdentifier (RFC 5652 §5.3).
        let siVersion  = b.derTLV(tag: 0x02, content: [0x03])  // INTEGER 3
        let siDigestAlg = b.derSequence(b.derOID(oidSHA256))
        let siSigAlg   = b.derSequence(b.derOID(oidECDSAwSHA256))
        let siSig      = b.derTLV(tag: 0x04, content: derSig)  // OCTET STRING
        let signerInfo  = b.derSequence(siVersion + subjectKeyIdentifier + siDigestAlg + siSigAlg + siSig)
        let signerInfos = b.derSet(signerInfo)

        // SignedData SEQUENCE { version 3, digestAlgorithms, encapContentInfo, signerInfos }
        // Version 3 because the SignerInfo is version 3 (RFC 5652 §5.1)
        let sdVersion  = b.derTLV(tag: 0x02, content: [0x03])  // INTEGER 3
        let signedData = b.derSequence(
            sdVersion + digestAlgorithms + encapContentInfo + signerInfos
        )

        // ContentInfo SEQUENCE { OID id-signedData, [0] EXPLICIT SignedData }
        let contentInfo = b.derSequence(
            b.derOID(oidSignedData) +
            b.derContextConstructed(tag: 0, content: [UInt8](signedData))
        )

        return Data(contentInfo)
    }
}

