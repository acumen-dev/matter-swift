// CertificationDeclarationSigner.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import MatterTypes
import SwiftASN1

// MARK: - CertificationDeclarationSigner

/// Builds Certification Declarations in the shape connectedhomeip `CMS_Sign` writes, for
/// attestation tests that the connectedhomeip vectors do not isolate.
///
/// The defaults are the fields of ``AttestationFixtures/testCD`` other than its VID and PIDs.
public enum CertificationDeclarationSigner {

    /// The TLV payload (`EncodeCertificationElements`).
    public static func content(
        vendorID: UInt16,
        productIDs: [UInt16],
        deviceTypeID: UInt32 = 0x1234,
        certificateID: String = "ZIG20141ZB330001-24",
        securityLevel: UInt8 = 0,
        securityInformation: UInt16 = 0,
        versionNumber: UInt16 = 0x9876,
        certificationType: UInt8 = 0,
        formatVersion: UInt8 = 1,
        dacOrigin: (vendorID: UInt16, productID: UInt16)? = nil,
        authorizedPAAs: [Data]? = nil
    ) -> Data {
        var fields: [TLVElement.TLVField] = [
            .init(tag: .contextSpecific(0), value: .unsignedInt(UInt64(formatVersion))),
            .init(tag: .contextSpecific(1), value: .unsignedInt(UInt64(vendorID))),
            .init(tag: .contextSpecific(2), value: .array(productIDs.map { .unsignedInt(UInt64($0)) })),
            .init(tag: .contextSpecific(3), value: .unsignedInt(UInt64(deviceTypeID))),
            .init(tag: .contextSpecific(4), value: .utf8String(certificateID)),
            .init(tag: .contextSpecific(5), value: .unsignedInt(UInt64(securityLevel))),
            .init(tag: .contextSpecific(6), value: .unsignedInt(UInt64(securityInformation))),
            .init(tag: .contextSpecific(7), value: .unsignedInt(UInt64(versionNumber))),
            .init(tag: .contextSpecific(8), value: .unsignedInt(UInt64(certificationType))),
        ]
        if let dacOrigin {
            fields.append(.init(tag: .contextSpecific(9), value: .unsignedInt(UInt64(dacOrigin.vendorID))))
            fields.append(.init(tag: .contextSpecific(10), value: .unsignedInt(UInt64(dacOrigin.productID))))
        }
        if let authorizedPAAs {
            fields.append(.init(tag: .contextSpecific(11), value: .array(authorizedPAAs.map { .octetString($0) })))
        }
        return TLVEncoder.encode(.structure(fields))
    }

    /// Wraps `content` in a CMS SignedData signed by `key`, naming the signer by `keyIdentifier`.
    public static func sign(content: Data, key: P256.Signing.PrivateKey, keyIdentifier: Data) throws -> Data {
        let signature = try key.signature(for: content).derRepresentation
        let contextZero = ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)
        let sha256: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 2, 1]

        var serializer = DER.Serializer()
        try serializer.appendConstructedNode(identifier: .sequence) { contentInfo in
            try contentInfo.serialize([1, 2, 840, 113549, 1, 7, 2] as ASN1ObjectIdentifier)
            try contentInfo.appendConstructedNode(identifier: contextZero) { explicit in
                try explicit.appendConstructedNode(identifier: .sequence) { signedData in
                    try signedData.serialize(3)
                    try signedData.appendConstructedNode(identifier: .set) { set in
                        try set.appendConstructedNode(identifier: .sequence) { try $0.serialize(sha256) }
                    }
                    try signedData.appendConstructedNode(identifier: .sequence) { encapsulated in
                        try encapsulated.serialize([1, 2, 840, 113549, 1, 7, 1] as ASN1ObjectIdentifier)
                        try encapsulated.appendConstructedNode(identifier: contextZero) {
                            try $0.serialize(ASN1OctetString(contentBytes: ArraySlice(content)))
                        }
                    }
                    try signedData.appendConstructedNode(identifier: .set) { set in
                        try set.appendConstructedNode(identifier: .sequence) { signerInfo in
                            try signerInfo.serialize(3)
                            signerInfo.appendPrimitiveNode(identifier: contextZero) { $0.append(contentsOf: keyIdentifier) }
                            try signerInfo.appendConstructedNode(identifier: .sequence) { try $0.serialize(sha256) }
                            try signerInfo.appendConstructedNode(identifier: .sequence) {
                                try $0.serialize([1, 2, 840, 10045, 4, 3, 2] as ASN1ObjectIdentifier)
                            }
                            try signerInfo.serialize(ASN1OctetString(contentBytes: ArraySlice(signature)))
                        }
                    }
                }
            }
        }
        return Data(serializer.serializedBytes)
    }

    /// Signs `content` with the upstream "Matter Test CD Signing Authority" key
    /// (``AttestationFixtures/testCDSigningKey``), the key that signs ``AttestationFixtures/testCD``.
    public static func signWithTestKey(content: Data) throws -> Data {
        let pem = String(decoding: try AttestationFixtures.testCDSigningKey, as: UTF8.self)
        let key = try P256.Signing.PrivateKey(pemRepresentation: pem)
        return try sign(content: content, key: key, keyIdentifier: testCDKeyIdentifier)
    }

    /// SubjectKeyIdentifier of ``AttestationFixtures/testCDSigningCert``.
    public static let testCDKeyIdentifier = Data([
        0x62, 0xFA, 0x82, 0x33, 0x59, 0xAC, 0xFA, 0xA9, 0x96, 0x3E,
        0x1C, 0xFA, 0x14, 0x0A, 0xDD, 0xF5, 0x04, 0xF3, 0x71, 0x60,
    ])
}
