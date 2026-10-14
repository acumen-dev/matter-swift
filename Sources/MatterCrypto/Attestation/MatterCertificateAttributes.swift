// MatterCertificateAttributes.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import SwiftASN1
import X509

// MARK: - MatterCertificateAttributes

/// Reads the Matter vendor and product identifiers from a certificate's distinguished name.
///
/// Matter carries them as dedicated subject attributes (a 4-hex-digit UTF8String under
/// 1.3.6.1.4.1.37244.2.1 and .2.2). The specification also allows a legacy form inside the
/// common name, for example `Mvid:FFF1 Mpid:8000`. Both are read; the dedicated attribute wins.
enum MatterCertificateAttributes {

    /// Matter vendor ID subject attribute.
    static let vendorIDOID: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 37244, 2, 1]

    /// Matter product ID subject attribute.
    static let productIDOID: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 37244, 2, 2]

    static func vendorID(in name: DistinguishedName) -> UInt16? {
        identifier(in: name, oid: vendorIDOID, legacyPrefix: "Mvid:")
    }

    static func productID(in name: DistinguishedName) -> UInt16? {
        identifier(in: name, oid: productIDOID, legacyPrefix: "Mpid:")
    }

    // MARK: - Parsing

    private static func identifier(
        in name: DistinguishedName, oid: ASN1ObjectIdentifier, legacyPrefix: String
    ) -> UInt16? {
        for rdn in name {
            for attribute in rdn where attribute.type == oid {
                if let text = String(attribute.value), let value = parseHex16(text) {
                    return value
                }
            }
        }
        for rdn in name {
            for attribute in rdn where attribute.type == .RDNAttributeType.commonName {
                guard let text = String(attribute.value) else { continue }
                for token in text.split(whereSeparator: { $0 == " " || $0 == "," }) where token.hasPrefix(legacyPrefix) {
                    if let value = parseHex16(String(token.dropFirst(legacyPrefix.count))) {
                        return value
                    }
                }
            }
        }
        return nil
    }

    /// Exactly four uppercase hex digits, as Matter requires.
    private static func parseHex16(_ text: String) -> UInt16? {
        guard text.utf8.count == 4, text.utf8.allSatisfy({ $0.isASCIIHexDigit }) else { return nil }
        return UInt16(text, radix: 16)
    }
}

private extension UInt8 {
    var isASCIIHexDigit: Bool {
        (0x30...0x39).contains(self) || (0x41...0x46).contains(self)
    }
}
