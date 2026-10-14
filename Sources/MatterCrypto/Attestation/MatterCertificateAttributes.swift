// MatterCertificateAttributes.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import SwiftASN1
import X509

// MARK: - MatterCertificateAttributes

/// Reads the Matter vendor and product identifiers from a certificate's distinguished name.
///
/// The semantics follow connectedhomeip (`ExtractVIDPIDFromX509Cert` and
/// `Find16BitUpperCaseHexAfterPrefix`):
///
/// - Matter carries the ids as dedicated subject attributes, a UTF8String of exactly four
///   uppercase hex digits under 1.3.6.1.4.1.37244.2.1 (VID) and .2.2 (PID).
/// - If any Matter attribute is present, the common name is ignored for both ids.
/// - Otherwise the legacy form is read from the common name: the substring `Mvid:` or
///   `Mpid:` anywhere, followed by exactly four uppercase hex digits; anything may follow.
/// - A malformed value, a prefix without four uppercase hex digits after it, or a repeated
///   attribute makes the name invalid, which is distinct from the ids being absent.
enum MatterCertificateAttributes {

    /// Matter vendor ID subject attribute.
    static let vendorIDOID: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 37244, 2, 1]

    /// Matter product ID subject attribute.
    static let productIDOID: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 37244, 2, 2]

    /// Why a distinguished name's Matter identifiers are invalid.
    enum Failure: Error, Equatable {
        case malformedValue(String)
        case duplicate(String)
    }

    /// The VID and PID carried by `name`; `nil` for an id that is absent. Throws when an id is
    /// present but malformed or repeated.
    static func identifiers(in name: DistinguishedName) throws -> (vendorID: UInt16?, productID: UInt16?) {
        var vendorID: UInt16?
        var productID: UInt16?
        var sawMatterAttribute = false

        for rdn in name {
            for attribute in rdn {
                if attribute.type == vendorIDOID {
                    sawMatterAttribute = true
                    guard vendorID == nil else { throw Failure.duplicate("VID") }
                    vendorID = try exactHex16(attribute.value, what: "VID")
                } else if attribute.type == productIDOID {
                    sawMatterAttribute = true
                    guard productID == nil else { throw Failure.duplicate("PID") }
                    productID = try exactHex16(attribute.value, what: "PID")
                }
            }
        }
        if sawMatterAttribute { return (vendorID, productID) }

        for rdn in name {
            for attribute in rdn where attribute.type == .RDNAttributeType.commonName {
                guard let text = String(attribute.value) else { continue }
                if let value = try hexAfterPrefix("Mvid:", in: text, what: "VID") {
                    guard vendorID == nil else { throw Failure.duplicate("VID") }
                    vendorID = value
                }
                if let value = try hexAfterPrefix("Mpid:", in: text, what: "PID") {
                    guard productID == nil else { throw Failure.duplicate("PID") }
                    productID = value
                }
            }
        }
        return (vendorID, productID)
    }

    // MARK: - Parsing

    private static func exactHex16(_ value: RelativeDistinguishedName.Attribute.Value, what: String) throws -> UInt16 {
        guard let text = String(value), let parsed = parseHex16(Substring(text)), text.utf8.count == 4 else {
            throw Failure.malformedValue(what)
        }
        return parsed
    }

    /// Finds `prefix` (the first occurrence) and requires four uppercase hex digits after it.
    private static func hexAfterPrefix(_ prefix: String, in text: String, what: String) throws -> UInt16? {
        guard let range = text.range(of: prefix) else { return nil }
        let rest = text[range.upperBound...]
        guard rest.utf8.count >= 4, let parsed = parseHex16(rest.prefix(4)) else {
            throw Failure.malformedValue(what)
        }
        return parsed
    }

    private static func parseHex16(_ text: Substring) -> UInt16? {
        guard text.utf8.count == 4, text.utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x46) })
        else { return nil }
        return UInt16(text, radix: 16)
    }
}
