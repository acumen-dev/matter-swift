// MatterCertificateAttributes.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import SwiftASN1
import X509

// MARK: - MatterCertificateAttributes

/// Reads the Matter vendor and product identifiers from a certificate's distinguished name.
///
/// Mirrors connectedhomeip v1.4.0.0 `ExtractVIDPIDFromAttributeString` and
/// `Find16BitUpperCaseHexAfterPrefix` (src/crypto/CHIPCryptoPAL.cpp), edge for edge:
///
/// - Matter carries the ids as dedicated subject attributes, a value of exactly four uppercase
///   hex digits under 1.3.6.1.4.1.37244.2.1 (VID) and .2.2 (PID); a repeat is an error.
/// - Common names are parsed too, and a malformed one is an error even when Matter attributes
///   are present. The CN ids are used only when no Matter attribute exists.
/// - Only the first common name that yields an id is used. It is truncated to 64 bytes, then
///   searched for `Mvid:` / `Mpid:` anywhere; the first occurrence followed by four uppercase
///   hex digits wins. A prefix seen with no valid hex after any occurrence is an error.
/// - An empty attribute value is an error.
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

    /// The VID and PID carried by `name`; `nil` for an id that is absent. Throws when the name
    /// is invalid under the rules above.
    static func identifiers(in name: DistinguishedName) throws -> (vendorID: UInt16?, productID: UInt16?) {
        var matterVID: UInt16?
        var matterPID: UInt16?
        var cnVID: UInt16?
        var cnPID: UInt16?
        var cnInitialized = false

        for rdn in name {
            for attribute in rdn {
                let isVID = attribute.type == vendorIDOID
                let isPID = attribute.type == productIDOID
                let isCN = attribute.type == .RDNAttributeType.commonName
                guard isVID || isPID || isCN else { continue }
                guard let text = String(attribute.value) else {
                    if isCN { continue }  // not a text string: nothing to search
                    throw Failure.malformedValue(isVID ? "VID" : "PID")
                }
                let bytes = Array(text.utf8)
                guard !bytes.isEmpty else { throw Failure.malformedValue("empty attribute") }

                if isVID || isPID {
                    let what = isVID ? "VID" : "PID"
                    guard bytes.count == 4, let value = parseHex16(bytes[...]) else {
                        throw Failure.malformedValue(what)
                    }
                    if isVID {
                        guard matterVID == nil else { throw Failure.duplicate(what) }
                        matterVID = value
                    } else {
                        guard matterPID == nil else { throw Failure.duplicate(what) }
                        matterPID = value
                    }
                } else if !cnInitialized {
                    let searched = bytes.prefix(maxCommonNameLength)
                    if let value = try hexAfterPrefix(Array("Mvid:".utf8), in: searched, what: "VID") {
                        cnVID = value
                    }
                    if let value = try hexAfterPrefix(Array("Mpid:".utf8), in: searched, what: "PID") {
                        cnPID = value
                    }
                    cnInitialized = cnVID != nil || cnPID != nil
                }
            }
        }
        if matterVID != nil || matterPID != nil { return (matterVID, matterPID) }
        return (cnVID, cnPID)
    }

    /// `kMax_CommonNameAttr_Length`: the CN is truncated to this many bytes before searching.
    private static let maxCommonNameLength = 64

    // MARK: - Parsing

    /// `Find16BitUpperCaseHexAfterPrefix`: scans for each occurrence of `prefix`; the first one
    /// followed by four uppercase hex digits wins. Seeing the prefix with no valid value is an error.
    private static func hexAfterPrefix(_ prefix: [UInt8], in buffer: ArraySlice<UInt8>, what: String) throws -> UInt16? {
        var sawPrefix = false
        var index = buffer.startIndex
        while index < buffer.endIndex {
            guard buffer.endIndex - index >= prefix.count else { break }
            guard buffer[index..<index + prefix.count].elementsEqual(prefix) else {
                index += 1
                continue
            }
            sawPrefix = true
            let valueStart = index + prefix.count
            guard buffer.endIndex - valueStart >= 4 else { break }
            if let value = parseHex16(buffer[valueStart..<valueStart + 4]) { return value }
            index += 1
        }
        if sawPrefix { throw Failure.malformedValue(what) }
        return nil
    }

    private static func parseHex16(_ bytes: ArraySlice<UInt8>) -> UInt16? {
        guard bytes.count == 4, bytes.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x46) })
        else { return nil }
        return UInt16(String(decoding: bytes, as: UTF8.self), radix: 16)
    }
}
