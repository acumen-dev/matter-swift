// TLVTag.swift
// Copyright 2026 Monagle Pty Ltd

/// Tag types used in Matter TLV encoding.
///
/// Tags identify fields within structures and lists. The tag type determines
/// the encoding size on the wire:
/// - Anonymous: no tag bytes (used in arrays)
/// - Context-specific: 1 byte tag number (0-255, most common in protocol messages)
/// - Common profile: 2-byte tag number in the common profile namespace
/// - Fully qualified: 6 bytes (vendor ID + profile number + tag number)
public enum TLVTag: Sendable, Equatable, Hashable {
    /// No tag — used for array elements and top-level values.
    case anonymous

    /// Context-specific tag (1 byte). Used within structures for protocol fields.
    /// Tag numbers 0-255.
    case contextSpecific(UInt8)

    /// Common profile tag (2 bytes). Shared across the Matter ecosystem.
    case commonProfile(UInt16)

    /// Fully qualified tag (6 bytes). Vendor-specific.
    case fullyQualified(vendorID: UInt16, profileNumber: UInt16, tag: UInt16)
}

extension TLVTag: CustomStringConvertible {
    public var description: String {
        switch self {
        case .anonymous:
            "anonymous"
        case .contextSpecific(let n):
            "ctx(\(n))"
        case .commonProfile(let n):
            "common(\(n))"
        case .fullyQualified(let v, let p, let t):
            "fq(\(v):\(p):\(t))"
        }
    }
}
