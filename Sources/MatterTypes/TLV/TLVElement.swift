// TLVElement.swift
// Copyright 2026 Monagle Pty Ltd

/// A single element in a Matter TLV stream.
///
/// Matter TLV (Tag-Length-Value) is the binary encoding used for all protocol messages,
/// attribute values, and certificates. Each element has an optional tag, a type, and a value.
///
/// TLV types include:
/// - Signed/unsigned integers (1, 2, 4, 8 bytes)
/// - Boolean (true/false, encoded as type with no value bytes)
/// - UTF-8 strings and octet strings (1, 2, 4 byte length prefix)
/// - Floating point (IEEE 754 single/double)
/// - Null
/// - Structures, arrays, and lists (container types)
public enum TLVElement: Sendable, Equatable {
    case signedInt(Int64)
    case unsignedInt(UInt64)
    case bool(Bool)
    case float(Float)
    case double(Double)
    case utf8String(String)
    case octetString(Data)
    case null
    case structure([TLVField])
    case array([TLVElement])
    case list([TLVField])

    /// A tagged field within a structure or list.
    public struct TLVField: Sendable, Equatable {
        public let tag: TLVTag
        public let value: TLVElement

        public init(tag: TLVTag, value: TLVElement) {
            self.tag = tag
            self.value = value
        }
    }
}

// MARK: - Convenience Accessors

extension TLVElement {
    /// Extract as signed integer, widening smaller types.
    public var intValue: Int64? {
        switch self {
        case .signedInt(let v): v
        case .unsignedInt(let v) where v <= UInt64(Int64.max): Int64(v)
        default: nil
        }
    }

    /// Extract as unsigned integer.
    public var uintValue: UInt64? {
        switch self {
        case .unsignedInt(let v): v
        case .signedInt(let v) where v >= 0: UInt64(v)
        default: nil
        }
    }

    /// Extract as boolean.
    public var boolValue: Bool? {
        if case .bool(let v) = self { return v }
        return nil
    }

    /// Extract as UTF-8 string.
    public var stringValue: String? {
        if case .utf8String(let v) = self { return v }
        return nil
    }

    /// Extract as octet string (raw bytes).
    public var dataValue: Data? {
        if case .octetString(let v) = self { return v }
        return nil
    }

    /// Extract structure fields.
    public var structureFields: [TLVField]? {
        if case .structure(let fields) = self { return fields }
        return nil
    }

    /// Extract array elements.
    public var arrayElements: [TLVElement]? {
        if case .array(let elements) = self { return elements }
        return nil
    }

    /// Whether this element is null.
    public var isNull: Bool {
        if case .null = self { return true }
        return false
    }
}

// MARK: - Structure Field Lookup

extension TLVElement {
    /// Look up a field by context tag number within a structure or list.
    public subscript(contextTag tag: UInt8) -> TLVElement? {
        let fields: [TLVField]?
        switch self {
        case .structure(let f): fields = f
        case .list(let f): fields = f
        default: return nil
        }
        return fields?.first(where: { $0.tag == .contextSpecific(tag) })?.value
    }
}

import Foundation
