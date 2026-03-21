// TLVCodable.swift
// Copyright 2026 Monagle Pty Ltd

/// A type that can be encoded to a Matter TLV element.
public protocol TLVEncodable: Sendable {
    func toTLVElement() -> TLVElement
}

/// A type that can be decoded from a Matter TLV element.
public protocol TLVDecodable: Sendable {
    static func fromTLVElement(_ element: TLVElement) throws -> Self
}

/// A type that supports both TLV encoding and decoding.
public typealias TLVCodable = TLVEncodable & TLVDecodable

/// Errors thrown during TLV decoding of generated structs.
public enum TLVDecodingError: Error, Sendable {
    case invalidStructure
    case missingField(name: String, tag: UInt8)
    case invalidFieldType(name: String, tag: UInt8, expected: String)
}
