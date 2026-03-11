// TLVDecoder.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

/// Decodes Matter TLV binary data into `TLVElement` values.
///
/// The decoder reads from a byte buffer and produces typed elements.
/// It handles all standard TLV types including nested containers
/// (structures, arrays, lists).
public struct TLVDecoder: Sendable {
    private var data: Data
    private var offset: Int

    public init(data: Data) {
        self.data = data
        self.offset = 0
    }

    /// Decode the next element from the buffer.
    ///
    /// Returns `nil` when the buffer is exhausted.
    public mutating func decodeElement() throws -> (tag: TLVTag, element: TLVElement)? {
        guard offset < data.count else { return nil }

        let controlByte = data[offset]
        offset += 1

        let elementTypeRaw = controlByte & 0x1F
        let tagFormRaw = controlByte & 0xE0

        // End of container is a special case — not a real element
        guard elementTypeRaw != 0x18 else {
            return nil
        }

        let tag = try decodeTag(tagForm: tagFormRaw)
        let element = try decodeValue(elementType: elementTypeRaw)

        return (tag, element)
    }

    /// Decode a single top-level element.
    public static func decode(_ data: Data) throws -> (tag: TLVTag, element: TLVElement) {
        var decoder = TLVDecoder(data: data)
        guard let result = try decoder.decodeElement() else {
            throw TLVError.unexpectedEndOfData
        }
        return result
    }
}

// MARK: - Tag Decoding

extension TLVDecoder {
    private mutating func decodeTag(tagForm: UInt8) throws -> TLVTag {
        switch tagForm {
        case 0x00: // Anonymous
            return .anonymous
        case 0x20: // Context-specific (1 byte)
            return .contextSpecific(try readByte())
        case 0x40: // Common profile (2 bytes)
            return .commonProfile(try readUInt16())
        case 0x60: // Common profile (4 bytes — vendor 0 + 2-byte tag)
            _ = try readUInt16() // vendor ID (0 for common)
            return .commonProfile(try readUInt16())
        case 0x80: // Fully qualified (6 bytes)
            let vendor = try readUInt16()
            let profile = try readUInt16()
            let tagNum = try readUInt16()
            return .fullyQualified(vendorID: vendor, profileNumber: profile, tag: tagNum)
        case 0xA0: // Fully qualified (8 bytes — 4-byte profile + 4-byte tag, not common)
            let vendor = try readUInt16()
            let profile = try readUInt16()
            let tagNum = try readUInt16()
            // Consume 2 extra bytes for the 8-byte form
            _ = try readUInt16()
            return .fullyQualified(vendorID: vendor, profileNumber: profile, tag: tagNum)
        default:
            throw TLVError.invalidTagForm(tagForm)
        }
    }
}

// MARK: - Value Decoding

extension TLVDecoder {
    private mutating func decodeValue(elementType: UInt8) throws -> TLVElement {
        switch elementType {
        // Signed integers
        case 0x00: return .signedInt(Int64(Int8(bitPattern: try readByte())))
        case 0x01: return .signedInt(Int64(Int16(bitPattern: try readUInt16())))
        case 0x02: return .signedInt(Int64(Int32(bitPattern: try readUInt32())))
        case 0x03: return .signedInt(Int64(bitPattern: try readUInt64()))

        // Unsigned integers
        case 0x04: return .unsignedInt(UInt64(try readByte()))
        case 0x05: return .unsignedInt(UInt64(try readUInt16()))
        case 0x06: return .unsignedInt(UInt64(try readUInt32()))
        case 0x07: return .unsignedInt(try readUInt64())

        // Booleans
        case 0x08: return .bool(false)
        case 0x09: return .bool(true)

        // Floating point
        case 0x0A:
            let bits = try readUInt32()
            return .float(Float(bitPattern: bits))
        case 0x0B:
            let bits = try readUInt64()
            return .double(Double(bitPattern: bits))

        // UTF-8 strings
        case 0x0C: return .utf8String(try readString(lengthBytes: 1))
        case 0x0D: return .utf8String(try readString(lengthBytes: 2))
        case 0x0E: return .utf8String(try readString(lengthBytes: 4))

        // Octet strings
        case 0x10: return .octetString(try readOctets(lengthBytes: 1))
        case 0x11: return .octetString(try readOctets(lengthBytes: 2))
        case 0x12: return .octetString(try readOctets(lengthBytes: 4))

        // Null
        case 0x14: return .null

        // Containers
        case 0x15: return .structure(try decodeContainerFields())
        case 0x16: return .array(try decodeContainerElements())
        case 0x17: return .list(try decodeContainerFields())

        default:
            throw TLVError.unknownElementType(elementType)
        }
    }

    private mutating func decodeContainerFields() throws -> [TLVElement.TLVField] {
        var fields: [TLVElement.TLVField] = []
        while let (tag, element) = try decodeElement() {
            fields.append(TLVElement.TLVField(tag: tag, value: element))
        }
        return fields
    }

    private mutating func decodeContainerElements() throws -> [TLVElement] {
        var elements: [TLVElement] = []
        while let (_, element) = try decodeElement() {
            elements.append(element)
        }
        return elements
    }
}

// MARK: - Primitive Readers

extension TLVDecoder {
    private mutating func readByte() throws -> UInt8 {
        guard offset < data.count else { throw TLVError.unexpectedEndOfData }
        let byte = data[offset]
        offset += 1
        return byte
    }

    private mutating func readUInt16() throws -> UInt16 {
        guard offset + 2 <= data.count else { throw TLVError.unexpectedEndOfData }
        let value = UInt16(data[offset]) | (UInt16(data[offset + 1]) << 8)
        offset += 2
        return value
    }

    private mutating func readUInt32() throws -> UInt32 {
        guard offset + 4 <= data.count else { throw TLVError.unexpectedEndOfData }
        var value: UInt32 = 0
        for i in 0..<4 {
            value |= UInt32(data[offset + i]) << (i * 8)
        }
        offset += 4
        return value
    }

    private mutating func readUInt64() throws -> UInt64 {
        guard offset + 8 <= data.count else { throw TLVError.unexpectedEndOfData }
        var value: UInt64 = 0
        for i in 0..<8 {
            value |= UInt64(data[offset + i]) << (i * 8)
        }
        offset += 8
        return value
    }

    private mutating func readString(lengthBytes: Int) throws -> String {
        let length = try readLength(bytes: lengthBytes)
        guard offset + length <= data.count else { throw TLVError.unexpectedEndOfData }
        let bytes = data[offset..<(offset + length)]
        offset += length
        guard let string = String(data: bytes, encoding: .utf8) else {
            throw TLVError.invalidUTF8
        }
        return string
    }

    private mutating func readOctets(lengthBytes: Int) throws -> Data {
        let length = try readLength(bytes: lengthBytes)
        guard offset + length <= data.count else { throw TLVError.unexpectedEndOfData }
        let bytes = data[offset..<(offset + length)]
        offset += length
        return Data(bytes)
    }

    private mutating func readLength(bytes: Int) throws -> Int {
        switch bytes {
        case 1: return Int(try readByte())
        case 2: return Int(try readUInt16())
        case 4: return Int(try readUInt32())
        default: throw TLVError.invalidLengthEncoding
        }
    }
}

// MARK: - Errors

/// Errors that can occur during TLV decoding.
public enum TLVError: Error, Sendable {
    case unexpectedEndOfData
    case invalidTagForm(UInt8)
    case unknownElementType(UInt8)
    case invalidUTF8
    case invalidLengthEncoding
}
