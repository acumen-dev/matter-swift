// TLVEncoder.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

/// Encodes `TLVElement` values into Matter TLV binary format.
///
/// The encoder produces the smallest valid encoding for each value:
/// - Integers use the minimum byte width (1/2/4/8) that fits the value
/// - Strings and octet strings use the minimum length prefix (1/2/4 bytes)
/// - Containers are delimited by an end-of-container marker (0x18)
///
/// ## Wire Format
///
/// Each element is encoded as:
/// ```
/// [control byte] [tag bytes] [length bytes] [value bytes]
/// ```
///
/// The control byte encodes both the element type and the tag form:
/// - Bits 0-4: Element type (signed int 1B, signed int 2B, ..., structure, array, etc.)
/// - Bits 5-7: Tag form (anonymous, context, common profile 2B, common profile 4B, fully qualified 6B/8B)
public struct TLVEncoder: Sendable {
    private var buffer: [UInt8] = []

    public init() {}

    /// Encode a tagged element and return the raw bytes.
    public mutating func encode(tag: TLVTag = .anonymous, _ element: TLVElement) {
        switch element {
        case .signedInt(let value):
            encodeSignedInt(tag: tag, value)
        case .unsignedInt(let value):
            encodeUnsignedInt(tag: tag, value)
        case .bool(let value):
            encodeBool(tag: tag, value)
        case .float(let value):
            encodeFloat(tag: tag, value)
        case .double(let value):
            encodeDouble(tag: tag, value)
        case .utf8String(let value):
            encodeUTF8String(tag: tag, value)
        case .octetString(let value):
            encodeOctetString(tag: tag, value)
        case .null:
            encodeNull(tag: tag)
        case .structure(let fields):
            encodeStructure(tag: tag, fields)
        case .array(let elements):
            encodeArray(tag: tag, elements)
        case .list(let fields):
            encodeList(tag: tag, fields)
        }
    }

    /// Returns the encoded bytes and resets the encoder.
    public mutating func finish() -> Data {
        let result = Data(buffer)
        buffer.removeAll()
        return result
    }

    /// Encode a tagged element and return the result as Data.
    public static func encode(tag: TLVTag = .anonymous, _ element: TLVElement) -> Data {
        var encoder = TLVEncoder()
        encoder.encode(tag: tag, element)
        return encoder.finish()
    }
}

// MARK: - Element Type Constants

/// Matter TLV element type codes (lower 5 bits of control byte).
private enum ElementType: UInt8 {
    case signedInt1   = 0x00
    case signedInt2   = 0x01
    case signedInt4   = 0x02
    case signedInt8   = 0x03
    case unsignedInt1 = 0x04
    case unsignedInt2 = 0x05
    case unsignedInt4 = 0x06
    case unsignedInt8 = 0x07
    case boolFalse    = 0x08
    case boolTrue     = 0x09
    case float4       = 0x0A
    case float8       = 0x0B
    case utf8String1  = 0x0C
    case utf8String2  = 0x0D
    case utf8String4  = 0x0E
    // 0x0F reserved for utf8String8
    case octetString1 = 0x10
    case octetString2 = 0x11
    case octetString4 = 0x12
    // 0x13 reserved for octetString8
    case null         = 0x14
    case structure    = 0x15
    case array        = 0x16
    case list         = 0x17
    case endOfContainer = 0x18
}

/// Tag form codes (upper 3 bits of control byte, shifted left by 5).
private enum TagForm: UInt8 {
    case anonymous        = 0x00  // 0b000
    case contextSpecific  = 0x20  // 0b001
    case commonProfile2   = 0x40  // 0b010
    case commonProfile4   = 0x60  // 0b011
    case fullyQualified6  = 0x80  // 0b100
    case fullyQualified8  = 0xA0  // 0b101
}

// MARK: - Private Encoding Methods

extension TLVEncoder {
    private mutating func writeControlByte(_ elementType: ElementType, tag: TLVTag) {
        let tagForm: TagForm
        switch tag {
        case .anonymous: tagForm = .anonymous
        case .contextSpecific: tagForm = .contextSpecific
        case .commonProfile(let n) where n <= UInt16.max: tagForm = .commonProfile2
        case .commonProfile: tagForm = .commonProfile4
        case .fullyQualified: tagForm = .fullyQualified6
        }
        buffer.append(tagForm.rawValue | elementType.rawValue)
        writeTagBytes(tag)
    }

    private mutating func writeTagBytes(_ tag: TLVTag) {
        switch tag {
        case .anonymous:
            break
        case .contextSpecific(let n):
            buffer.append(n)
        case .commonProfile(let n):
            appendLittleEndian(n)
        case .fullyQualified(let vendorID, let profileNumber, let tagNumber):
            appendLittleEndian(vendorID)
            appendLittleEndian(profileNumber)
            appendLittleEndian(tagNumber)
        }
    }

    private mutating func appendLittleEndian(_ value: UInt16) {
        buffer.append(UInt8(value & 0xFF))
        buffer.append(UInt8((value >> 8) & 0xFF))
    }

    private mutating func appendLittleEndian(_ value: UInt32) {
        buffer.append(UInt8(value & 0xFF))
        buffer.append(UInt8((value >> 8) & 0xFF))
        buffer.append(UInt8((value >> 16) & 0xFF))
        buffer.append(UInt8((value >> 24) & 0xFF))
    }

    private mutating func appendLittleEndian(_ value: UInt64) {
        for i in 0..<8 {
            buffer.append(UInt8((value >> (i * 8)) & 0xFF))
        }
    }

    // MARK: - Typed Encoders

    private mutating func encodeSignedInt(tag: TLVTag, _ value: Int64) {
        if value >= Int8.min && value <= Int8.max {
            writeControlByte(.signedInt1, tag: tag)
            buffer.append(UInt8(bitPattern: Int8(value)))
        } else if value >= Int16.min && value <= Int16.max {
            writeControlByte(.signedInt2, tag: tag)
            appendLittleEndian(UInt16(bitPattern: Int16(value)))
        } else if value >= Int32.min && value <= Int32.max {
            writeControlByte(.signedInt4, tag: tag)
            appendLittleEndian(UInt32(bitPattern: Int32(value)))
        } else {
            writeControlByte(.signedInt8, tag: tag)
            appendLittleEndian(UInt64(bitPattern: value))
        }
    }

    private mutating func encodeUnsignedInt(tag: TLVTag, _ value: UInt64) {
        if value <= UInt8.max {
            writeControlByte(.unsignedInt1, tag: tag)
            buffer.append(UInt8(value))
        } else if value <= UInt16.max {
            writeControlByte(.unsignedInt2, tag: tag)
            appendLittleEndian(UInt16(value))
        } else if value <= UInt32.max {
            writeControlByte(.unsignedInt4, tag: tag)
            appendLittleEndian(UInt32(value))
        } else {
            writeControlByte(.unsignedInt8, tag: tag)
            appendLittleEndian(value)
        }
    }

    private mutating func encodeBool(tag: TLVTag, _ value: Bool) {
        writeControlByte(value ? .boolTrue : .boolFalse, tag: tag)
    }

    private mutating func encodeFloat(tag: TLVTag, _ value: Float) {
        writeControlByte(.float4, tag: tag)
        appendLittleEndian(value.bitPattern)
    }

    private mutating func encodeDouble(tag: TLVTag, _ value: Double) {
        writeControlByte(.float8, tag: tag)
        appendLittleEndian(value.bitPattern)
    }

    private mutating func encodeUTF8String(tag: TLVTag, _ value: String) {
        let bytes = Array(value.utf8)
        if bytes.count <= UInt8.max {
            writeControlByte(.utf8String1, tag: tag)
            buffer.append(UInt8(bytes.count))
        } else if bytes.count <= UInt16.max {
            writeControlByte(.utf8String2, tag: tag)
            appendLittleEndian(UInt16(bytes.count))
        } else {
            writeControlByte(.utf8String4, tag: tag)
            appendLittleEndian(UInt32(bytes.count))
        }
        buffer.append(contentsOf: bytes)
    }

    private mutating func encodeOctetString(tag: TLVTag, _ value: Data) {
        if value.count <= UInt8.max {
            writeControlByte(.octetString1, tag: tag)
            buffer.append(UInt8(value.count))
        } else if value.count <= UInt16.max {
            writeControlByte(.octetString2, tag: tag)
            appendLittleEndian(UInt16(value.count))
        } else {
            writeControlByte(.octetString4, tag: tag)
            appendLittleEndian(UInt32(value.count))
        }
        buffer.append(contentsOf: value)
    }

    private mutating func encodeNull(tag: TLVTag) {
        writeControlByte(.null, tag: tag)
    }

    private mutating func encodeStructure(tag: TLVTag, _ fields: [TLVElement.TLVField]) {
        writeControlByte(.structure, tag: tag)
        for field in fields {
            encode(tag: field.tag, field.value)
        }
        buffer.append(ElementType.endOfContainer.rawValue)
    }

    private mutating func encodeArray(tag: TLVTag, _ elements: [TLVElement]) {
        writeControlByte(.array, tag: tag)
        for element in elements {
            encode(tag: .anonymous, element)
        }
        buffer.append(ElementType.endOfContainer.rawValue)
    }

    private mutating func encodeList(tag: TLVTag, _ fields: [TLVElement.TLVField]) {
        writeControlByte(.list, tag: tag)
        for field in fields {
            encode(tag: field.tag, field.value)
        }
        buffer.append(ElementType.endOfContainer.rawValue)
    }
}
