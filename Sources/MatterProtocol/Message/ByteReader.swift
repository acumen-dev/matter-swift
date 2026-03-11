// ByteReader.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

/// Sequential byte reader for parsing wire-format data.
///
/// All multi-byte reads are little-endian (Matter wire format convention).
struct ByteReader: Sendable {
    private let data: Data
    private(set) var offset: Int

    init(data: Data) {
        self.data = data
        self.offset = 0
    }

    /// The remaining unread bytes.
    var remaining: Data.SubSequence {
        data[offset...]
    }

    /// Whether there are more bytes to read.
    var hasRemaining: Bool {
        offset < data.count
    }

    /// Number of bytes remaining.
    var remainingCount: Int {
        data.count - offset
    }

    mutating func readUInt8() throws -> UInt8 {
        guard offset < data.count else {
            throw MessageError.unexpectedEndOfData
        }
        let value = data[offset]
        offset += 1
        return value
    }

    mutating func readUInt16() throws -> UInt16 {
        guard offset + 2 <= data.count else {
            throw MessageError.unexpectedEndOfData
        }
        let value = UInt16(data[offset]) | (UInt16(data[offset + 1]) << 8)
        offset += 2
        return value
    }

    mutating func readUInt32() throws -> UInt32 {
        guard offset + 4 <= data.count else {
            throw MessageError.unexpectedEndOfData
        }
        var value: UInt32 = 0
        for i in 0..<4 {
            value |= UInt32(data[offset + i]) << (i * 8)
        }
        offset += 4
        return value
    }

    mutating func readUInt64() throws -> UInt64 {
        guard offset + 8 <= data.count else {
            throw MessageError.unexpectedEndOfData
        }
        var value: UInt64 = 0
        for i in 0..<8 {
            value |= UInt64(data[offset + i]) << (i * 8)
        }
        offset += 8
        return value
    }

    mutating func readBytes(_ count: Int) throws -> Data {
        guard offset + count <= data.count else {
            throw MessageError.unexpectedEndOfData
        }
        let bytes = data[offset..<(offset + count)]
        offset += count
        return Data(bytes)
    }

    mutating func skip(_ count: Int) throws {
        guard offset + count <= data.count else {
            throw MessageError.unexpectedEndOfData
        }
        offset += count
    }
}

// MARK: - Data Writing Extensions

extension Data {
    mutating func appendLittleEndian(_ value: UInt16) {
        append(UInt8(value & 0xFF))
        append(UInt8((value >> 8) & 0xFF))
    }

    mutating func appendLittleEndian(_ value: UInt32) {
        append(UInt8(value & 0xFF))
        append(UInt8((value >> 8) & 0xFF))
        append(UInt8((value >> 16) & 0xFF))
        append(UInt8((value >> 24) & 0xFF))
    }

    mutating func appendLittleEndian(_ value: UInt64) {
        for i in 0..<8 {
            append(UInt8((value >> (i * 8)) & 0xFF))
        }
    }
}
