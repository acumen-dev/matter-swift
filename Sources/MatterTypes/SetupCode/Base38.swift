// Base38.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

// MARK: - Base38

/// Matter's Base38 encoding for QR onboarding payloads (Matter Core §5.1.3.1).
///
/// 3 bytes map to 5 characters, 2 bytes to 4, and 1 byte to 2, least-significant first.
public enum Base38 {

    // 10 digits + 26 uppercase letters + '-' + '.'. No space.
    private static let alphabet = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-.".utf8)

    private static let values: [UInt8: UInt32] = {
        var table = [UInt8: UInt32]()
        for (i, c) in alphabet.enumerated() { table[c] = UInt32(i) }
        return table
    }()

    public static func encode(_ data: Data) -> String {
        var result = [UInt8]()
        var index = data.startIndex
        while index < data.endIndex {
            let remaining = data.distance(from: index, to: data.endIndex)
            let byteCount = min(remaining, 3)
            var value: UInt32 = 0
            for i in 0..<byteCount {
                value |= UInt32(data[data.index(index, offsetBy: i)]) << (8 * UInt32(i))
            }
            for _ in 0..<charCount(forBytes: byteCount) {
                result.append(alphabet[Int(value % 38)])
                value /= 38
            }
            index = data.index(index, offsetBy: byteCount)
        }
        return String(decoding: result, as: UTF8.self)
    }

    public static func decode(_ text: String) throws(SetupCodeError) -> Data {
        let chars = Array(text.utf8)
        guard chars.allSatisfy({ values[$0] != nil }) else { throw .invalidCharacters }
        var out = Data()
        var index = 0
        while index < chars.count {
            let n = min(chars.count - index, 5)
            guard let byteCount = byteCount(forChars: n) else {
                throw .malformedQRCode("Base38 group of \(n) characters")
            }
            var value: UInt64 = 0
            for i in (0..<n).reversed() {
                guard let digit = values[chars[index + i]] else { throw .invalidCharacters }
                value = value * 38 + UInt64(digit)
            }
            guard value < (UInt64(1) << (8 * UInt64(byteCount))) else {
                throw .malformedQRCode("Base38 group out of range")
            }
            for i in 0..<byteCount { out.append(UInt8((value >> (8 * UInt64(i))) & 0xFF)) }
            index += n
        }
        return out
    }

    private static func charCount(forBytes bytes: Int) -> Int {
        switch bytes {
        case 3: 5
        case 2: 4
        default: 2
        }
    }

    private static func byteCount(forChars chars: Int) -> Int? {
        switch chars {
        case 5: 3
        case 4: 2
        case 2: 1
        default: nil
        }
    }
}
