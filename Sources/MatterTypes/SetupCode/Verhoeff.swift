// Verhoeff.swift
// Copyright 2026 Monagle Pty Ltd

// MARK: - Verhoeff

/// The Verhoeff check-digit algorithm used by Matter manual pairing codes.
public enum Verhoeff {

    // Multiplication table for the dihedral group D5.
    private static let d: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ]

    // Permutation table.
    private static let p: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ]

    // Inverse table for D5.
    private static let inv = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]

    /// ASCII digits 0-9 of `text`; everything else (including non-ASCII numerals) is ignored.
    private static func asciiDigits(_ text: String) -> [Int] {
        text.utf8.compactMap { (0x30...0x39).contains($0) ? Int($0 - 0x30) : nil }
    }

    /// The check digit to append to `digits` (ASCII digits only; other characters are ignored).
    public static func checkDigit(for digits: String) -> Int {
        // Positions start at 1, reserving position 0 for the appended check digit.
        var c = 0
        for (i, digit) in asciiDigits(digits).reversed().enumerated() {
            c = d[c][p[(i + 1) % 8][digit]]
        }
        return inv[c]
    }

    /// Whether the last digit of `digitsWithCheck` is the correct check digit for the rest.
    public static func validate(_ digitsWithCheck: String) -> Bool {
        let all = asciiDigits(digitsWithCheck)
        guard !all.isEmpty else { return false }
        var c = 0
        for (i, digit) in all.reversed().enumerated() {
            c = d[c][p[i % 8][digit]]
        }
        return c == 0
    }
}
