// SetupCodeTests.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Testing
@testable import MatterTypes

@Suite("SetupCode Tests")
struct SetupCodeTests {

    // MARK: - Helpers

    /// Builds a manual code (11 or 21 digits) with a valid Verhoeff digit.
    private func manualCode(
        version: UInt32 = 0,
        discriminator: UInt32 = 3840,
        passcode: UInt32 = 20202021,
        vidPid: (UInt16, UInt16)? = nil
    ) -> String {
        let d1 = ((discriminator >> 10) & 0x3) | (vidPid != nil ? 4 : 0) | (version << 3)
        let chunk2 = ((discriminator >> 8) & 0x3) << 14 | (passcode & 0x3FFF)
        let chunk3 = passcode >> 14
        var digits = String(format: "%01d%05d%04d", d1, chunk2, chunk3)
        if let (vid, pid) = vidPid {
            digits += String(format: "%05d%05d", vid, pid)
        }
        return digits + String(Verhoeff.checkDigit(for: digits))
    }

    // MARK: - Manual Codes

    @Test("11-digit manual code parses passcode and short discriminator")
    func manual11() throws {
        let code = try SetupCode(parsing: "34970112332")
        #expect(code.passcode == 20202021)
        #expect(code.discriminator == .short(15))
        #expect(code.vendorID == nil)
        #expect(code.productID == nil)
        #expect(code.commissioningFlow == 0)
    }

    @Test("separators are ignored")
    func separators() throws {
        let a = try SetupCode(parsing: "3497-011-2332")
        let b = try SetupCode(parsing: "3497 011 2332")
        #expect(a == (try SetupCode(parsing: "34970112332")))
        #expect(b == a)
    }

    @Test("wrong check digit")
    func checkDigit() {
        #expect(throws: SetupCodeError.checkDigitMismatch) { try SetupCode(parsing: "34970112331") }
    }

    @Test("bad lengths, characters, empty")
    func lengthsAndCharacters() {
        #expect(throws: SetupCodeError.invalidLength(10)) { try SetupCode(parsing: "3497011233") }
        #expect(throws: SetupCodeError.invalidLength(12)) { try SetupCode(parsing: "349701123321") }
        #expect(throws: SetupCodeError.invalidCharacters) { try SetupCode(parsing: "3497011233a") }
        #expect(throws: SetupCodeError.empty) { try SetupCode(parsing: "  ") }
    }

    @Test("version bit set is unsupported")
    func version() {
        // First digit 8 = version bit (bit 3) set; valid check digit so the version check is reached.
        let text = manualCode(version: 1, discriminator: 0)
        #expect(text.hasPrefix("8"))
        #expect(throws: SetupCodeError.unsupportedVersion(8)) { try SetupCode(parsing: text) }
    }

    @Test("invalid passcodes are rejected once the check digit is valid")
    func invalidPasscodes() {
        for passcode: UInt32 in [0, 11111111, 12345678] {
            #expect(throws: SetupCodeError.invalidPasscode) {
                try SetupCode(parsing: manualCode(passcode: passcode))
            }
        }
    }

    @Test("21-digit manual code carries vendor and product")
    func manual21() throws {
        let text = manualCode(vidPid: (0xFFF1, 0x8000))
        #expect(text.count == 21)
        let code = try SetupCode(parsing: text)
        #expect(code.vendorID == 0xFFF1)
        #expect(code.productID == 0x8000)
        #expect(code.commissioningFlow == 2)
        #expect(code.passcode == 20202021)
        #expect(code.discriminator == .short(15))
    }

    @Test("vid/pid bit with an 11-digit code is a length error")
    func vidPidBitShortCode() {
        var digits = "4" + "34970112332".dropFirst().dropLast()
        digits += String(Verhoeff.checkDigit(for: digits))
        #expect(digits.count == 11)
        #expect(throws: SetupCodeError.invalidLength(11)) { try SetupCode(parsing: digits) }
    }

    @Test("21-digit code without the vid/pid bit is a length error")
    func noBitLongCode() {
        var digits = "3497011233" + "0000100001"
        digits += String(Verhoeff.checkDigit(for: digits))
        #expect(digits.count == 21)
        #expect(throws: SetupCodeError.invalidLength(21)) { try SetupCode(parsing: digits) }
    }

    // MARK: - Base38 / Verhoeff

    @Test("base38 round-trips random data of length 1 to 20")
    func base38RoundTrip() throws {
        var generator = SystemRandomNumberGenerator()
        for length in 1...20 {
            let data = Data((0..<length).map { _ in UInt8.random(in: 0...255, using: &generator) })
            #expect(try Base38.decode(Base38.encode(data)) == data)
        }
    }

    @Test("base38 group overflow is malformed")
    func base38Overflow() {
        // Five '.' characters decode to 38^5 - 1, far above 2^24.
        #expect {
            try Base38.decode(".....")
        } throws: { error in
            if case SetupCodeError.malformedQRCode = error { return true }
            return false
        }
    }

    @Test("verhoeff vector")
    func verhoeff() {
        #expect(Verhoeff.checkDigit(for: "3497011233") == 2)
        #expect(Verhoeff.validate("34970112332"))
        #expect(!Verhoeff.validate("34970112331"))
    }

    // MARK: - QR

    private func qrBytes(version: UInt64 = 0, passcode: UInt64 = 20202021, length: Int = 11) -> Data {
        // Fields are packed LSB-first; the passcode straddles the 64-bit boundary.
        var low: UInt64 = version
        low |= UInt64(0xFFF1) << 3
        low |= UInt64(0x8000) << 19
        low |= UInt64(4) << 37
        low |= UInt64(3840) << 45
        low |= (passcode & 0x7F) << 57
        let high = passcode >> 7
        var bytes = [UInt8]()
        for i in 0..<8 { bytes.append(UInt8(truncatingIfNeeded: low >> UInt64(i * 8))) }
        for i in 0..<8 { bytes.append(UInt8(truncatingIfNeeded: high >> UInt64(i * 8))) }
        return Data(bytes.prefix(length)) + Data(count: max(0, length - 16))
    }

    @Test("multi-device QR takes the first payload")
    func qrMulti() throws {
        let first = "MT:" + Base38.encode(qrBytes())
        let second = "MT:" + Base38.encode(qrBytes(passcode: 99999998))
        let code = try SetupCode(parsing: first + "*" + second.dropFirst(3))
        #expect(code.passcode == 20202021)
    }

    @Test("QR errors")
    func qrErrors() {
        #expect(throws: SetupCodeError.unsupportedVersion(1)) {
            try SetupCode(parsing: "MT:" + Base38.encode(qrBytes(version: 1)))
        }
        #expect {
            try SetupCode(parsing: "MT:" + Base38.encode(qrBytes(length: 10)))
        } throws: { error in
            if case SetupCodeError.malformedQRCode = error { return true }
            return false
        }
        #expect(throws: SetupCodeError.invalidPasscode) {
            try SetupCode(parsing: "MT:" + Base38.encode(qrBytes(passcode: 11111111)))
        }
        #expect(throws: SetupCodeError.invalidCharacters) {
            try SetupCode(parsing: "MT:ab")
        }
    }

    @Test("bytes beyond 88 bits are ignored")
    func qrTrailing() throws {
        let code = try SetupCode(parsing: "MT:" + Base38.encode(qrBytes(length: 14)))
        #expect(code.passcode == 20202021)
        #expect(code.discriminator == .long(3840))
    }

    // MARK: - Discriminator

    @Test("discriminator matching")
    func matching() {
        #expect(SetupCode.Discriminator.short(15).matches(3840))
        #expect(SetupCode.Discriminator.short(15).matches(0xFFF))
        #expect(!SetupCode.Discriminator.short(15).matches(0xEFF))
        #expect(SetupCode.Discriminator.long(3840).matches(3840))
        #expect(!SetupCode.Discriminator.long(3840).matches(3841))
    }

    // MARK: - Guards and hostile input

    private func withCheck(_ digits: String) -> String { digits + String(Verhoeff.checkDigit(for: digits)) }

    @Test("manual chunks that cannot encode a passcode are rejected")
    func chunkRanges() {
        // chunk2 = 99999 > 65535
        #expect(throws: SetupCodeError.invalidPasscode) { try SetupCode(parsing: withCheck("0999990001")) }
        // chunk3 = 9999 > 8191
        #expect(throws: SetupCodeError.invalidPasscode) { try SetupCode(parsing: withCheck("0000019999")) }
    }

    @Test("21-digit code with vendor or product above 65535 is rejected")
    func vidPidOverflow() {
        let head = "4" + "00001" + "0001" // valid passcode (1 | 1 << 14)
        #expect(throws: SetupCodeError.invalidLength(21)) { try SetupCode(parsing: withCheck(head + "99999" + "00001")) }
        #expect(throws: SetupCodeError.invalidLength(21)) { try SetupCode(parsing: withCheck(head + "00001" + "99999")) }
    }

    @Test("verhoeff ignores non-ASCII numerals and rejects empty input")
    func verhoeffASCII() {
        #expect(Verhoeff.checkDigit(for: "34970\u{2469}") == Verhoeff.checkDigit(for: "34970"))
        #expect(!Verhoeff.validate("34970112331\u{216B}"))
        #expect(Verhoeff.validate("34970112332\u{216B}"))
        #expect(!Verhoeff.validate(""))
    }

    @Test("base38 rejects tails of 1, 3 and 6 characters")
    func base38Tails() {
        for text in ["0", "000", "000000"] {
            #expect {
                try Base38.decode(text)
            } throws: { error in
                if case SetupCodeError.malformedQRCode = error { return true }
                return false
            }
        }
    }

    @Test("QR with non-zero trailing bytes still parses")
    func qrNonZeroTrailing() throws {
        var bytes = qrBytes(length: 11)
        bytes.append(contentsOf: [0xFF, 0xAA, 0x55])
        let code = try SetupCode(parsing: "MT:" + Base38.encode(bytes))
        #expect(code.passcode == 20202021)
    }

    private struct SeededGenerator: RandomNumberGenerator {
        var state: UInt64
        mutating func next() -> UInt64 {
            state &+= 0x9E3779B97F4A7C15
            var z = state
            z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
            z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
            return z ^ (z >> 31)
        }
    }

    @Test("hostile input never traps")
    func hostileInput() {
        var rng = SeededGenerator(state: 42)
        let pool = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-.*: \n\tabcxyz")
            + ["\u{216B}", "\u{2469}", "\u{0663}", "\u{FF11}", "\u{1F600}", "é", "\0"]
        func random(_ length: Int, from chars: [Character]) -> String {
            String((0..<length).map { _ in chars[Int.random(in: 0..<chars.count, using: &rng)] })
        }
        let digitChars = Array("0123456789")
        for _ in 0..<3000 {
            let length = Int.random(in: 0...40, using: &rng)
            let inputs = [
                random(length, from: pool),
                "MT:" + random(length, from: pool),
                random([11, 21].randomElement(using: &rng)!, from: digitChars),
                random(Int.random(in: 9...23, using: &rng), from: digitChars + ["-", " "]),
            ]
            for input in inputs {
                _ = try? SetupCode(parsing: input)
                _ = try? Base38.decode(input)
                _ = Verhoeff.checkDigit(for: input)
                _ = Verhoeff.validate(input)
            }
        }
    }
}
