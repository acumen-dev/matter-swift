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
}
