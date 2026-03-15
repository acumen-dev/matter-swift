// SetupPayloadTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
@testable import MatterDevice

@Suite("SetupPayload Tests")
struct SetupPayloadTests {

    // MARK: - QR Code

    @Test("QR code starts with MT: prefix")
    func qrCodePrefix() throws {
        let payload = try SetupPayload(
            vendorID: 0xFFF1,
            productID: 0x8000,
            discriminator: 3840,
            passcode: 20202021
        )
        #expect(payload.qrCodeString.hasPrefix("MT:"))
    }

    @Test("QR code contains only valid Base38 characters")
    func qrCodeCharacters() throws {
        let payload = try SetupPayload(
            vendorID: 0xFFF1,
            productID: 0x8000,
            discriminator: 3840,
            passcode: 20202021
        )
        // Matter Base38 alphabet: digits, uppercase letters, '-', '.' — no space
        let validChars = Set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-.")
        let encoded = payload.qrCodeString.dropFirst(3) // strip "MT:"
        for ch in encoded {
            #expect(validChars.contains(ch), "Unexpected character: \(ch)")
        }
    }

    @Test("QR code has correct length for 12-byte payload")
    func qrCodeLength() throws {
        // 12 bytes = 4 groups of 3 bytes → 4×5 = 20 Base38 chars, plus "MT:" prefix
        let payload = try SetupPayload(
            vendorID: 0xFFF1,
            productID: 0x8000,
            discriminator: 3840,
            passcode: 20202021
        )
        // 12 bytes: 4 full 3-byte groups → 20 chars + "MT:"
        #expect(payload.qrCodeString.count == 23)
    }

    // MARK: - Manual Pairing Code

    @Test("Manual pairing code is exactly 11 digits")
    func manualCodeLength() throws {
        let payload = try SetupPayload(discriminator: 3840, passcode: 20202021)
        let code = payload.manualPairingCode
        #expect(code.count == 11)
        #expect(code.allSatisfy { $0.isNumber })
    }

    @Test("Manual pairing code matches connectedhomeip reference vector")
    func manualCodeReferenceVector() throws {
        // Reference vector from connectedhomeip test suite:
        // disc=3840=0xF00, passcode=20202021 → "34970112332"
        // chunk1 = (0xF00>>10)&0x3 = 3
        // chunk2 = ((0xF00>>8)&0x3)<<14 | (20202021&0x3FFF) = 3<<14|549 = 49701
        // chunk3 = 20202021>>14 = 1233
        // Verhoeff("3497011233") = 2
        let payload = try SetupPayload(discriminator: 3840, passcode: 20202021)
        #expect(payload.manualPairingCode == "34970112332")
    }

    @Test("Manual pairing code chunk encoding is correct")
    func manualCodeChunks() throws {
        // disc=3840=0xF00: chunk1=(0xF>>2)&0x3=3, chunk2=(0xF&0x3)<<14|549=49701, chunk3=1233
        let payload = try SetupPayload(discriminator: 3840, passcode: 20202021)
        let code = payload.manualPairingCode
        // Strip the Verhoeff checksum digit (last char) before decomposing
        let digits = String(code.dropLast())
        let c1 = UInt32(String(digits.prefix(1)))!
        let c2 = UInt32(String(digits.dropFirst(1).prefix(5)))!
        let c3 = UInt32(String(digits.dropFirst(6)))!

        let d = UInt32(3840)
        #expect(c1 == (d >> 10) & 0x3)
        #expect(c2 == ((d >> 8) & 0x3) << 14 | (20202021 & 0x3FFF))
        #expect(c3 == 20202021 >> 14)
    }

    // MARK: - Invalid Passcode Rejection

    @Test("Passcode 12345678 is rejected")
    func rejectPasscode12345678() {
        #expect(throws: SetupPayloadError.invalidPasscode) {
            try SetupPayload(discriminator: 100, passcode: 12345678)
        }
    }

    @Test("Passcode 00000000 (zero) is rejected")
    func rejectPasscodeZero() {
        #expect(throws: SetupPayloadError.invalidPasscode) {
            try SetupPayload(discriminator: 100, passcode: 0)
        }
    }

    @Test("Passcode 11111111 is rejected")
    func rejectRepeatingPasscode() {
        #expect(throws: SetupPayloadError.invalidPasscode) {
            try SetupPayload(discriminator: 100, passcode: 11111111)
        }
    }

    @Test("Passcode at or above 2^27 is rejected")
    func rejectPasscodeTooLarge() {
        #expect(throws: SetupPayloadError.invalidPasscode) {
            try SetupPayload(discriminator: 100, passcode: 0x8000000)
        }
    }

    // MARK: - Invalid Discriminator Rejection

    @Test("Discriminator above 4095 is rejected")
    func rejectDiscriminatorTooLarge() {
        #expect(throws: SetupPayloadError.invalidDiscriminator) {
            try SetupPayload(discriminator: 4096, passcode: 20202021)
        }
    }

    // MARK: - Field Storage

    @Test("All fields are stored correctly")
    func fieldStorage() throws {
        let payload = try SetupPayload(
            vendorID: 0xFFF1,
            productID: 0x8000,
            commissioningFlow: .userActionRequired,
            rendezvousInformation: [.ble, .onNetwork],
            discriminator: 512,
            passcode: 98765432
        )
        #expect(payload.version == 0)
        #expect(payload.vendorID == 0xFFF1)
        #expect(payload.productID == 0x8000)
        #expect(payload.commissioningFlow == .userActionRequired)
        #expect(payload.rendezvousInformation.contains(.ble))
        #expect(payload.rendezvousInformation.contains(.onNetwork))
        #expect(payload.discriminator == 512)
        #expect(payload.passcode == 98765432)
    }
}
