// SetupPayload.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

// MARK: - Errors

/// Errors thrown when constructing a ``SetupPayload``.
public enum SetupPayloadError: Error, Sendable {
    case invalidPasscode
    case invalidDiscriminator
}

// MARK: - SetupPayload

/// A Matter commissioning setup payload.
///
/// Encodes all fields required for device commissioning and can produce both
/// the QR code string (`MT:...`) and the 11-digit manual pairing code.
///
/// ```swift
/// let payload = try SetupPayload(
///     vendorID: 0xFFF1,
///     productID: 0x8000,
///     discriminator: 3840,
///     passcode: 20202021
/// )
/// print(payload.qrCodeString)       // MT:Y.GHY00 00KA0648G00
/// print(payload.manualPairingCode)  // 34970112332
/// ```
public struct SetupPayload: Sendable {

    // MARK: - Nested Types

    /// The commissioning flow type for this device.
    public enum CommissioningFlow: UInt8, Sendable {
        case standard = 0
        case userActionRequired = 1
        case custom = 2
    }

    /// The transport methods over which the device can be commissioned.
    public struct RendezvousInformation: OptionSet, Sendable {
        public let rawValue: UInt8
        public init(rawValue: UInt8) { self.rawValue = rawValue }

        public static let softAP    = RendezvousInformation(rawValue: 0x01)
        public static let ble       = RendezvousInformation(rawValue: 0x02)
        public static let onNetwork = RendezvousInformation(rawValue: 0x04)
    }

    // MARK: - Properties

    public let version: UInt8
    public let vendorID: UInt16
    public let productID: UInt16
    public let commissioningFlow: CommissioningFlow
    public let rendezvousInformation: RendezvousInformation
    /// 12-bit discriminator, 0–4095.
    public let discriminator: UInt16
    /// 27-bit setup passcode.
    public let passcode: UInt32

    // MARK: - Initialiser

    public init(
        vendorID: UInt16 = 0,
        productID: UInt16 = 0,
        commissioningFlow: CommissioningFlow = .standard,
        rendezvousInformation: RendezvousInformation = .onNetwork,
        discriminator: UInt16,
        passcode: UInt32
    ) throws {
        guard discriminator <= 0xFFF else {
            throw SetupPayloadError.invalidDiscriminator
        }
        guard Self.isValidPasscode(passcode) else {
            throw SetupPayloadError.invalidPasscode
        }
        self.version = 0
        self.vendorID = vendorID
        self.productID = productID
        self.commissioningFlow = commissioningFlow
        self.rendezvousInformation = rendezvousInformation
        self.discriminator = discriminator
        self.passcode = passcode
    }

    // MARK: - Passcode Validation

    private static let invalidPasscodes: Set<UInt32> = [
        00000000, 11111111, 22222222, 33333333, 44444444,
        55555555, 66666666, 77777777, 88888888, 99999999,
        12345678, 87654321,
    ]

    private static func isValidPasscode(_ code: UInt32) -> Bool {
        guard code > 0, code < 0x8000000 else { return false }
        return !invalidPasscodes.contains(code)
    }

    // MARK: - Bit-Packed Payload

    /// Packs all fields into a 96-bit (12-byte) buffer, LSB-first per field.
    ///
    /// Field layout (88 bits used, 8-bit zero-pad appended):
    /// ```
    /// [2:0]   version          (3 bits)
    /// [18:3]  vendorID         (16 bits)
    /// [34:19] productID        (16 bits)
    /// [36:35] commissioningFlow (2 bits)
    /// [44:37] rendezvousInfo   (8 bits)
    /// [56:45] discriminator    (12 bits)
    /// [83:57] setupPINCode     (27 bits)
    /// [87:84] padding          (4 bits, zero)
    /// [95:88] padding          (8 bits, zero)
    /// ```
    private var packedBits: Data {
        var bits: UInt64 = 0
        var hi: UInt32 = 0   // bits 64–95

        var cursor = 0

        // version (3 bits)
        bits |= UInt64(version & 0x7) << cursor; cursor += 3
        // vendorID (16 bits)
        bits |= UInt64(vendorID) << cursor; cursor += 16
        // productID (16 bits)
        bits |= UInt64(productID) << cursor; cursor += 16
        // commissioningFlow (2 bits)
        bits |= UInt64(commissioningFlow.rawValue & 0x3) << cursor; cursor += 2
        // rendezvousInformation (8 bits)
        bits |= UInt64(rendezvousInformation.rawValue) << cursor; cursor += 8
        // discriminator (12 bits)
        bits |= UInt64(discriminator & 0xFFF) << cursor; cursor += 12
        // passcode (27 bits) — cursor is 57 here, so it spans bits 57–83
        // The low 7 bits of passcode fit in bits 57–63 of `bits`
        let passcodeLow = UInt64(passcode) & 0x7F   // bits 57–63: 7 bits
        let passcodeHi  = UInt64(passcode) >> 7      // bits 64–83: 20 bits
        bits |= passcodeLow << cursor  // cursor == 57
        hi   |= UInt32(passcodeHi)     // hi bits 0–19 = passcode bits 7–26
        // padding 4 bits at bits 84–87 → hi bits 20–23 (already zero)
        // padding 8 bits at bits 88–95 → hi bits 24–31 (already zero)

        // Pack into 12 bytes, little-endian
        var data = Data(count: 12)
        for i in 0..<8 {
            data[i] = UInt8((bits >> (i * 8)) & 0xFF)
        }
        for i in 0..<4 {
            data[8 + i] = UInt8((hi >> (i * 8)) & 0xFF)
        }
        return data
    }

    // MARK: - QR Code

    // Matter Base38 alphabet: 10 digits + 26 uppercase letters + '-' + '.' = 38 chars exactly.
    // No space — the space sometimes seen in reference QR strings is a display separator only.
    private static let base38Alphabet = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-.")

    /// Encodes `data` using Matter's Base38 scheme.
    ///
    /// - 3 bytes → 5 characters
    /// - 2 bytes → 4 characters
    /// - 1 byte  → 2 characters
    private static func base38Encode(_ data: Data) -> String {
        var result = ""
        var index = 0
        while index < data.count {
            let remaining = data.count - index
            let (value, outLen): (UInt32, Int)
            if remaining >= 3 {
                value = UInt32(data[index]) | UInt32(data[index + 1]) << 8 | UInt32(data[index + 2]) << 16
                outLen = 5
                index += 3
            } else if remaining == 2 {
                value = UInt32(data[index]) | UInt32(data[index + 1]) << 8
                outLen = 4
                index += 2
            } else {
                value = UInt32(data[index])
                outLen = 2
                index += 1
            }
            var v = value
            for _ in 0..<outLen {
                result.append(base38Alphabet[Int(v % 38)])
                v /= 38
            }
        }
        return result
    }

    /// The QR code payload string, e.g. `"MT:Y.GHY00 00KA0648G00"`.
    public var qrCodeString: String {
        "MT:" + Self.base38Encode(packedBits)
    }

    // MARK: - Manual Pairing Code

    /// The 11-digit manual pairing code per Matter spec §5.1.4.1.
    ///
    /// Format: chunk1 (1 digit) + chunk2 (5 digits) + chunk3 (4 digits) + Verhoeff checksum (1 digit)
    ///
    /// - `chunk1`: top 2 bits of discriminator: `(discriminator >> 10) & 0x3`
    /// - `chunk2`: next 2 discriminator bits + low 14 passcode bits:
    ///             `((discriminator >> 8) & 0x3) << 14 | (passcode & 0x3FFF)`
    /// - `chunk3`: high 13 passcode bits: `passcode >> 14`
    public var manualPairingCode: String {
        let d = UInt32(discriminator)
        let chunk1 = (d >> 10) & 0x3
        let chunk2 = ((d >> 8) & 0x3) << 14 | (passcode & 0x3FFF)
        let chunk3 = passcode >> 14
        let digits = String(format: "%01d%05d%04d", chunk1, chunk2, chunk3)
        let checksum = Self.verhoeffChecksum(digits)
        return digits + String(checksum)
    }

    // MARK: - Verhoeff Checksum

    /// Computes the Verhoeff checksum digit for the given decimal string.
    private static func verhoeffChecksum(_ string: String) -> Int {
        // Multiplication table for dihedral group D5
        let d: [[Int]] = [
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
        // Permutation table
        let p: [[Int]] = [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
            [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
            [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
            [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
            [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
            [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
            [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
        ]
        // Inverse table
        let inv = [0, 4, 3, 2, 1, 9, 8, 7, 6, 5]

        // Digits are processed right-to-left starting at position 1 (not 0),
        // reserving position 0 for the check digit that will be appended.
        var c = 0
        let digits = string.compactMap { $0.wholeNumberValue }
        for (i, digit) in digits.reversed().enumerated() {
            c = d[c][p[(i + 1) % 8][digit]]
        }
        return inv[c]
    }
}
