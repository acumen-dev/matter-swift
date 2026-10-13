// SetupPayload.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

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

    private static func isValidPasscode(_ code: UInt32) -> Bool {
        SetupCode.isValidPasscode(code)
    }

    // MARK: - Bit-Packed Payload

    /// Packs all fields into an 88-bit (11-byte) buffer, LSB-first per field.
    ///
    /// Field layout (88 bits):
    /// ```
    /// [2:0]   version          (3 bits)
    /// [18:3]  vendorID         (16 bits)
    /// [34:19] productID        (16 bits)
    /// [36:35] commissioningFlow (2 bits)
    /// [44:37] rendezvousInfo   (8 bits)
    /// [56:45] discriminator    (12 bits)
    /// [83:57] setupPINCode     (27 bits)
    /// [87:84] padding          (4 bits, zero)
    /// ```
    private var packedBits: Data {
        var bits: UInt64 = 0
        var hi: UInt32 = 0   // bits 64–87

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

        // Pack into 11 bytes, little-endian. CHIP reads anything beyond 88 bits as optional TLV,
        // so a trailing zero byte makes it reject the payload.
        var data = Data(count: 11)
        for i in 0..<8 {
            data[i] = UInt8((bits >> (i * 8)) & 0xFF)
        }
        for i in 0..<3 {
            data[8 + i] = UInt8((hi >> (i * 8)) & 0xFF)
        }
        return data
    }

    // MARK: - QR Code

    /// The QR code payload string, e.g. `"MT:Y.GHY00 00KA0648G00"`.
    public var qrCodeString: String {
        "MT:" + Base38.encode(packedBits)
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
        let checksum = Verhoeff.checkDigit(for: digits)
        return digits + String(checksum)
    }
}
