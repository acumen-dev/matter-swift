// SetupCode.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

// MARK: - SetupCodeError

public enum SetupCodeError: Error, Sendable, Equatable {
    case empty
    case invalidCharacters
    case invalidLength(Int)
    case checkDigitMismatch
    case unsupportedVersion(Int)
    case invalidPasscode
    case malformedQRCode(String)
}

// MARK: - SetupCode

/// A parsed onboarding payload (Matter Core §5.1). Manual codes carry only the 4-bit short discriminator.
public struct SetupCode: Sendable, Hashable {

    public enum Discriminator: Sendable, Hashable {
        /// 12 bits, from a QR code.
        case long(UInt16)
        /// The upper 4 bits of the 12-bit value, from a manual code.
        case short(UInt8)

        /// Whether a commissionable advertisement's full 12-bit discriminator (TXT "D") matches.
        public func matches(_ advertised: UInt16) -> Bool {
            switch self {
            case .long(let d): return d == advertised & 0xFFF
            case .short(let s): return UInt8((advertised >> 8) & 0xF) == s
            }
        }
    }

    public var passcode: UInt32
    public var discriminator: Discriminator
    /// From a QR code, or a 21-digit manual code.
    public var vendorID: UInt16?
    public var productID: UInt16?
    /// From a QR code. Manual codes imply it, as chip-tool reports: 0 (standard) for 11 digits, 2 (custom) for 21.
    public var commissioningFlow: UInt8?
    /// QR codes only.
    public var rendezvousInformation: UInt8?

    // MARK: - Passcode Validation

    private static let invalidPasscodes: Set<UInt32> = [
        00000000, 11111111, 22222222, 33333333, 44444444,
        55555555, 66666666, 77777777, 88888888, 99999999,
        12345678, 87654321,
    ]

    /// Non-zero, below 2^27, and not one of the passcodes Matter forbids.
    public static func isValidPasscode(_ code: UInt32) -> Bool {
        guard code > 0, code < 0x8000000 else { return false }
        return !invalidPasscodes.contains(code)
    }

    // MARK: - Parsing

    /// Accepts a manual code (11 or 21 digits; spaces and '-' ignored) or a QR payload ("MT:…").
    ///
    /// Error mapping for out-of-range fields: a manual-code chunk that cannot encode a passcode
    /// (chunk2 > 65535, chunk3 > 8191) is `.invalidPasscode`; a 21-digit code whose vendor or
    /// product ID exceeds 65535 is `.invalidLength` (the layout is malformed). `.malformedQRCode`
    /// is reserved for QR payloads.
    public init(parsing text: String) throws(SetupCodeError) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw .empty }
        if trimmed.hasPrefix("MT:") {
            self = try Self.parseQR(String(trimmed.dropFirst(3)))
        } else {
            self = try Self.parseManual(trimmed)
        }
    }

    private init(
        passcode: UInt32, discriminator: Discriminator,
        vendorID: UInt16? = nil, productID: UInt16? = nil,
        commissioningFlow: UInt8? = nil, rendezvousInformation: UInt8? = nil
    ) {
        self.passcode = passcode
        self.discriminator = discriminator
        self.vendorID = vendorID
        self.productID = productID
        self.commissioningFlow = commissioningFlow
        self.rendezvousInformation = rendezvousInformation
    }

    // Digits: d1 (1) | chunk2 (5) | chunk3 (4) | [vid (5) | pid (5)] | check (1)
    private static func parseManual(_ text: String) throws(SetupCodeError) -> SetupCode {
        let digits = text.filter { $0 != " " && $0 != "-" }
        guard !digits.isEmpty else { throw .empty }
        guard digits.allSatisfy({ $0.isASCII && $0.isNumber }) else { throw .invalidCharacters }
        guard digits.count == 11 || digits.count == 21 else { throw .invalidLength(digits.count) }
        guard Verhoeff.validate(digits) else { throw .checkDigitMismatch }

        let values = digits.compactMap(\.wholeNumberValue)
        func number(_ range: Range<Int>) -> Int { values[range].reduce(0) { $0 * 10 + $1 } }

        let d1 = values[0]
        guard d1 & 0x8 == 0 else { throw .unsupportedVersion(d1) }
        let hasVidPid = d1 & 0x4 != 0
        guard hasVidPid == (digits.count == 21) else { throw .invalidLength(digits.count) }

        let chunk2 = number(1..<6)
        let chunk3 = number(6..<10)
        guard chunk2 <= 0xFFFF, chunk3 <= 0x1FFF else { throw .invalidPasscode }
        let short = UInt8((d1 & 0x3) << 2) | UInt8(chunk2 >> 14)
        let passcode = UInt32(chunk2 & 0x3FFF) | (UInt32(chunk3) << 14)
        guard isValidPasscode(passcode) else { throw .invalidPasscode }

        var code = SetupCode(passcode: passcode, discriminator: .short(short), commissioningFlow: hasVidPid ? 2 : 0)
        if hasVidPid {
            let vid = number(10..<15), pid = number(15..<20)
            guard vid <= 0xFFFF, pid <= 0xFFFF else { throw .invalidLength(digits.count) }
            code.vendorID = UInt16(vid)
            code.productID = UInt16(pid)
        }
        return code
    }

    // Base38 body, read LSB-first: version 3, VID 16, PID 16, flow 2, rendezvous 8, discriminator 12, passcode 27, padding 4.
    private static func parseQR(_ body: String) throws(SetupCodeError) -> SetupCode {
        // Multiple payloads are joined with '*'; the first is used.
        let first = body.split(separator: "*", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? ""
        let bytes = try Base38.decode(first)
        guard bytes.count >= 11 else {
            throw .malformedQRCode("payload is \(bytes.count) bytes, expected at least 11")
        }
        let base = bytes.startIndex
        var cursor = 0
        func read(_ width: Int) -> UInt64 {
            var value: UInt64 = 0
            for i in 0..<width {
                let bit = cursor + i
                let byte = bytes[base + bit / 8]
                value |= UInt64((byte >> UInt8(bit % 8)) & 1) << UInt64(i)
            }
            cursor += width
            return value
        }
        let version = read(3)
        let vid = read(16), pid = read(16)
        let flow = read(2), rendezvous = read(8)
        let discriminator = read(12)
        let passcode = UInt32(read(27))
        guard version == 0 else { throw .unsupportedVersion(Int(version)) }
        guard isValidPasscode(passcode) else { throw .invalidPasscode }
        return SetupCode(
            passcode: passcode, discriminator: .long(UInt16(discriminator)),
            vendorID: UInt16(vid), productID: UInt16(pid),
            commissioningFlow: UInt8(flow), rendezvousInformation: UInt8(rendezvous)
        )
    }
}
