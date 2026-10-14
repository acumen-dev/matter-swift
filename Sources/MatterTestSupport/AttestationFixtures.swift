// AttestationFixtures.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

// MARK: - AttestationFixtures

/// Device attestation fixtures copied from connectedhomeip v1.4.0.0 into
/// `Tests/Fixtures/Attestation`, relative to the package root.
///
/// `Tools/Attestation/fetch-chip-fixtures.sh` reproduces the copy, and
/// `Tests/Fixtures/Attestation/SOURCES.md` records each file's upstream path and SHA-256.
public enum AttestationFixtures {

    /// The package root, derived from this file's own location (Sources/MatterTestSupport/).
    private static let packageRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()  // MatterTestSupport/
        .deletingLastPathComponent()  // Sources/
        .deletingLastPathComponent()  // package root

    /// The fixture directory, `Tests/Fixtures/Attestation`.
    public static let directory = packageRoot.appendingPathComponent("Tests/Fixtures/Attestation")

    // MARK: - Development Chain (VID 0xFFF1, PID 0x8000)

    /// The development DAC for VID 0xFFF1 / PID 0x8000 (DER). This is the DAC that
    /// connectedhomeip's example apps present by default.
    public static var devDAC: Data {
        get throws { try load("dev/Matter-Development-DAC-FFF1-8000-Cert.der") }
    }

    /// The private key of ``devDAC`` (DER, SEC1 `ECPrivateKey`, P-256).
    public static var devDACPrivateKey: Data {
        get throws { try load("dev/Matter-Development-DAC-FFF1-8000-Key.der") }
    }

    /// The development PAI for VID 0xFFF1 that issues ``devDAC`` (DER).
    public static var devPAI: Data {
        get throws { try load("dev/Matter-Development-PAI-FFF1-noPID-Cert.der") }
    }

    /// The test PAA for VID 0xFFF1 that issues ``devPAI`` (DER, self-signed).
    public static var testPAA: Data {
        get throws { try load("dev/Chip-Test-PAA-FFF1-Cert.der") }
    }

    // MARK: - Certification Declarations

    /// A test Certification Declaration (CMS SignedData, DER) for VID 0xFFF1 / PID 0x8000,
    /// signed by ``testCDSigningCert``.
    public static var testCD: Data {
        get throws { try load("cd/Test-CD-FFF1-8000.der") }
    }

    /// The "Matter Test CD Signing Authority" certificate (DER, self-signed) that signs ``testCD``.
    public static var testCDSigningCert: Data {
        get throws { try load("cd/Chip-Test-CD-Cert.der") }
    }

    /// The private key of ``testCDSigningCert`` (PEM, SEC1 `EC PRIVATE KEY`, P-256).
    public static var testCDSigningKey: Data {
        get throws { try load("cd/Chip-Test-CD-Signing-Key.pem") }
    }

    /// The Certification Declaration that connectedhomeip's example apps present for VID 0xFFF1
    /// (CMS SignedData, DER). It lists VID 0xFFF1 with PIDs 0x8000…0x8063 and is signed by
    /// CSA "Certification Declaration Signing Key 001", the first of ``productionCDSigningCerts``.
    public static var exampleCD: Data {
        get throws { try load("cd/Example-CD-FFF1.der") }
    }

    /// The five CSA Certification Declaration signing certificates (DER), keys 001 to 005 in order.
    public static var productionCDSigningCerts: [Data] {
        get throws {
            try (1...5).map { try load("cd/CSA_Matter_CD_Signing_Key_00\($0).cert.der") }
        }
    }

    // MARK: - Commissioner DUT Vectors

    /// connectedhomeip's commissioner DUT attestation vectors, sorted by directory name.
    ///
    /// Despite the name, the set holds both failure and success cases: see
    /// ``NegativeCaseVector/isSuccessCase``.
    public static var negativeCases: [(name: String, vector: NegativeCaseVector)] {
        get throws {
            try requireDirectory()
            let root = directory.appendingPathComponent("commissioner_dut")
            let names = try FileManager.default.contentsOfDirectory(atPath: root.path)
                .filter { !$0.hasPrefix(".") }
                .sorted()
            let decoder = JSONDecoder()
            return try names.map { name in
                let json = try Data(contentsOf: root.appendingPathComponent("\(name)/test_case_vector.json"))
                return (name, try decoder.decode(NegativeCaseVector.self, from: json))
            }
        }
    }

    // MARK: - Loading

    private static func load(_ relativePath: String) throws -> Data {
        try requireDirectory()
        return try Data(contentsOf: directory.appendingPathComponent(relativePath))
    }

    private static func requireDirectory() throws {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: directory.path, isDirectory: &isDirectory),
              isDirectory.boolValue
        else {
            throw AttestationFixtureError.missingDirectory(directory.path)
        }
    }
}

// MARK: - AttestationFixtureError

/// Why an attestation fixture could not be loaded.
public enum AttestationFixtureError: Error, CustomStringConvertible {

    /// The fixture directory does not exist.
    case missingDirectory(String)

    public var description: String {
        switch self {
        case .missingDirectory(let path):
            "attestation fixtures not found at \(path); run Tools/Attestation/fetch-chip-fixtures.sh"
        }
    }
}

// MARK: - NegativeCaseVector

/// One connectedhomeip commissioner DUT vector (`test_case_vector.json`).
public struct NegativeCaseVector: Decodable, Sendable, Equatable {

    /// The upstream description of the case.
    public let description: String

    /// Whether a commissioner should accept this attestation.
    public let isSuccessCase: Bool

    /// The product ID the device reports in its Basic Information cluster.
    public let basicInfoPID: UInt16

    /// The DAC (DER).
    public let dacCert: Data

    /// The PAI (DER).
    public let paiCert: Data

    /// The Certification Declaration (CMS SignedData, DER).
    public let certificationDeclaration: Data

    /// The DAC private key scalar (32 bytes).
    public let dacPrivateKey: Data

    /// The DAC public key (65-byte uncompressed point).
    public let dacPublicKey: Data

    private enum CodingKeys: String, CodingKey {
        case description
        case isSuccessCase = "is_success_case"
        case basicInfoPID = "basic_info_pid"
        case dacCert = "dac_cert"
        case paiCert = "pai_cert"
        case certificationDeclaration = "certification_declaration"
        case dacPrivateKey = "dac_private_key"
        case dacPublicKey = "dac_public_key"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        description = try container.decode(String.self, forKey: .description)
        // Upstream encodes the flag as the string "true" or "false".
        switch try container.decode(String.self, forKey: .isSuccessCase) {
        case "true": isSuccessCase = true
        case "false": isSuccessCase = false
        case let other:
            throw DecodingError.dataCorruptedError(
                forKey: .isSuccessCase, in: container, debugDescription: "expected \"true\" or \"false\", got \(other)")
        }
        basicInfoPID = try container.decode(UInt16.self, forKey: .basicInfoPID)
        dacCert = try Self.hex(container, .dacCert)
        paiCert = try Self.hex(container, .paiCert)
        certificationDeclaration = try Self.hex(container, .certificationDeclaration)
        dacPrivateKey = try Self.hex(container, .dacPrivateKey)
        dacPublicKey = try Self.hex(container, .dacPublicKey)
    }

    private static func hex(_ container: KeyedDecodingContainer<CodingKeys>, _ key: CodingKeys) throws -> Data {
        let string = try container.decode(String.self, forKey: key)
        let digits = Array(string.utf8)
        guard digits.count % 2 == 0 else {
            throw DecodingError.dataCorruptedError(forKey: key, in: container, debugDescription: "odd-length hex")
        }
        var bytes = [UInt8]()
        bytes.reserveCapacity(digits.count / 2)
        for index in stride(from: 0, to: digits.count, by: 2) {
            guard let high = nibble(digits[index]), let low = nibble(digits[index + 1]) else {
                throw DecodingError.dataCorruptedError(forKey: key, in: container, debugDescription: "non-hex digit")
            }
            bytes.append(high << 4 | low)
        }
        return Data(bytes)
    }

    private static func nibble(_ ascii: UInt8) -> UInt8? {
        switch ascii {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): ascii - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): ascii - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"): ascii - UInt8(ascii: "A") + 10
        default: nil
        }
    }
}
