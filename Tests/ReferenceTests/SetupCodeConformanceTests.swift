// SetupCodeConformanceTests.swift
// Copyright 2026 Monagle Pty Ltd
//
// Checks SetupPayload and SetupCode against chip-tool's `payload` commands.
// Skips silently when chip-tool has not been built (see `make ref-setup-tool`).

import Foundation
import Testing
import MatterDevice
import MatterTestSupport
import MatterTypes

@Suite("SetupCodeConformance Tests")
struct SetupCodeConformanceTests {

    // MARK: - chip-tool

    /// Runs chip-tool and returns its combined output. A watchdog terminates a hung process.
    private func run(_ binary: URL, _ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = binary
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        let watchdog = DispatchWorkItem { [process] in if process.isRunning { process.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + 120, execute: watchdog)
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        watchdog.cancel()
        // chip-tool colours its log lines even when piped; strip the escape sequences.
        return String(decoding: data, as: UTF8.self)
            .replacingOccurrences(of: "\u{1B}\\[[0-9;]*m", with: "", options: .regularExpression)
    }

    /// The value after `label:` on a line of chip-tool's `parse-setup-payload` output.
    private func field(_ label: String, in output: String) -> Int? {
        for line in output.split(separator: "\n") {
            guard let range = line.range(of: "\(label):") else { continue }
            let rest = line[range.upperBound...].split(separator: " ").first
            return rest.flatMap { Int($0) }
        }
        return nil
    }

    private func value(after label: String, in output: String) -> String? {
        for line in output.split(separator: "\n") {
            guard let range = line.range(of: label) else { continue }
            return line[range.upperBound...].trimmingCharacters(in: .whitespaces)
        }
        return nil
    }

    // MARK: - Cases

    private static let discriminators: [UInt16] = [0, 1, 3840, 4095]
    private static let passcodes: [UInt32] = [1, 20202021, 99999998]
    private static let vidPids: [(UInt16, UInt16)] = [(0, 0), (0xFFF1, 0x8000)]

    @Test("chip-tool parses our manual codes and QR codes")
    func chipToolParsesOurs() throws {
        guard let chipTool = RefImplBinary.find("chip-tool") else { return }
        for d in Self.discriminators {
            for p in Self.passcodes {
                for (vid, pid) in Self.vidPids {
                    let payload = try SetupPayload(
                        vendorID: vid, productID: pid, discriminator: d, passcode: p
                    )
                    let manual = try run(chipTool, ["payload", "parse-setup-payload", payload.manualPairingCode])
                    #expect(field("Passcode", in: manual) == Int(p), "manual \(d) \(p)")
                    #expect(field("Short discriminator", in: manual) == Int(d >> 8), "manual \(d) \(p)")

                    let qr = try run(chipTool, ["payload", "parse-setup-payload", payload.qrCodeString])
                    #expect(field("Passcode", in: qr) == Int(p), "qr \(d) \(p) \(vid)")
                    #expect(field("Long discriminator", in: qr) == Int(d), "qr \(d) \(p) \(vid)")
                    #expect(field("VendorID", in: qr) == Int(vid), "qr \(d) \(p) \(vid)")
                    #expect(field("ProductID", in: qr) == Int(pid), "qr \(d) \(p) \(vid)")
                }
            }
        }
    }

    @Test("SetupCode parses chip-tool generated codes")
    func weParseChipToolCodes() throws {
        guard let chipTool = RefImplBinary.find("chip-tool") else { return }
        for d in Self.discriminators {
            for p in Self.passcodes {
                for (vid, pid) in Self.vidPids {
                    let common = [
                        "--discriminator", "\(d)", "--setup-pin-code", "\(p)",
                        "--vendor-id", "\(vid)", "--product-id", "\(pid)",
                    ]
                    let qrOut = try run(chipTool, ["payload", "generate-qrcode", "--rendezvous", "4"] + common)
                    let qrText = try #require(value(after: "QR Code:", in: qrOut), "no QR in: \(qrOut)")
                    let qr = try SetupCode(parsing: qrText)
                    #expect(qr.passcode == p)
                    #expect(qr.discriminator == .long(d))
                    #expect(qr.vendorID == vid)
                    #expect(qr.productID == pid)
                    #expect(qr.rendezvousInformation == 4)
                    #expect(qr.commissioningFlow == 0)

                    let manualOut = try run(chipTool, ["payload", "generate-manualcode"] + common)
                    let manualText = try #require(value(after: "Manual Code:", in: manualOut), "no code in: \(manualOut)")
                    let manual = try SetupCode(parsing: manualText)
                    #expect(manual.passcode == p)
                    #expect(manual.discriminator == .short(UInt8(d >> 8)))
                    #expect(manual.commissioningFlow == 0)

                    // --commissioning-mode 1 yields the 21-digit form, which carries VID/PID.
                    let longOut = try run(chipTool, ["payload", "generate-manualcode", "--commissioning-mode", "1"] + common)
                    let longText = try #require(value(after: "Manual Code:", in: longOut), "no code in: \(longOut)")
                    let long = try SetupCode(parsing: longText)
                    #expect(longText.count == 21)
                    #expect(long.passcode == p)
                    #expect(long.discriminator == .short(UInt8(d >> 8)))
                    #expect(long.vendorID == vid)
                    #expect(long.productID == pid)
                    #expect(long.commissioningFlow == 2)
                }
            }
        }
    }
}
