// ChipCertRunner.swift
// Copyright 2026 Monagle Pty Ltd
//
// Wrapper for invoking the chip-cert reference implementation binary.
// chip-cert is part of the connectedhomeip SDK and must be built first via:
//   make ref-setup-cert
//
// Tests that use this runner skip gracefully when chip-cert is not available.

import Foundation

// MARK: - ChipCertRunner

/// Invokes the chip-cert binary from the connectedhomeip reference implementation.
///
/// Finds the binary relative to the package root using `#filePath`. Tests that
/// call this runner should call `findBinary()` first and skip if nil.
struct ChipCertRunner: Sendable {

    // MARK: - Properties

    /// Absolute path to the chip-cert binary.
    let binaryPath: String

    // MARK: - Init

    /// Create a runner pointing at the chip-cert binary.
    ///
    /// Returns `nil` if the binary does not exist. Tests should skip when this
    /// returns `nil` to avoid failures on machines that haven't run `setup.sh`.
    static func findBinary(sourceFile: String = #filePath) -> ChipCertRunner? {
        let url = URL(fileURLWithPath: sourceFile)
            .deletingLastPathComponent()  // ReferenceTests/
            .deletingLastPathComponent()  // Tests/
            .deletingLastPathComponent()  // package root
        let binaryURL = url
            .appendingPathComponent("Tools/RefImpl/bin/chip-cert")
        let path = binaryURL.path
        guard FileManager.default.isExecutableFile(atPath: path) else {
            return nil
        }
        return ChipCertRunner(binaryPath: path)
    }

    // MARK: - Result

    struct RunResult: Sendable {
        let exitCode: Int32
        let stdout: String
        let stderr: String

        var succeeded: Bool { exitCode == 0 }
    }

    // MARK: - Run

    /// Run chip-cert with the given arguments.
    func run(_ arguments: [String]) throws -> RunResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: binaryPath)
        process.arguments = arguments

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        try process.run()
        process.waitUntilExit()

        let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()

        return RunResult(
            exitCode: process.terminationStatus,
            stdout: String(data: stdoutData, encoding: .utf8) ?? "",
            stderr: String(data: stderrData, encoding: .utf8) ?? ""
        )
    }

    // MARK: - Temp Directory Helper

    /// Create a temporary directory, run the body, then clean up.
    private func withTempDir<T>(_ body: (URL) throws -> T) throws -> T {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("chip-cert-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        return try body(dir)
    }

    // MARK: - Certificate Validation

    // chip-cert validate-cert CLI (v1.4):
    //   chip-cert validate-cert [options] <cert-file>
    //     <cert-file>              Certificate to validate (positional)
    //     -t, --trusted-cert       Trusted root (RCAC)
    //     -c, --cert               Untrusted intermediate (ICAC)

    /// Validate a single self-signed root certificate (RCAC).
    func validateRCAC(_ rcacData: Data) throws -> RunResult {
        try withTempDir { dir in
            let rcacFile = dir.appendingPathComponent("rcac.chip")
            try rcacData.write(to: rcacFile)
            // Self-signed: the cert is both the subject and the trust anchor
            return try run(["validate-cert", "-t", rcacFile.path, rcacFile.path])
        }
    }

    /// Validate a NOC against an RCAC (no ICAC).
    func validateNOC(_ nocData: Data, rcac rcacData: Data) throws -> RunResult {
        try withTempDir { dir in
            let nocFile = dir.appendingPathComponent("noc.chip")
            let rcacFile = dir.appendingPathComponent("rcac.chip")
            try nocData.write(to: nocFile)
            try rcacData.write(to: rcacFile)
            return try run(["validate-cert", "-t", rcacFile.path, nocFile.path])
        }
    }

    /// Validate a NOC with ICAC against an RCAC.
    func validateNOC(_ nocData: Data, icac icacData: Data, rcac rcacData: Data) throws -> RunResult {
        try withTempDir { dir in
            let nocFile = dir.appendingPathComponent("noc.chip")
            let icacFile = dir.appendingPathComponent("icac.chip")
            let rcacFile = dir.appendingPathComponent("rcac.chip")
            try nocData.write(to: nocFile)
            try icacData.write(to: icacFile)
            try rcacData.write(to: rcacFile)
            return try run(["validate-cert", "-t", rcacFile.path, "-c", icacFile.path, nocFile.path])
        }
    }

    // MARK: - Certificate Conversion

    // chip-cert convert-cert CLI (v1.4):
    //   chip-cert convert-cert [options] <in-file> <out-file>
    //     -d, --x509-der           Output in X.509 DER format

    /// Convert a Matter TLV certificate to X.509 DER format.
    func convertTLVtoDER(_ tlvData: Data) throws -> Data {
        try withTempDir { dir in
            let inputFile = dir.appendingPathComponent("cert.chip")
            let outputFile = dir.appendingPathComponent("cert.der")
            try tlvData.write(to: inputFile)
            let result = try run(["convert-cert", "-d", inputFile.path, outputFile.path])
            guard result.succeeded else {
                throw ChipCertError.conversionFailed(result.stderr)
            }
            return try Data(contentsOf: outputFile)
        }
    }

    /// Convert an X.509 DER/PEM certificate to Matter TLV format.
    func convertToTLV(_ certData: Data, inputFormat: String = "x509-der") throws -> Data {
        try withTempDir { dir in
            let inputFile = dir.appendingPathComponent("cert.der")
            let outputFile = dir.appendingPathComponent("cert.chip")
            try certData.write(to: inputFile)
            let result = try run(["convert-cert", "--x509-\(inputFormat == "x509-pem" ? "pem" : "der")", inputFile.path, outputFile.path])
            guard result.succeeded else {
                throw ChipCertError.conversionFailed(result.stderr)
            }
            return try Data(contentsOf: outputFile)
        }
    }

    /// Generate a certificate chain (RCAC → ICAC → NOC) with chip-cert,
    /// mimicking what Apple Home produces. Returns TLV-encoded certs.
    func generateTestChain(
        rcacCN: String = "Apple Home RCAC",
        icacCN: String = "Apple Home ICAC",
        nocCN: String = "Test Node",
        fabricID: String = "0000000000000001",
        nodeID: String = "0000000000001234"
    ) throws -> (rcacTLV: Data, icacTLV: Data, nocTLV: Data) {
        try withTempDir { dir in
            let rcacFile = dir.appendingPathComponent("rcac")
            let rcacKeyFile = dir.appendingPathComponent("rcac-key")
            let icacFile = dir.appendingPathComponent("icac")
            let icacKeyFile = dir.appendingPathComponent("icac-key")
            let nocFile = dir.appendingPathComponent("noc")
            let nocKeyFile = dir.appendingPathComponent("noc-key")

            // Generate RCAC
            var result = try run([
                "gen-cert", "-t", "r",
                "-c", rcacCN,
                "-i", "1", "-f", fabricID,
                "-V", "2025-01-01", "-l", "3650",
                "-F", "chip",
                "-o", rcacFile.path, "-O", rcacKeyFile.path
            ])
            guard result.succeeded else {
                throw ChipCertError.conversionFailed("gen RCAC: \(result.stderr)")
            }

            // Generate ICAC signed by RCAC
            result = try run([
                "gen-cert", "-t", "c",
                "-c", icacCN,
                "-i", "2", "-f", fabricID,
                "-V", "2025-01-01", "-l", "3650",
                "-C", rcacFile.path, "-K", rcacKeyFile.path,
                "-F", "chip",
                "-o", icacFile.path, "-O", icacKeyFile.path
            ])
            guard result.succeeded else {
                throw ChipCertError.conversionFailed("gen ICAC: \(result.stderr)")
            }

            // Generate NOC signed by ICAC
            result = try run([
                "gen-cert", "-t", "n",
                "-c", nocCN,
                "-i", nodeID, "-f", fabricID,
                "-V", "2025-01-01", "-l", "3650",
                "-C", icacFile.path, "-K", icacKeyFile.path,
                "-F", "chip",
                "-o", nocFile.path, "-O", nocKeyFile.path
            ])
            guard result.succeeded else {
                throw ChipCertError.conversionFailed("gen NOC: \(result.stderr)")
            }

            let rcacTLV = try Data(contentsOf: rcacFile)
            let icacTLV = try Data(contentsOf: icacFile)
            let nocTLV = try Data(contentsOf: nocFile)

            return (rcacTLV, icacTLV, nocTLV)
        }
    }

    // MARK: - Attestation Certificate Validation

    // chip-cert validate-att-cert CLI (v1.4):
    //   chip-cert validate-att-cert -d <dac> -i <pai> -a <paa>

    /// Validate attestation certificate chain (PAA → PAI → DAC).
    func validateAttestationChain(dac dacDER: Data, pai paiDER: Data, paa paaDER: Data) throws -> RunResult {
        try withTempDir { dir in
            let dacFile = dir.appendingPathComponent("dac.der")
            let paiFile = dir.appendingPathComponent("pai.der")
            let paaFile = dir.appendingPathComponent("paa.der")
            try dacDER.write(to: dacFile)
            try paiDER.write(to: paiFile)
            try paaDER.write(to: paaFile)
            return try run(["validate-att-cert", "-d", dacFile.path, "-i", paiFile.path, "-a", paaFile.path])
        }
    }
}

// MARK: - Errors

enum ChipCertError: Error, CustomStringConvertible {
    case conversionFailed(String)

    var description: String {
        switch self {
        case .conversionFailed(let msg): return "chip-cert conversion failed: \(msg)"
        }
    }
}
