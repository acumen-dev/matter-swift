// CertificateConformanceTests.swift
// Copyright 2026 Monagle Pty Ltd
//
// Validates Matter certificate generation against the chip-cert reference tool
// from the connectedhomeip SDK.
//
// These tests require chip-cert to be built first:
//   make ref-setup-cert
//
// Tests skip gracefully when chip-cert is not available (e.g. on developer
// machines that haven't run setup.sh, or GitHub Actions before cache is warm).

import Testing
import Foundation
import Crypto
@testable import MatterCrypto
@testable import MatterTypes

// MARK: - Operational Certificate Conformance

@Suite("Certificate Conformance (chip-cert)")
struct CertificateConformanceTests {

    // MARK: - TLV → DER conversion (verifies TLV structure is correct)

    @Test("chip-cert can convert RCAC TLV to DER without error")
    func chipCertConvertRCACToDER() throws {
        guard let runner = ChipCertRunner.findBinary() else {
            print("[SKIP] chip-cert not found — run: make ref-setup-cert")
            return
        }

        let rootKey = P256.Signing.PrivateKey()
        let rcac = try MatterCertificate.generateRCAC(
            key: rootKey,
            fabricID: FabricID(rawValue: 0x0000000000000001)
        )
        let tlv = rcac.tlvEncode()

        let der = try runner.convertTLVtoDER(tlv)
        #expect(der.count > 0, "chip-cert produced empty DER output")
        #expect(der.first == 0x30, "DER output does not start with SEQUENCE tag (0x30)")
    }

    @Test("chip-cert can convert NOC TLV to DER without error")
    func chipCertConvertNOCtoDER() throws {
        guard let runner = ChipCertRunner.findBinary() else {
            print("[SKIP] chip-cert not found — run: make ref-setup-cert")
            return
        }

        let (fabric, _) = try FabricInfo.generateTestFabric()
        let nocTLV = fabric.noc.tlvEncode()

        let der = try runner.convertTLVtoDER(nocTLV)
        #expect(der.count > 0, "chip-cert produced empty DER output for NOC")
        #expect(der.first == 0x30, "NOC DER does not start with SEQUENCE tag")
    }

    // MARK: - NOC chain validation (RCAC → NOC)

    @Test("chip-cert validates NOC signed by RCAC")
    func chipCertValidatesNOCChain() throws {
        guard let runner = ChipCertRunner.findBinary() else {
            print("[SKIP] chip-cert not found — run: make ref-setup-cert")
            return
        }

        let (fabric, _) = try FabricInfo.generateTestFabric(
            fabricID: FabricID(rawValue: 0x0000000000000001),
            nodeID: NodeID(rawValue: 0x0000000000000001)
        )

        let rcacTLV = fabric.rcac.tlvEncode()
        let nocTLV = fabric.noc.tlvEncode()

        let result = try runner.validateNOC(nocTLV, rcac: rcacTLV)
        #expect(result.succeeded,
            "chip-cert rejected NOC chain. exit=\(result.exitCode)\nstderr: \(result.stderr)")
    }

    // MARK: - DER TBS comparison

    @Test("Our DER TBS bytes match chip-cert output")
    func tbsBytesMatchChipCert() throws {
        guard let runner = ChipCertRunner.findBinary() else {
            print("[SKIP] chip-cert not found — run: make ref-setup-cert")
            return
        }

        let rootKey = P256.Signing.PrivateKey()
        let rcac = try MatterCertificate.generateRCAC(
            key: rootKey,
            fabricID: FabricID(rawValue: 0x0000000000000001)
        )
        let tlv = rcac.tlvEncode()

        let parsed = try MatterCertificate.fromTLV(tlv)
        let ourTBS = parsed.tbsData()

        let fullDER = try runner.convertTLVtoDER(tlv)
        let chipCertTBS = try extractTBSFromDER(fullDER)

        #expect(ourTBS == chipCertTBS,
            "TBS mismatch:\n  ours:      \(ourTBS.hex)\n  chip-cert: \(chipCertTBS.hex)")
    }

    // MARK: - Self-signed RCAC verification (our own implementation)

    @Test("Self-signed RCAC verifies with DER TBS")
    func rcacSelfSignedVerifiesWithDER() throws {
        let key = P256.Signing.PrivateKey()
        let rcac = try MatterCertificate.generateRCAC(
            key: key,
            fabricID: FabricID(rawValue: 0x0000000000000001)
        )

        // Verify using our own implementation (which now uses DER TBS)
        #expect(rcac.verifySelfSigned(), "RCAC self-signature verification failed")

        // Also verify after TLV round-trip
        let tlv = rcac.tlvEncode()
        let parsed = try MatterCertificate.fromTLV(tlv)
        #expect(parsed.verifySelfSigned(), "RCAC self-signature verification failed after TLV round-trip")
    }
}

    // MARK: - RCAC → ICAC → NOC chain (Apple Home pattern)

    @Test("Verify chip-cert-generated RCAC→ICAC→NOC chain with our tbsData()")
    func verifyChipCertGeneratedChainWithICAC() throws {
        guard let runner = ChipCertRunner.findBinary() else {
            print("[SKIP] chip-cert not found — run: make ref-setup-cert")
            return
        }

        // Generate a 3-cert chain with chip-cert (same pattern as Apple Home)
        let (rcacTLV, icacTLV, nocTLV) = try runner.generateTestChain()

        // Parse the TLV certs
        let rcac = try MatterCertificate.fromTLV(rcacTLV)
        let icac = try MatterCertificate.fromTLV(icacTLV)
        let noc = try MatterCertificate.fromTLV(nocTLV)

        // Verify each cert's DER TBS matches chip-cert's DER output
        let rcacDER = try runner.convertTLVtoDER(rcacTLV)
        let rcacChipCertTBS = try extractTBSFromDER(rcacDER)
        let rcacOurTBS = rcac.tbsData()
        #expect(rcacOurTBS == rcacChipCertTBS,
            "RCAC TBS mismatch (\(rcacOurTBS.count)B vs \(rcacChipCertTBS.count)B)")

        let icacDER = try runner.convertTLVtoDER(icacTLV)
        let icacChipCertTBS = try extractTBSFromDER(icacDER)
        let icacOurTBS = icac.tbsData()
        #expect(icacOurTBS == icacChipCertTBS,
            "ICAC TBS mismatch (\(icacOurTBS.count)B vs \(icacChipCertTBS.count)B)")

        let nocDER = try runner.convertTLVtoDER(nocTLV)
        let nocChipCertTBS = try extractTBSFromDER(nocDER)
        let nocOurTBS = noc.tbsData()
        #expect(nocOurTBS == nocChipCertTBS,
            "NOC TBS mismatch (\(nocOurTBS.count)B vs \(nocChipCertTBS.count)B)")

        // Verify the full chain validates with our implementation
        #expect(rcac.verifySelfSigned(), "RCAC self-signature failed")
        #expect(MatterCertificate.validateChain(noc: noc, icac: icac, rcac: rcac),
            "3-cert chain validation failed")
    }

    // Note: "chip-cert validates our RCAC→ICAC→NOC chain" test deferred —
    // requires a generateICAC() method (generateNOC produces wrong extensions for an ICAC).

// MARK: - Attestation Certificate Conformance

@Suite("Attestation Certificate Conformance (chip-cert)")
struct AttestationCertConformanceTests {

    @Test("chip-cert accepts test PAA/PAI/DAC attestation chain")
    func chipCertAcceptsAttestationChain() throws {
        guard let runner = ChipCertRunner.findBinary() else {
            print("[SKIP] chip-cert not found — run: make ref-setup-cert")
            return
        }

        let creds = try DeviceAttestationCredentials.testCredentials()

        let result = try runner.validateAttestationChain(
            dac: creds.dacCertificate,
            pai: creds.paiCertificate,
            paa: creds.paaCertificate
        )
        #expect(result.succeeded,
            "chip-cert rejected attestation chain. exit=\(result.exitCode)\nstderr: \(result.stderr)")
    }
}

// MARK: - TBS Extraction Helper

/// Extract the `TBSCertificate` SEQUENCE from a DER-encoded X.509 certificate.
private func extractTBSFromDER(_ der: Data) throws -> Data {
    var idx = der.startIndex

    guard der[idx] == 0x30 else {
        throw TBSExtractionError.notASequence
    }
    idx = der.index(after: idx)

    let (_, outerLenBytes) = try parseDERLength(der, at: idx)
    idx = der.index(idx, offsetBy: outerLenBytes)

    guard idx < der.endIndex, der[idx] == 0x30 else {
        throw TBSExtractionError.tbsNotFound
    }
    let tbsStart = idx

    let tbsTagIdx = der.index(after: idx)
    let (tbsLength, tbsLenBytes) = try parseDERLength(der, at: tbsTagIdx)
    let tbsEnd = der.index(tbsTagIdx, offsetBy: tbsLenBytes + tbsLength)

    return Data(der[tbsStart..<tbsEnd])
}

private enum TBSExtractionError: Error {
    case notASequence
    case tbsNotFound
    case truncated
}

private func parseDERLength(_ data: Data, at index: Data.Index) throws -> (Int, Int) {
    guard index < data.endIndex else { throw TBSExtractionError.truncated }
    let first = data[index]
    if first & 0x80 == 0 {
        return (Int(first), 1)
    }
    let numBytes = Int(first & 0x7F)
    var length = 0
    for i in 1...numBytes {
        let byteIdx = data.index(index, offsetBy: i)
        guard byteIdx < data.endIndex else { throw TBSExtractionError.truncated }
        length = (length << 8) | Int(data[byteIdx])
    }
    return (length, 1 + numBytes)
}

// MARK: - Data hex helper (test-only)

private extension Data {
    var hex: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
