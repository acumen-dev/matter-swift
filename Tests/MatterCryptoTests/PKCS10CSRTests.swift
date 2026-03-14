// PKCS10CSRTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
@testable import MatterCrypto

@Suite("PKCS#10 CSR Builder")
struct PKCS10CSRTests {

    // MARK: - Helpers

    /// Parse the outer SEQUENCE of a DER structure, returning the content bytes.
    private func derSequenceContent(_ data: Data) throws -> Data {
        var idx = data.startIndex
        // Tag byte
        let tag = data[idx]
        idx = data.index(after: idx)
        #expect(tag == 0x30, "Expected SEQUENCE tag 0x30, got \(String(format: "0x%02X", tag))")
        // Length
        let length: Int
        let lenByte = data[idx]
        idx = data.index(after: idx)
        if lenByte & 0x80 == 0 {
            length = Int(lenByte)
        } else {
            let numBytes = Int(lenByte & 0x7F)
            var len = 0
            for _ in 0..<numBytes {
                len = (len << 8) | Int(data[idx])
                idx = data.index(after: idx)
            }
            length = len
        }
        let contentStart = idx
        let contentEnd = data.index(contentStart, offsetBy: length)
        return data[contentStart..<contentEnd]
    }

    /// Count the number of top-level DER elements in a buffer.
    private func countDERElements(_ data: Data) -> Int {
        var count = 0
        var idx = data.startIndex
        while idx < data.endIndex {
            idx = data.index(after: idx) // tag
            guard idx < data.endIndex else { break }
            let lenByte = data[idx]
            idx = data.index(after: idx)
            if lenByte & 0x80 == 0 {
                idx = data.index(idx, offsetBy: Int(lenByte), limitedBy: data.endIndex) ?? data.endIndex
            } else {
                let numBytes = Int(lenByte & 0x7F)
                var len = 0
                for _ in 0..<numBytes {
                    guard idx < data.endIndex else { break }
                    len = (len << 8) | Int(data[idx])
                    idx = data.index(after: idx)
                }
                idx = data.index(idx, offsetBy: len, limitedBy: data.endIndex) ?? data.endIndex
            }
            count += 1
        }
        return count
    }

    // MARK: - Test 1: Valid DER Structure

    @Test("CSR is valid DER with 3 top-level elements in outer SEQUENCE")
    func csrHasValidDERStructure() throws {
        let privateKey = P256.Signing.PrivateKey()
        let csrData = try PKCS10CSRBuilder.buildCSR(privateKey: privateKey)

        // Must be non-empty
        #expect(!csrData.isEmpty)

        // Outer byte must be SEQUENCE tag (0x30)
        #expect(csrData[csrData.startIndex] == 0x30)

        // Parse outer SEQUENCE content
        let outerContent = try derSequenceContent(csrData)

        // Inner elements: CertificationRequestInfo (SEQUENCE), signatureAlgorithm (SEQUENCE), signature (BIT STRING)
        let elementCount = countDERElements(outerContent)
        #expect(elementCount == 3, "Expected 3 elements in outer SEQUENCE, got \(elementCount)")

        // First element is SEQUENCE (CertificationRequestInfo)
        #expect(outerContent[outerContent.startIndex] == 0x30)
    }

    // MARK: - Test 2: Public Key Extraction

    @Test("CSR SubjectPublicKeyInfo contains the correct P-256 public key")
    func csrContainsCorrectPublicKey() throws {
        let privateKey = P256.Signing.PrivateKey()
        let expectedPublicKeyBytes = Data(privateKey.publicKey.x963Representation)

        let csrData = try PKCS10CSRBuilder.buildCSR(privateKey: privateKey)

        // The uncompressed P-256 key is 65 bytes (0x04 + X + Y)
        // It appears inside the CSR as a BIT STRING: 0x00 prefix + 65 bytes
        // Search for the key bytes in the CSR
        let csrBytes = [UInt8](csrData)
        let keyBytes = [UInt8](expectedPublicKeyBytes)

        var found = false
        for i in 0..<(csrBytes.count - keyBytes.count) {
            if csrBytes[i..<(i + keyBytes.count)].elementsEqual(keyBytes) {
                found = true
                break
            }
        }

        #expect(found, "Expected P-256 public key bytes not found in CSR")
    }

    // MARK: - Test 3: Signature Verification

    @Test("CSR ECDSA signature verifies with the key's public key")
    func csrSignatureVerifies() throws {
        let privateKey = P256.Signing.PrivateKey()
        let csrData = try PKCS10CSRBuilder.buildCSR(privateKey: privateKey)

        // Parse structure:
        // SEQUENCE {              <- outer CertificationRequest
        //   SEQUENCE { ... }     <- CertificationRequestInfo (element 0)
        //   SEQUENCE { OID }     <- signatureAlgorithm (element 1)
        //   BIT STRING(sig)      <- signature (element 2)
        // }

        let outerContent = try derSequenceContent(csrData)
        var idx = outerContent.startIndex

        // Skip CertificationRequestInfo (first SEQUENCE)
        let criTag = outerContent[idx]
        idx = outerContent.index(after: idx)
        #expect(criTag == 0x30)

        // Parse CRI length to find where CRI ends
        let criLenByte = outerContent[idx]
        idx = outerContent.index(after: idx)
        let criLength: Int
        if criLenByte & 0x80 == 0 {
            criLength = Int(criLenByte)
        } else {
            let numBytes = Int(criLenByte & 0x7F)
            var len = 0
            for _ in 0..<numBytes {
                len = (len << 8) | Int(outerContent[idx])
                idx = outerContent.index(after: idx)
            }
            criLength = len
        }

        // CRI bytes (tag + length already consumed above, so reconstruct full CRI for verification)
        // We need the full DER-encoded CRI to verify the signature
        // Reconstruct CRI: find start of CRI in original data
        // Simpler: rebuild the CRI from the private key and compare signatures
        let criEnd = outerContent.index(idx, offsetBy: criLength)
        let criBodyBytes = outerContent[idx..<criEnd]
        idx = criEnd

        // Reconstruct full CRI bytes for signature verification
        let criContentData = Data(criBodyBytes)
        let criHeaderLen = PKCS10CSRBuilder.derLength(criLength)
        var criFullBytes = Data([0x30])
        criFullBytes.append(contentsOf: criHeaderLen)
        criFullBytes.append(criContentData)

        // Skip signatureAlgorithm SEQUENCE
        let sigAlgTag = outerContent[idx]
        idx = outerContent.index(after: idx)
        #expect(sigAlgTag == 0x30)
        let sigAlgLenByte = outerContent[idx]
        idx = outerContent.index(after: idx)
        let sigAlgLength: Int
        if sigAlgLenByte & 0x80 == 0 {
            sigAlgLength = Int(sigAlgLenByte)
        } else {
            let numBytes = Int(sigAlgLenByte & 0x7F)
            var len = 0
            for _ in 0..<numBytes {
                len = (len << 8) | Int(outerContent[idx])
                idx = outerContent.index(after: idx)
            }
            sigAlgLength = len
        }
        idx = outerContent.index(idx, offsetBy: sigAlgLength)

        // Parse BIT STRING for signature
        let sigTag = outerContent[idx]
        idx = outerContent.index(after: idx)
        #expect(sigTag == 0x03, "Expected BIT STRING tag 0x03")
        let sigLenByte = outerContent[idx]
        idx = outerContent.index(after: idx)
        let sigLength: Int
        if sigLenByte & 0x80 == 0 {
            sigLength = Int(sigLenByte)
        } else {
            let numBytes = Int(sigLenByte & 0x7F)
            var len = 0
            for _ in 0..<numBytes {
                len = (len << 8) | Int(outerContent[idx])
                idx = outerContent.index(after: idx)
            }
            sigLength = len
        }

        // Skip the 0x00 unused-bits byte
        idx = outerContent.index(after: idx)
        let derSigData = Data(outerContent[idx..<outerContent.index(idx, offsetBy: sigLength - 1)])

        // Verify signature over CRI bytes
        let ecdsaSig = try P256.Signing.ECDSASignature(derRepresentation: derSigData)
        let verified = privateKey.publicKey.isValidSignature(ecdsaSig, for: criFullBytes)
        #expect(verified, "ECDSA signature in CSR should verify against the public key")
    }
}

// MARK: - OID Encoding Tests

@Suite("PKCS10CSR DER OID Encoding")
struct DEREncodingTests {

    @Test("ecPublicKey OID encodes to known bytes")
    func ecPublicKeyOID() {
        // 1.2.840.10045.2.1 → known DER bytes
        let encoded = PKCS10CSRBuilder.derOID(PKCS10CSRBuilder.oidECPublicKey)
        let expected: [UInt8] = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]
        #expect(encoded == expected)
    }

    @Test("prime256v1 OID encodes to known bytes")
    func prime256v1OID() {
        // 1.2.840.10045.3.1.7 → known DER bytes
        let encoded = PKCS10CSRBuilder.derOID(PKCS10CSRBuilder.oidPrime256v1)
        let expected: [UInt8] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
        #expect(encoded == expected)
    }

    @Test("ecdsa-with-SHA256 OID encodes to known bytes")
    func ecdsaWithSHA256OID() {
        // 1.2.840.10045.4.3.2 → known DER bytes
        let encoded = PKCS10CSRBuilder.derOID(PKCS10CSRBuilder.oidECDSAWithSHA256)
        let expected: [UInt8] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]
        #expect(encoded == expected)
    }
}
