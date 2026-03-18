// CryptoVectorTests.swift
// Copyright 2026 Monagle Pty Ltd
//
// Validates crypto primitives against known-good reference vectors from:
//   - RFC 5869 (HKDF)
//   - RFC 4231 (HMAC-SHA256)
//   - NIST CAVP (SHA-256)
//   - RFC 7914 / connectedhomeip (PBKDF2)
//   - Computed via pycryptodome (AES-128-CCM)
//
// These tests catch regressions in the core cryptographic primitives used by
// every layer of the Matter protocol stack.

import Testing
import Foundation
import Crypto
import MatterTypes
@testable import MatterCrypto

// MARK: - HKDF-SHA256

@Suite("HKDF-SHA256 Reference Vectors")
struct HKDFVectorTests {

    @Test("HKDF output matches RFC 5869 reference", arguments: HKDFTestVectors.verifiable)
    func hkdfMatchesReference(vector: HKDFTestVector) throws {
        let ikm = SymmetricKey(data: vector.ikm)
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm,
            salt: vector.salt,
            info: vector.info,
            outputByteCount: vector.outputLength
        )
        let derivedBytes = derived.withUnsafeBytes { Data($0) }
        #expect(derivedBytes == vector.expectedOKM,
            "HKDF mismatch for \(vector.name): got \(derivedBytes.hex), expected \(vector.expectedOKM.hex)")
    }

    @Test("HKDF with empty salt uses zero-filled PRK salt per RFC 5869 §2.2")
    func hkdfEmptySaltAllowed() throws {
        let vector = HKDFTestVectors.all.first { $0.name == "RFC5869_TC3" }!
        let ikm = SymmetricKey(data: vector.ikm)
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm,
            salt: Data(),   // explicitly empty
            info: Data(),
            outputByteCount: vector.outputLength
        )
        let derivedBytes = derived.withUnsafeBytes { Data($0) }
        #expect(derivedBytes == vector.expectedOKM)
    }

    @Test("Matter session key derivation produces 48 bytes with correct layout")
    func matterSessionKeys() {
        let sharedSecret = Data(repeating: 0x42, count: 32)
        let result = KeyDerivation.deriveSessionKeys(sharedSecret: sharedSecret)

        let i2r = result.i2rKey.withUnsafeBytes { Data($0) }
        let r2i = result.r2iKey.withUnsafeBytes { Data($0) }
        let att = result.attestationKey.withUnsafeBytes { Data($0) }

        #expect(i2r.count == 16)
        #expect(r2i.count == 16)
        #expect(att.count == 16)
        #expect(i2r != r2i)
        #expect(i2r != att)
        #expect(r2i != att)
    }
}

// MARK: - HMAC-SHA256

@Suite("HMAC-SHA256 Reference Vectors")
struct HMACVectorTests {

    @Test("HMAC-SHA256 output matches RFC 4231 reference", arguments: HMACTestVectors.all)
    func hmacMatchesReference(vector: HMACTestVector) {
        let key = SymmetricKey(data: vector.key)
        let mac = Data(HMAC<SHA256>.authenticationCode(for: vector.data, using: key))
        #expect(mac == vector.expectedMAC,
            "HMAC mismatch for \(vector.name): got \(mac.hex), expected \(vector.expectedMAC.hex)")
    }
}

// MARK: - SHA-256

@Suite("SHA-256 Reference Vectors")
struct SHA256VectorTests {

    @Test("SHA-256 digest matches NIST CAVP reference", arguments: SHA256TestVectors.all)
    func sha256MatchesReference(vector: SHA256TestVector) {
        let digest = Data(SHA256.hash(data: vector.input))
        #expect(digest == vector.expectedDigest,
            "SHA-256 mismatch for \(vector.name): got \(digest.hex), expected \(vector.expectedDigest.hex)")
    }
}

// MARK: - PBKDF2-SHA256

@Suite("PBKDF2-SHA256 Reference Vectors")
struct PBKDF2VectorTests {

    @Test("PBKDF2-HMAC-SHA256 output matches reference", arguments: PBKDF2TestVectors.all)
    func pbkdf2MatchesReference(vector: PBKDF2TestVector) {
        let dk = KeyDerivation.pbkdf2HMACSHA256(
            password: vector.password,
            salt: vector.salt,
            iterations: vector.iterations,
            derivedKeyLength: vector.derivedKeyLength
        )
        #expect(dk == vector.expectedDK,
            "PBKDF2 mismatch for \(vector.name): got \(dk.hex), expected \(vector.expectedDK.hex)")
    }

    @Test("SPAKE2+ W0s/W1s derivation has correct byte count for passcode 20202021")
    func spake2WsDerivedLength() {
        let ws = KeyDerivation.pbkdf2DeriveWS(
            passcode: 20202021,
            salt: Data(repeating: 0xAB, count: 32),
            iterations: 1000
        )
        // W0s and W1s: 80 bytes total (40 + 40)
        #expect(ws.count == 80)
    }

    @Test("SPAKE2+ W0s/W1s matches PBKDF2 reference vector for passcode 20202021")
    func spake2WsMatchesReference() {
        let vector = PBKDF2TestVectors.all.first { $0.name == "Matter_Passcode20202021" }!
        let ws = KeyDerivation.pbkdf2DeriveWS(
            passcode: 20202021,
            salt: vector.salt,
            iterations: vector.iterations
        )
        #expect(ws == vector.expectedDK,
            "W0s/W1s mismatch: got \(ws.hex), expected \(vector.expectedDK.hex)")
    }
}

// MARK: - AES-128-CCM

@Suite("AES-128-CCM Reference Vectors")
struct AESCCMVectorTests {

    @Test("AES-128-CCM encrypt matches reference vector", arguments: AESCCMTestVectors.all)
    func encryptMatchesReference(vector: AESCCMTestVector) throws {
        let key = SymmetricKey(data: vector.key)
        let result = try MessageEncryption.encrypt(
            plaintext: vector.plaintext,
            key: key,
            nonce: vector.nonce,
            aad: vector.aad
        )
        // Result = ciphertext || 16-byte tag
        let ct = result.dropLast(MessageEncryption.micLength)
        let tag = result.suffix(MessageEncryption.micLength)

        #expect(Data(ct) == vector.expectedCiphertext,
            "Ciphertext mismatch for \(vector.name): got \(Data(ct).hex), expected \(vector.expectedCiphertext.hex)")
        #expect(Data(tag) == vector.expectedTag,
            "Tag mismatch for \(vector.name): got \(Data(tag).hex), expected \(vector.expectedTag.hex)")
    }

    @Test("AES-128-CCM decrypt round-trips correctly", arguments: AESCCMTestVectors.all)
    func decryptRoundTrip(vector: AESCCMTestVector) throws {
        let key = SymmetricKey(data: vector.key)

        // Encrypt using reference ciphertext || tag
        var ciphertextWithTag = vector.expectedCiphertext
        ciphertextWithTag.append(vector.expectedTag)

        let decrypted = try MessageEncryption.decrypt(
            ciphertextWithMIC: ciphertextWithTag,
            key: key,
            nonce: vector.nonce,
            aad: vector.aad
        )
        #expect(decrypted == vector.plaintext,
            "Decrypt mismatch for \(vector.name): got \(decrypted.hex), expected \(vector.plaintext.hex)")
    }

    @Test("AES-128-CCM decrypt rejects tampered ciphertext")
    func decryptRejectsTamperedCiphertext() throws {
        let vector = AESCCMTestVectors.all[0]
        let key = SymmetricKey(data: vector.key)

        var tampered = vector.expectedCiphertext
        tampered[0] ^= 0xFF  // flip a bit
        tampered.append(vector.expectedTag)

        #expect(throws: CryptoError.authenticationFailed) {
            try MessageEncryption.decrypt(
                ciphertextWithMIC: tampered,
                key: key,
                nonce: vector.nonce,
                aad: vector.aad
            )
        }
    }

    @Test("AES-128-CCM decrypt rejects tampered tag")
    func decryptRejectsTamperedTag() throws {
        let vector = AESCCMTestVectors.all[0]
        let key = SymmetricKey(data: vector.key)

        var withBadTag = vector.expectedCiphertext
        var badTag = vector.expectedTag
        badTag[0] ^= 0x01
        withBadTag.append(badTag)

        #expect(throws: CryptoError.authenticationFailed) {
            try MessageEncryption.decrypt(
                ciphertextWithMIC: withBadTag,
                key: key,
                nonce: vector.nonce,
                aad: vector.aad
            )
        }
    }

    @Test("AES-128-CCM encrypt then decrypt is identity for random inputs")
    func encryptDecryptIdentity() throws {
        let key = SymmetricKey(size: .bits128)
        let nonce = Data((0..<13).map { _ in UInt8.random(in: 0...255) })
        let plaintext = Data((0..<64).map { _ in UInt8.random(in: 0...255) })
        let aad = Data((0..<8).map { _ in UInt8.random(in: 0...255) })

        let encrypted = try MessageEncryption.encrypt(plaintext: plaintext, key: key, nonce: nonce, aad: aad)
        let decrypted = try MessageEncryption.decrypt(ciphertextWithMIC: encrypted, key: key, nonce: nonce, aad: aad)
        #expect(decrypted == plaintext)
    }
}

// MARK: - Destination ID

@Suite("Destination ID Reference Vectors")
struct DestinationIDVectorTests {

    @Test("Destination ID matches TestCASESession.cpp reference", arguments: DestinationIDTestVectors.all)
    func destinationIDMatchesReference(vector: DestinationIDTestVector) {
        let result = CASEKeyDerivation.computeDestinationID(
            initiatorRandom: vector.initiatorRandom,
            rootPublicKey: vector.rootPubKey,
            fabricID: FabricID(rawValue: vector.fabricID),
            nodeID: NodeID(rawValue: vector.nodeID),
            ipk: vector.ipk
        )
        #expect(result == vector.expectedDestinationID,
            "DestinationID mismatch for \(vector.name): got \(result.hex), expected \(vector.expectedDestinationID.hex)")
    }
}

// MARK: - Data hex helper (test-only)

private extension Data {
    var hex: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
