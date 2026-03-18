// PBKDF2TestVectors.swift
// Copyright 2026 Monagle Pty Ltd
//
// PBKDF2-HMAC-SHA256 test vectors.
// Sources:
//   - RFC 7914 Appendix B (PBKDF2-SHA256 reference vectors)
//   - connectedhomeip/src/crypto/tests/PBKDF2_SHA256_test_vectors.h
//   - Matter spec §5.3.2 (passcode-to-verifier derivation)

import Foundation

// MARK: - PBKDF2-SHA256 Test Vectors

/// A single PBKDF2-HMAC-SHA256 test vector.
struct PBKDF2TestVector: Sendable, CustomStringConvertible {
    let name: String
    let password: Data
    let salt: Data
    let iterations: Int
    let derivedKeyLength: Int
    let expectedDK: Data
    var description: String { name }
}

enum PBKDF2TestVectors {
    static let all: [PBKDF2TestVector] = [
        // ── RFC 7914 Appendix B — password "password", salt "salt" ───────────
        PBKDF2TestVector(
            name: "RFC7914_1iter",
            password: Data("password".utf8),
            salt: Data("salt".utf8),
            iterations: 1,
            derivedKeyLength: 32,
            expectedDK: Data([
                0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c,
                0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
                0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48,
                0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b,
            ])
        ),

        PBKDF2TestVector(
            name: "RFC7914_2iter",
            password: Data("password".utf8),
            salt: Data("salt".utf8),
            iterations: 2,
            derivedKeyLength: 32,
            expectedDK: Data([
                0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3,
                0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0, 0x6d, 0xd0,
                0x2a, 0x30, 0x3f, 0x8e, 0xf3, 0xc2, 0x51, 0xdf,
                0xd6, 0xe2, 0xd8, 0x5a, 0x95, 0x47, 0x4c, 0x43,
            ])
        ),

        PBKDF2TestVector(
            name: "RFC7914_4096iter",
            password: Data("password".utf8),
            salt: Data("salt".utf8),
            iterations: 4096,
            derivedKeyLength: 32,
            expectedDK: Data([
                0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41,
                0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c, 0x4c, 0x8d,
                0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11,
                0xa4, 0x96, 0x38, 0x73, 0xaa, 0x98, 0x13, 0x4a,
            ])
        ),

        // ── RFC 7914 — longer salt ────────────────────────────────────────────
        PBKDF2TestVector(
            name: "RFC7914_LongSalt",
            password: Data("password".utf8),
            salt: Data("saltSALTsaltSALTsaltSALTsaltSALTsalt".utf8),
            iterations: 4096,
            derivedKeyLength: 25,
            expectedDK: Data([
                0x8e, 0x70, 0xc0, 0xba, 0x95, 0x34, 0xb2, 0x79,
                0x32, 0x73, 0x0a, 0x52, 0xfa, 0x8d, 0x39, 0xec,
                0xd9, 0x7a, 0x88, 0xec, 0x82, 0xcc, 0xa2, 0x20, 0x1f,
            ])
        ),

        // ── Matter spec §5.3.2 — passcode 20202021 ───────────────────────────
        // Passcode as little-endian UInt32: 20202021 = 0x01344225
        // little-endian bytes: 0x25, 0x42, 0x34, 0x01
        // Salt = 32 bytes of 0xAB, iterations = 1000, dkLen = 80
        // Used to derive W0s and W1s for SPAKE2+
        // Verified: python3 -c "import hashlib,struct; print(hashlib.pbkdf2_hmac('sha256',struct.pack('<I',20202021),bytes([0xAB]*32),1000,80).hex())"
        PBKDF2TestVector(
            name: "Matter_Passcode20202021",
            password: Data([0x25, 0x42, 0x34, 0x01]),
            salt: Data(repeating: 0xAB, count: 32),
            iterations: 1000,
            derivedKeyLength: 80,
            expectedDK: Data([
                0x5a, 0xc4, 0x09, 0x24, 0x83, 0x12, 0xe9, 0x84,
                0xf3, 0xdb, 0x27, 0x22, 0x19, 0x6e, 0x79, 0xcb,
                0xd5, 0x76, 0x9a, 0x9f, 0x83, 0xd6, 0x90, 0xb9,
                0x0f, 0xeb, 0x34, 0x2f, 0xaf, 0xa1, 0x28, 0x50,
                0x6e, 0x41, 0x39, 0x27, 0x55, 0x6e, 0xf3, 0xb7,
                0xfe, 0x3f, 0xad, 0x85, 0xf9, 0x5b, 0xdd, 0x53,
                0xbd, 0x46, 0x3a, 0x2e, 0xe5, 0x3e, 0x0b, 0xb9,
                0x98, 0xbc, 0xf1, 0x7e, 0x6e, 0xf4, 0x24, 0x93,
                0x10, 0x37, 0xb0, 0x95, 0x88, 0x6a, 0xc9, 0x0d,
                0x3a, 0xc5, 0x33, 0x52, 0x61, 0x19, 0xf0, 0xfc,
            ])
        ),
    ]
}
