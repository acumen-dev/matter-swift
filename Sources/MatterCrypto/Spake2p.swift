// Spake2p.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto

/// SPAKE2+ Password-Authenticated Key Exchange for Matter (PASE).
///
/// Implements SPAKE2+ over P-256 as specified by the Matter protocol.
/// This is used during device commissioning to establish a secure session
/// from a shared passcode without revealing it.
///
/// ## Protocol Flow
///
/// 1. **PBKDFParamRequest/Response**: Exchange PBKDF2 parameters
/// 2. **Pake1**: Prover sends pA (= x*G + w0*M)
/// 3. **Pake2**: Verifier sends pB (= y*G + w0*N) + cB (confirmation MAC)
/// 4. **Pake3**: Prover sends cA (confirmation MAC)
///
/// After Pake3 is verified, both sides derive session keys from Ke.
public struct Spake2p: Sendable {

    // MARK: - Constants

    /// SPAKE2+ context prefix for Matter.
    public static let contextPrefix = Data("CHIP PAKE V1 Commissioning".utf8)

    /// P-256 curve order.
    static let curveOrder = bigIntFromHex(
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
    )

    /// M point (compressed, 33 bytes).
    static let pointM: Data = dataFromHex(
        "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
    )

    /// N point (compressed, 33 bytes).
    static let pointN: Data = dataFromHex(
        "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"
    )

    /// PBKDF2 iteration count bounds.
    public static let minIterations = 1000
    public static let maxIterations = 100_000

    /// Salt length bounds.
    public static let minSaltLength = 16
    public static let maxSaltLength = 32

    // MARK: - Verifier Computation

    /// Compute the SPAKE2+ verifier from a passcode.
    ///
    /// The verifier (w0 || L) is stored on the device and used during PASE.
    ///
    /// - Parameters:
    ///   - passcode: Setup passcode (e.g., 20202021).
    ///   - salt: Random salt (16-32 bytes).
    ///   - iterations: PBKDF2 iteration count (1000-100000).
    /// - Returns: The verifier containing w0 (32 bytes) and L (65 bytes).
    public static func computeVerifier(
        passcode: UInt32,
        salt: Data,
        iterations: Int
    ) throws -> Spake2pVerifier {
        guard salt.count >= minSaltLength && salt.count <= maxSaltLength else {
            throw CryptoError.invalidSalt
        }
        guard iterations >= minIterations && iterations <= maxIterations else {
            throw CryptoError.invalidIterations
        }

        // Derive w0s || w1s (80 bytes) via PBKDF2
        let ws = KeyDerivation.pbkdf2DeriveWS(
            passcode: passcode,
            salt: salt,
            iterations: iterations
        )

        let w0s = ws[0..<40]
        let w1s = ws[40..<80]

        // Reduce mod curve order to get w0, w1 scalars
        let w0 = reduceModOrder(Data(w0s))
        let w1 = reduceModOrder(Data(w1s))

        // L = w1 * G (generator point multiplication)
        let w1Key = try P256.Signing.PrivateKey(rawRepresentation: w1)
        let L = w1Key.publicKey.x963Representation

        return Spake2pVerifier(w0: w0, L: Data(L))
    }

    // MARK: - Prover (Initiator/Commissioner)

    /// Create the prover's pA value (Pake1 message).
    ///
    /// pA = x*G + w0*M
    ///
    /// - Parameter w0: The w0 scalar (32 bytes).
    /// - Returns: The prover context and pA (65 bytes, uncompressed).
    public static func proverStep1(
        w0: Data
    ) throws -> (context: Spake2pProverContext, pA: Data) {
        // Generate random scalar x
        let x = P256.Signing.PrivateKey()
        let xPublic = x.publicKey // x*G

        // Compute w0*M
        let w0M = try multiplyPoint(pointM, scalar: w0)

        // pA = x*G + w0*M
        let pA = try addPoints(xPublic.x963Representation, w0M)

        let context = Spake2pProverContext(
            x: x,
            w0: w0,
            pA: pA
        )

        return (context, pA)
    }

    /// Complete the prover's side after receiving Pake2.
    ///
    /// Computes Z, V, transcript hash, verifies cB, and produces cA.
    ///
    /// - Parameters:
    ///   - context: The prover context from step 1.
    ///   - pB: The verifier's public value (65 bytes, uncompressed).
    ///   - cB: The verifier's confirmation MAC (32 bytes).
    ///   - hashContext: SHA-256 hash of (context prefix || PBKDFParamRequest || PBKDFParamResponse).
    ///   - w1: The w1 scalar (32 bytes).
    /// - Returns: cA (32 bytes) and Ke (16-byte shared secret).
    public static func proverStep2(
        context: Spake2pProverContext,
        pB: Data,
        cB: Data,
        hashContext: Data,
        w1: Data
    ) throws -> (cA: Data, ke: Data) {
        // Compute Y - w0*N
        let w0N = try multiplyPoint(pointN, scalar: context.w0)
        let yMinusW0N = try subtractPoints(pB, w0N)

        // Z = x * (Y - w0*N)
        let Z = try multiplyPoint(yMinusW0N, scalar: context.x.rawRepresentation)

        // V = w1 * (Y - w0*N)
        let V = try multiplyPoint(yMinusW0N, scalar: w1)

        // Build transcript and derive keys
        let ttHash = computeTranscriptHash(
            context: hashContext,
            pA: context.pA,
            pB: pB,
            Z: Z,
            V: V,
            w0: context.w0
        )

        let ka = Data(ttHash[0..<16])
        let ke = Data(ttHash[16..<32])

        // Derive confirmation keys
        let (kcA, kcB) = KeyDerivation.deriveConfirmationKeys(ka: ka)

        // Verify cB = HMAC(KcB, pA)
        let expectedCB = Data(HMAC<SHA256>.authenticationCode(
            for: context.pA, using: kcB
        ))
        guard constantTimeEqual(cB, expectedCB) else {
            throw CryptoError.verificationFailed
        }

        // Compute cA = HMAC(KcA, pB)
        let cA = Data(HMAC<SHA256>.authenticationCode(
            for: pB, using: kcA
        ))

        return (cA, ke)
    }

    // MARK: - Verifier (Responder/Device)

    /// Create the verifier's pB and cB values (Pake2 message).
    ///
    /// pB = y*G + w0*N
    ///
    /// - Parameters:
    ///   - pA: The prover's public value from Pake1 (65 bytes, uncompressed).
    ///   - verifier: The stored SPAKE2+ verifier (w0, L).
    ///   - hashContext: SHA-256 hash of (context prefix || PBKDFParamRequest || PBKDFParamResponse).
    /// - Returns: Verifier context, pB (65 bytes), cB (32 bytes).
    public static func verifierStep1(
        pA: Data,
        verifier: Spake2pVerifier,
        hashContext: Data
    ) throws -> (context: Spake2pVerifierContext, pB: Data, cB: Data) {
        // Generate random scalar y
        let y = P256.Signing.PrivateKey()
        let yPublic = y.publicKey // y*G

        // Compute w0*N
        let w0N = try multiplyPoint(pointN, scalar: verifier.w0)

        // pB = y*G + w0*N
        let pB = try addPoints(yPublic.x963Representation, w0N)

        // Compute X - w0*M
        let w0M = try multiplyPoint(pointM, scalar: verifier.w0)
        let xMinusW0M = try subtractPoints(pA, w0M)

        // Z = y * (X - w0*M)
        let Z = try multiplyPoint(xMinusW0M, scalar: y.rawRepresentation)

        // V = y * L
        let V = try multiplyPoint(verifier.L, scalar: y.rawRepresentation)

        // Build transcript and derive keys
        let ttHash = computeTranscriptHash(
            context: hashContext,
            pA: pA,
            pB: pB,
            Z: Z,
            V: V,
            w0: verifier.w0
        )

        let ka = Data(ttHash[0..<16])
        let ke = Data(ttHash[16..<32])

        // Derive confirmation keys
        let (kcA, kcB) = KeyDerivation.deriveConfirmationKeys(ka: ka)

        // Compute cB = HMAC(KcB, pA)
        let cB = Data(HMAC<SHA256>.authenticationCode(
            for: pA, using: kcB
        ))

        let context = Spake2pVerifierContext(
            y: y,
            pB: pB,
            ke: ke,
            kcA: kcA
        )

        return (context, pB, cB)
    }

    /// Verify the prover's cA (Pake3 message).
    ///
    /// - Parameters:
    ///   - context: The verifier context from step 1.
    ///   - cA: The prover's confirmation MAC (32 bytes).
    ///   - pB: The verifier's pB to check against.
    /// - Returns: Ke (16-byte shared secret) on success.
    public static func verifierStep2(
        context: Spake2pVerifierContext,
        cA: Data
    ) throws -> Data {
        // Verify cA = HMAC(KcA, pB)
        let expectedCA = Data(HMAC<SHA256>.authenticationCode(
            for: context.pB, using: context.kcA
        ))
        guard constantTimeEqual(cA, expectedCA) else {
            throw CryptoError.verificationFailed
        }

        return context.ke
    }

    // MARK: - Hash Context

    /// Compute the SPAKE2+ hash context from PASE parameter exchange messages.
    ///
    /// `context = SHA-256(contextPrefix || pbkdfParamRequest || pbkdfParamResponse)`
    ///
    /// - Parameters:
    ///   - pbkdfParamRequest: Raw bytes of the PBKDFParamRequest TLV.
    ///   - pbkdfParamResponse: Raw bytes of the PBKDFParamResponse TLV.
    /// - Returns: 32-byte SHA-256 hash.
    public static func computeHashContext(
        pbkdfParamRequest: Data,
        pbkdfParamResponse: Data
    ) -> Data {
        var hasher = SHA256()
        hasher.update(data: contextPrefix)
        hasher.update(data: pbkdfParamRequest)
        hasher.update(data: pbkdfParamResponse)
        return Data(hasher.finalize())
    }
}

// MARK: - Transcript Hash

extension Spake2p {
    /// Compute the transcript hash TT.
    ///
    /// Each element is prefixed with its length as a UInt64 little-endian.
    /// idProver and idVerifier are empty strings in Matter.
    static func computeTranscriptHash(
        context: Data,
        pA: Data,
        pB: Data,
        Z: Data,
        V: Data,
        w0: Data
    ) -> Data {
        var transcript = Data()

        // context
        appendWithLength(&transcript, context)
        // idProver (empty)
        appendWithLength(&transcript, Data())
        // idVerifier (empty)
        appendWithLength(&transcript, Data())
        // M
        appendWithLength(&transcript, pointMUncompressed)
        // N
        appendWithLength(&transcript, pointNUncompressed)
        // X (pA)
        appendWithLength(&transcript, pA)
        // Y (pB)
        appendWithLength(&transcript, pB)
        // Z
        appendWithLength(&transcript, Z)
        // V
        appendWithLength(&transcript, V)
        // w0
        appendWithLength(&transcript, w0)

        return Data(SHA256.hash(data: transcript))
    }

    private static func appendWithLength(_ data: inout Data, _ element: Data) {
        // Length as UInt64 little-endian
        var len = UInt64(element.count)
        withUnsafeBytes(of: &len) { data.append(contentsOf: $0) }
        data.append(element)
    }

    /// M point uncompressed (65 bytes).
    static let pointMUncompressed: Data = dataFromHex(
        "04886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f" +
        "5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20"
    )

    /// N point uncompressed (65 bytes).
    static let pointNUncompressed: Data = dataFromHex(
        "04d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49" +
        "07d60aa6bfade45008a636337f5168c64d9bd36034808cd564490b1e656edbe7"
    )
}

// MARK: - P-256 Point Operations

extension Spake2p {
    /// Parse uncompressed or compressed SEC1 point data into a P256Point.
    static func parsePoint(_ data: Data) throws -> P256Point {
        if data.count == 65 {
            return try P256Point(uncompressed: data)
        } else if data.count == 33 {
            return try P256Point(compressed: data)
        }
        throw CryptoError.invalidPoint
    }

    /// Multiply an EC point by a scalar.
    static func multiplyPoint(_ point: Data, scalar: Data) throws -> Data {
        let p = try parsePoint(point)
        let s = bigIntFromBytes(scalar)
        let result = P256Point.multiply(p, scalar: s)
        guard !result.isInfinity else { throw CryptoError.invalidPoint }
        return result.uncompressed
    }

    /// Add two EC points.
    static func addPoints(_ a: Data, _ b: Data) throws -> Data {
        let pa = try parsePoint(a)
        let pb = try parsePoint(b)
        let result = P256Point.add(pa, pb)
        guard !result.isInfinity else { throw CryptoError.invalidPoint }
        return result.uncompressed
    }

    /// Subtract point b from point a (a + (-b)).
    static func subtractPoints(_ a: Data, _ b: Data) throws -> Data {
        let pa = try parsePoint(a)
        let pb = try parsePoint(b)
        let result = P256Point.add(pa, P256Point.negate(pb))
        guard !result.isInfinity else { throw CryptoError.invalidPoint }
        return result.uncompressed
    }

    /// Negate a point (reflect across x-axis: negate the y-coordinate).
    static func negatePoint(_ point: Data) throws -> Data {
        let p = try parsePoint(point)
        let result = P256Point.negate(p)
        return result.uncompressed
    }

    /// Derive the w0 and w1 scalars from a passcode using PBKDF2.
    ///
    /// This is the public entry point for computing SPAKE2+ scalars from
    /// a passcode and PBKDF parameters (used by both prover and verifier).
    ///
    /// - Parameters:
    ///   - passcode: The setup passcode.
    ///   - salt: PBKDF2 salt (16-32 bytes).
    ///   - iterations: PBKDF2 iteration count.
    /// - Returns: Tuple of (w0, w1) as 32-byte big-endian scalars.
    public static func deriveW0W1(
        passcode: UInt32,
        salt: Data,
        iterations: Int
    ) -> (w0: Data, w1: Data) {
        let ws = KeyDerivation.pbkdf2DeriveWS(
            passcode: passcode,
            salt: salt,
            iterations: iterations
        )
        let w0 = reduceModOrder(Data(ws[0..<40]))
        let w1 = reduceModOrder(Data(ws[40..<80]))
        return (w0, w1)
    }

    /// Reduce a 40-byte big-endian integer modulo the curve order.
    static func reduceModOrder(_ value: Data) -> Data {
        let bigVal = bigIntFromBytes(value)
        let reduced = bigVal % curveOrder
        return bigIntToBytes(reduced, count: 32)
    }

    /// Constant-time comparison of two Data values.
    static func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var result: UInt8 = 0
        for i in 0..<a.count {
            result |= a[a.startIndex + i] ^ b[b.startIndex + i]
        }
        return result == 0
    }
}

// MARK: - Big Integer Helpers (minimal, for modular reduction)

/// Simple big-integer type for modular arithmetic.
/// Only supports the operations needed for SPAKE2+ setup.
struct BigUInt: Comparable, Sendable {
    var words: [UInt64] // Little-endian word array

    init() { words = [] }

    init(_ value: UInt64) {
        words = value == 0 ? [] : [value]
    }

    static func < (lhs: BigUInt, rhs: BigUInt) -> Bool {
        let lCount = lhs.effectiveCount
        let rCount = rhs.effectiveCount
        if lCount != rCount { return lCount < rCount }
        for i in stride(from: lCount - 1, through: 0, by: -1) {
            if lhs[i] != rhs[i] { return lhs[i] < rhs[i] }
        }
        return false
    }

    static func == (lhs: BigUInt, rhs: BigUInt) -> Bool {
        let count = max(lhs.effectiveCount, rhs.effectiveCount)
        for i in 0..<count {
            if lhs[i] != rhs[i] { return false }
        }
        return true
    }

    subscript(index: Int) -> UInt64 {
        get { index < words.count ? words[index] : 0 }
        set {
            while words.count <= index { words.append(0) }
            words[index] = newValue
        }
    }

    var effectiveCount: Int {
        var count = words.count
        while count > 0 && words[count - 1] == 0 { count -= 1 }
        return max(count, 1)
    }

    var isZero: Bool {
        effectiveCount == 1 && self[0] == 0
    }

    static func - (lhs: BigUInt, rhs: BigUInt) -> BigUInt {
        var result = BigUInt()
        let count = max(lhs.effectiveCount, rhs.effectiveCount)
        var borrow: UInt64 = 0
        for i in 0..<count {
            let (diff, overflow1) = lhs[i].subtractingReportingOverflow(rhs[i])
            let (diff2, overflow2) = diff.subtractingReportingOverflow(borrow)
            result[i] = diff2
            borrow = (overflow1 ? 1 : 0) + (overflow2 ? 1 : 0)
        }
        return result
    }

    static func % (lhs: BigUInt, rhs: BigUInt) -> BigUInt {
        if lhs < rhs { return lhs }
        // Simple repeated subtraction with shifting for modular reduction
        var remainder = lhs
        let rhsBits = rhs.bitCount
        let lhsBits = remainder.bitCount

        if lhsBits < rhsBits { return remainder }

        var shift = lhsBits - rhsBits
        var shifted = rhs << shift

        while shift >= 0 {
            if !(remainder < shifted) {
                remainder = remainder - shifted
            }
            if shift == 0 { break }
            shifted = shifted >> 1
            shift -= 1
        }
        return remainder
    }

    static func << (lhs: BigUInt, shift: Int) -> BigUInt {
        guard shift > 0 else { return lhs }
        let wordShift = shift / 64
        let bitShift = shift % 64
        var result = BigUInt()
        let count = lhs.effectiveCount
        for i in 0..<count {
            result[i + wordShift] |= lhs[i] << bitShift
            if bitShift > 0 && i + wordShift + 1 >= 0 {
                result[i + wordShift + 1] |= (bitShift == 0 ? 0 : lhs[i] >> (64 - bitShift))
            }
        }
        return result
    }

    static func >> (lhs: BigUInt, shift: Int) -> BigUInt {
        guard shift > 0 else { return lhs }
        let wordShift = shift / 64
        let bitShift = shift % 64
        var result = BigUInt()
        let count = lhs.effectiveCount
        for i in wordShift..<count {
            result[i - wordShift] |= lhs[i] >> bitShift
            if bitShift > 0 && i + 1 < count {
                result[i - wordShift] |= lhs[i + 1] << (64 - bitShift)
            }
        }
        return result
    }

    var bitCount: Int {
        let ec = effectiveCount
        if ec == 0 || (ec == 1 && self[0] == 0) { return 0 }
        let topWord = self[ec - 1]
        return (ec - 1) * 64 + (64 - topWord.leadingZeroBitCount)
    }
}

// MARK: - Conversion Helpers

func bigIntFromHex(_ hex: String) -> BigUInt {
    let bytes = dataFromHex(hex)
    return bigIntFromBytes(bytes)
}

func bigIntFromBytes(_ data: Data) -> BigUInt {
    var result = BigUInt()
    // data is big-endian
    let count = data.count
    for i in 0..<count {
        let byteIndex = count - 1 - i
        let wordIndex = i / 8
        let bitOffset = (i % 8) * 8
        result[wordIndex] |= UInt64(data[data.startIndex + byteIndex]) << bitOffset
    }
    return result
}

func bigIntToBytes(_ value: BigUInt, count: Int) -> Data {
    var bytes = Data(count: count)
    for i in 0..<count {
        let wordIndex = i / 8
        let bitOffset = (i % 8) * 8
        bytes[count - 1 - i] = UInt8((value[wordIndex] >> bitOffset) & 0xFF)
    }
    return bytes
}

func dataFromHex(_ hex: String) -> Data {
    var data = Data()
    var index = hex.startIndex
    while index < hex.endIndex {
        let nextIndex = hex.index(index, offsetBy: 2)
        let byteString = hex[index..<nextIndex]
        if let byte = UInt8(byteString, radix: 16) {
            data.append(byte)
        }
        index = nextIndex
    }
    return data
}

// MARK: - Context Types

/// SPAKE2+ verifier (stored on device, derived from passcode).
public struct Spake2pVerifier: Sendable, Equatable {
    /// w0 scalar (32 bytes, big-endian).
    public let w0: Data

    /// L point (65 bytes, uncompressed SEC1).
    public let L: Data

    public init(w0: Data, L: Data) {
        self.w0 = w0
        self.L = L
    }

    /// Serialized form: w0 (32 bytes) || L (65 bytes) = 97 bytes.
    public var serialized: Data {
        var data = Data(capacity: 97)
        data.append(w0)
        data.append(L)
        return data
    }

    /// Deserialize from 97 bytes.
    public static func deserialize(_ data: Data) throws -> Spake2pVerifier {
        guard data.count == 97 else { throw CryptoError.invalidKeyLength }
        return Spake2pVerifier(
            w0: Data(data[0..<32]),
            L: Data(data[32..<97])
        )
    }
}

/// Prover-side context carried between Pake1 and Pake3.
public struct Spake2pProverContext: Sendable {
    let x: P256.Signing.PrivateKey
    let w0: Data
    let pA: Data
}

/// Verifier-side context carried between Pake2 and Pake3 verification.
public struct Spake2pVerifierContext: Sendable {
    let y: P256.Signing.PrivateKey
    let pB: Data
    let ke: Data
    let kcA: SymmetricKey
}
