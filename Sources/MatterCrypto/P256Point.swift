// P256Point.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

/// P-256 elliptic curve point operations for SPAKE2+.
///
/// CryptoKit doesn't expose arbitrary EC point arithmetic (add, scalar multiply
/// with full point result). SPAKE2+ requires these for computing pA, pB, Z, and V.
///
/// This implements point operations using Jacobian projective coordinates
/// with P-256 fast field reduction, avoiding expensive modular inverses
/// during intermediate operations.
///
/// These operations are NOT constant-time and should only be used for SPAKE2+
/// setup computations, not for operations involving long-term secrets.
struct P256Point: Sendable, Equatable {
    /// x-coordinate (32 bytes, big-endian as BigUInt).
    let x: BigUInt
    /// y-coordinate (32 bytes, big-endian as BigUInt).
    let y: BigUInt

    /// The point at infinity (identity element).
    static let infinity = P256Point(x: BigUInt(0), y: BigUInt(0))

    /// Whether this is the point at infinity.
    var isInfinity: Bool {
        x.isZero && y.isZero
    }
}

// MARK: - P-256 Curve Constants

enum P256Curve {
    /// Field prime p = 2^256 - 2^224 + 2^192 + 2^96 - 1.
    static let p = bigIntFromHex(
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"
    )

    /// Curve parameter a = -3 (mod p) = p - 3.
    static let a: BigUInt = {
        p - BigUInt(3)
    }()

    /// Curve parameter b.
    static let b = bigIntFromHex(
        "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"
    )

    /// Curve order n.
    static let n = bigIntFromHex(
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
    )

    /// Generator point G.
    static let G = P256Point(
        x: bigIntFromHex(
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
        ),
        y: bigIntFromHex(
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
        )
    )
}

// MARK: - P-256 Fast Field Reduction

/// Fast modular reduction for P-256.
///
/// Exploits the special form p = 2^256 - 2^224 + 2^192 + 2^96 - 1
/// to reduce a 512-bit product modulo p using only additions and subtractions
/// of 256-bit values, avoiding expensive general-purpose division.
///
/// Reference: FIPS 186-4 Section D.2.3 (NIST curve-specific reduction).
private func p256Reduce(_ t: BigUInt) -> BigUInt {
    // Extract 32-bit limbs from the 512-bit input (little-endian)
    // t = t0 + t1*2^32 + ... + t15*2^480
    func limb32(_ val: BigUInt, _ index: Int) -> UInt64 {
        let wordIndex = index / 2
        let halfIndex = index % 2
        let word = val[wordIndex]
        return halfIndex == 0 ? word & 0xFFFFFFFF : word >> 32
    }

    let c = (0..<16).map { limb32(t, $0) }

    // Build the addend/subtractend values per NIST specification
    // s1 = (c7, c6, c5, c4, c3, c2, c1, c0)  — the input itself (low 256 bits)
    // s2 = (c15, c14, c13, c12, c11, 0, 0, 0)
    // s3 = (0, c15, c14, c13, c12, 0, 0, 0)
    // s4 = (c15, c14, 0, 0, 0, c10, c9, c8)
    // s5 = (c8, c13, c15, c14, c13, c11, c10, c9)
    // d1 = (c10, c8, 0, 0, 0, c13, c12, c11)
    // d2 = (c11, c9, 0, 0, c15, c14, c13, c12)
    // d3 = (c12, 0, c10, c9, c8, c15, c14, c13)
    // d4 = (c13, 0, c11, c10, c9, 0, c15, c14)
    //
    // result = s1 + 2*s2 + 2*s3 + s4 + s5 - d1 - d2 - d3 - d4 (mod p)

    func build(_ c7: UInt64, _ c6: UInt64, _ c5: UInt64, _ c4: UInt64,
               _ c3: UInt64, _ c2: UInt64, _ c1: UInt64, _ c0: UInt64) -> BigUInt {
        var r = BigUInt()
        r[0] = c0 | (c1 << 32)
        r[1] = c2 | (c3 << 32)
        r[2] = c4 | (c5 << 32)
        r[3] = c6 | (c7 << 32)
        return r
    }

    let s1 = build(c[7], c[6], c[5], c[4], c[3], c[2], c[1], c[0])
    let s2 = build(c[15], c[14], c[13], c[12], c[11], 0, 0, 0)
    let s3 = build(0, c[15], c[14], c[13], c[12], 0, 0, 0)
    let s4 = build(c[15], c[14], 0, 0, 0, c[10], c[9], c[8])
    let s5 = build(c[8], c[13], c[15], c[14], c[13], c[11], c[10], c[9])
    let d1 = build(c[10], c[8], 0, 0, 0, c[13], c[12], c[11])
    let d2 = build(c[11], c[9], 0, 0, c[15], c[14], c[13], c[12])
    let d3 = build(c[12], 0, c[10], c[9], c[8], c[15], c[14], c[13])
    let d4 = build(c[13], 0, c[11], c[10], c[9], 0, c[15], c[14])

    // Accumulate using wider arithmetic to track carries/borrows
    let p = P256Curve.p

    // Sum the adds
    var sum = bigAdd(s1, bigAdd(s2, s2))
    sum = bigAdd(sum, bigAdd(s3, s3))
    sum = bigAdd(sum, s4)
    sum = bigAdd(sum, s5)

    // Sum the subtracts
    var sub = bigAdd(d1, d2)
    sub = bigAdd(sub, d3)
    sub = bigAdd(sub, d4)

    // result = sum - sub (may be negative, so add multiples of p)
    // Add extra p's to ensure positive before subtraction
    var result = bigAdd(sum, bigAdd(p, p)) // add 2p to avoid underflow
    result = bigAdd(result, bigAdd(p, p)) // add another 2p for safety (4p total)
    if result >= sub {
        result = result - sub
    } else {
        result = bigAdd(result, p) - sub
    }

    // Final reduction: bring into [0, p)
    while result >= p {
        result = result - p
    }

    return result
}

// MARK: - Modular Arithmetic

extension P256Curve {
    /// Modular addition: (a + b) mod p.
    static func modAdd(_ a: BigUInt, _ b: BigUInt) -> BigUInt {
        let sum = bigAdd(a, b)
        if sum >= p { return sum - p }
        return sum
    }

    /// Modular subtraction: (a - b) mod p.
    static func modSub(_ a: BigUInt, _ b: BigUInt) -> BigUInt {
        if a >= b {
            return a - b
        }
        return bigAdd(p, a) - b
    }

    /// Modular multiplication: (a * b) mod p using P-256 fast reduction.
    static func modMul(_ a: BigUInt, _ b: BigUInt) -> BigUInt {
        let product = bigMul(a, b)
        return p256Reduce(product)
    }

    /// Modular squaring: a² mod p (uses same path as modMul but semantically distinct).
    static func modSqr(_ a: BigUInt) -> BigUInt {
        modMul(a, a)
    }

    /// Modular inverse: a^(-1) mod p using Fermat's little theorem.
    /// a^(-1) = a^(p-2) mod p
    static func modInverse(_ a: BigUInt) -> BigUInt {
        let exp = p - BigUInt(2)
        return modPow(a, exp, p)
    }

    /// Modular exponentiation: base^exp mod mod.
    static func modPow(_ base: BigUInt, _ exp: BigUInt, _ mod: BigUInt) -> BigUInt {
        var result = BigUInt(1)
        var b = base % mod
        let bits = exp.bitCount

        for i in 0..<bits {
            let wordIndex = i / 64
            let bitIndex = i % 64
            if (exp[wordIndex] >> bitIndex) & 1 == 1 {
                result = p256Reduce(bigMul(result, b))
            }
            b = p256Reduce(bigMul(b, b))
        }
        return result
    }
}

// MARK: - Jacobian Projective Coordinates

/// A point in Jacobian projective coordinates: (X : Y : Z)
/// where the affine point is (X/Z², Y/Z³).
/// Point at infinity is represented by Z = 0.
private struct JacobianPoint {
    var X: BigUInt
    var Y: BigUInt
    var Z: BigUInt

    static let infinity = JacobianPoint(X: BigUInt(1), Y: BigUInt(1), Z: BigUInt(0))

    var isInfinity: Bool { Z.isZero }

    /// Convert from affine to Jacobian.
    init(affine p: P256Point) {
        if p.isInfinity {
            self = .infinity
        } else {
            X = p.x
            Y = p.y
            Z = BigUInt(1)
        }
    }

    init(X: BigUInt, Y: BigUInt, Z: BigUInt) {
        self.X = X
        self.Y = Y
        self.Z = Z
    }

    /// Convert back to affine: (X/Z², Y/Z³).
    func toAffine() -> P256Point {
        if isInfinity { return .infinity }
        let zInv = P256Curve.modInverse(Z)
        let zInv2 = P256Curve.modSqr(zInv)
        let zInv3 = P256Curve.modMul(zInv2, zInv)
        let ax = P256Curve.modMul(X, zInv2)
        let ay = P256Curve.modMul(Y, zInv3)
        return P256Point(x: ax, y: ay)
    }

    /// Point doubling in Jacobian coordinates.
    ///
    /// Uses the "dbl-2001-b" formula (12M + 4S).
    /// For a = -3 (P-256), uses the optimized "dbl-2007-bl" (1M + 5S + 1*a + 7add).
    static func double(_ p: JacobianPoint) -> JacobianPoint {
        if p.isInfinity { return .infinity }

        // P-256 has a = -3, use the optimized formula
        // α = 3(X - Z²)(X + Z²)
        let Z2 = P256Curve.modSqr(p.Z)
        let xMinusZ2 = P256Curve.modSub(p.X, Z2)
        let xPlusZ2 = P256Curve.modAdd(p.X, Z2)
        let alpha = P256Curve.modMul(
            P256Curve.modAdd(P256Curve.modAdd(xMinusZ2, xMinusZ2), xMinusZ2), // 3 * (X - Z²)
            xPlusZ2 // Not exactly right for generic, but for a=-3 this gives 3(X² - Z⁴) = 3X² + aZ⁴
        )
        // Wait, the standard formula for a=-3:
        // α = 3(X + Z²)(X - Z²) = 3(X² - Z⁴) = 3X² + aZ⁴ (since a = -3)

        // β = 4XY²
        let Y2 = P256Curve.modSqr(p.Y)
        let beta = P256Curve.modMul(P256Curve.modAdd(P256Curve.modAdd(p.X, p.X), P256Curve.modAdd(p.X, p.X)), Y2) // 4X * Y²

        // X3 = α² - 2β
        let alpha2 = P256Curve.modSqr(alpha)
        let X3 = P256Curve.modSub(alpha2, P256Curve.modAdd(beta, beta))

        // Z3 = (Y + Z)² - Y² - Z² = 2YZ
        let Z3 = P256Curve.modSub(
            P256Curve.modSub(
                P256Curve.modSqr(P256Curve.modAdd(p.Y, p.Z)),
                Y2
            ),
            Z2
        )

        // Y3 = α(β - X3) - 8Y⁴
        let Y4 = P256Curve.modSqr(Y2)
        let eightY4 = P256Curve.modAdd(
            P256Curve.modAdd(P256Curve.modAdd(Y4, Y4), P256Curve.modAdd(Y4, Y4)),
            P256Curve.modAdd(P256Curve.modAdd(Y4, Y4), P256Curve.modAdd(Y4, Y4))
        )
        let Y3 = P256Curve.modSub(
            P256Curve.modMul(alpha, P256Curve.modSub(beta, X3)),
            eightY4
        )

        return JacobianPoint(X: X3, Y: Y3, Z: Z3)
    }

    /// Point addition in Jacobian coordinates (mixed: p2 has Z=1).
    ///
    /// Mixed addition is faster when one input is affine (Z=1), which is
    /// the common case for precomputed tables.
    static func addMixed(_ p1: JacobianPoint, _ p2: P256Point) -> JacobianPoint {
        if p1.isInfinity { return JacobianPoint(affine: p2) }
        if p2.isInfinity { return p1 }

        // U2 = X2 * Z1²
        let Z1_2 = P256Curve.modSqr(p1.Z)
        let U2 = P256Curve.modMul(p2.x, Z1_2)

        // S2 = Y2 * Z1³
        let Z1_3 = P256Curve.modMul(Z1_2, p1.Z)
        let S2 = P256Curve.modMul(p2.y, Z1_3)

        // H = U2 - X1
        let H = P256Curve.modSub(U2, p1.X)
        // R = S2 - Y1
        let R = P256Curve.modSub(S2, p1.Y)

        if H.isZero {
            if R.isZero {
                return JacobianPoint.double(p1)
            }
            return .infinity
        }

        let H2 = P256Curve.modSqr(H)
        let H3 = P256Curve.modMul(H2, H)

        // X3 = R² - H³ - 2*X1*H²
        let X1H2 = P256Curve.modMul(p1.X, H2)
        let X3 = P256Curve.modSub(
            P256Curve.modSub(P256Curve.modSqr(R), H3),
            P256Curve.modAdd(X1H2, X1H2)
        )

        // Y3 = R*(X1*H² - X3) - Y1*H³
        let Y3 = P256Curve.modSub(
            P256Curve.modMul(R, P256Curve.modSub(X1H2, X3)),
            P256Curve.modMul(p1.Y, H3)
        )

        // Z3 = Z1 * H
        let Z3 = P256Curve.modMul(p1.Z, H)

        return JacobianPoint(X: X3, Y: Y3, Z: Z3)
    }

    /// Full Jacobian addition (both inputs may have Z ≠ 1).
    static func add(_ p1: JacobianPoint, _ p2: JacobianPoint) -> JacobianPoint {
        if p1.isInfinity { return p2 }
        if p2.isInfinity { return p1 }

        let Z1_2 = P256Curve.modSqr(p1.Z)
        let Z2_2 = P256Curve.modSqr(p2.Z)
        let U1 = P256Curve.modMul(p1.X, Z2_2)
        let U2 = P256Curve.modMul(p2.X, Z1_2)
        let S1 = P256Curve.modMul(p1.Y, P256Curve.modMul(Z2_2, p2.Z))
        let S2 = P256Curve.modMul(p2.Y, P256Curve.modMul(Z1_2, p1.Z))

        let H = P256Curve.modSub(U2, U1)
        let R = P256Curve.modSub(S2, S1)

        if H.isZero {
            if R.isZero {
                return JacobianPoint.double(p1)
            }
            return .infinity
        }

        let H2 = P256Curve.modSqr(H)
        let H3 = P256Curve.modMul(H2, H)
        let U1H2 = P256Curve.modMul(U1, H2)

        let X3 = P256Curve.modSub(
            P256Curve.modSub(P256Curve.modSqr(R), H3),
            P256Curve.modAdd(U1H2, U1H2)
        )
        let Y3 = P256Curve.modSub(
            P256Curve.modMul(R, P256Curve.modSub(U1H2, X3)),
            P256Curve.modMul(S1, H3)
        )
        let Z3 = P256Curve.modMul(P256Curve.modMul(p1.Z, p2.Z), H)

        return JacobianPoint(X: X3, Y: Y3, Z: Z3)
    }
}

// MARK: - Point Operations (public, affine interface)

extension P256Point {
    /// Add two points on the curve.
    static func add(_ p1: P256Point, _ p2: P256Point) -> P256Point {
        if p1.isInfinity { return p2 }
        if p2.isInfinity { return p1 }

        // Use mixed addition: convert p1 to Jacobian, keep p2 as affine
        let jp1 = JacobianPoint(affine: p1)
        let result = JacobianPoint.addMixed(jp1, p2)
        return result.toAffine()
    }

    /// Double a point on the curve.
    static func double(_ p1: P256Point) -> P256Point {
        JacobianPoint.double(JacobianPoint(affine: p1)).toAffine()
    }

    /// Scalar multiplication: scalar * point using 4-bit windowed method.
    ///
    /// Precomputes a table of [1P, 2P, ..., 15P] and scans the scalar
    /// 4 bits at a time, reducing the number of point additions by ~4x.
    static func multiply(_ point: P256Point, scalar: BigUInt) -> P256Point {
        if scalar.isZero { return .infinity }

        // Precompute table: table[i] = (i+1) * point for i = 0..14
        var table = [P256Point](repeating: .infinity, count: 15)
        table[0] = point
        for i in 1..<15 {
            table[i] = add(table[i - 1], point)
        }

        // Scan scalar 4 bits at a time (MSB to LSB) using Jacobian coords
        let bits = scalar.bitCount
        let nibbles = (bits + 3) / 4

        var result = JacobianPoint.infinity

        for ni in stride(from: nibbles - 1, through: 0, by: -1) {
            // Double 4 times
            result = JacobianPoint.double(result)
            result = JacobianPoint.double(result)
            result = JacobianPoint.double(result)
            result = JacobianPoint.double(result)

            // Extract 4-bit nibble
            let bitPos = ni * 4
            var nibble: UInt64 = 0
            for b in 0..<4 {
                let pos = bitPos + b
                let wordIndex = pos / 64
                let bitIndex = pos % 64
                if (scalar[wordIndex] >> bitIndex) & 1 == 1 {
                    nibble |= 1 << b
                }
            }

            if nibble > 0 {
                // Add table[nibble - 1] using mixed addition (affine table point)
                result = JacobianPoint.addMixed(result, table[Int(nibble) - 1])
            }
        }

        return result.toAffine()
    }

    /// Negate a point (reflect across x-axis).
    static func negate(_ point: P256Point) -> P256Point {
        if point.isInfinity { return .infinity }
        return P256Point(x: point.x, y: P256Curve.modSub(P256Curve.p, point.y))
    }
}

// MARK: - Serialization

extension P256Point {
    /// Deserialize from SEC1 uncompressed format (04 || x || y, 65 bytes).
    init(uncompressed data: Data) throws {
        guard data.count == 65, data[data.startIndex] == 0x04 else {
            throw CryptoError.invalidPoint
        }
        self.x = bigIntFromBytes(Data(data[(data.startIndex + 1)..<(data.startIndex + 33)]))
        self.y = bigIntFromBytes(Data(data[(data.startIndex + 33)..<(data.startIndex + 65)]))
    }

    /// Deserialize from SEC1 compressed format (02/03 || x, 33 bytes).
    init(compressed data: Data) throws {
        guard data.count == 33 else {
            throw CryptoError.invalidPoint
        }
        let prefix = data[data.startIndex]
        guard prefix == 0x02 || prefix == 0x03 else {
            throw CryptoError.invalidPoint
        }

        let x = bigIntFromBytes(Data(data[(data.startIndex + 1)..<(data.startIndex + 33)]))

        // y² = x³ + ax + b mod p
        let x2 = P256Curve.modMul(x, x)
        let x3 = P256Curve.modMul(x2, x)
        let ax = P256Curve.modMul(P256Curve.a, x)
        let y2 = P256Curve.modAdd(P256Curve.modAdd(x3, ax), P256Curve.b)

        // y = sqrt(y²) mod p using Tonelli-Shanks (p ≡ 3 mod 4 for P-256)
        // y = y2^((p+1)/4) mod p
        let exp = (bigAdd(P256Curve.p, BigUInt(1))) >> 2
        var y = P256Curve.modPow(y2, exp, P256Curve.p)

        // Choose the correct root based on the prefix byte
        let yIsOdd = y[0] & 1 == 1
        let wantOdd = prefix == 0x03
        if yIsOdd != wantOdd {
            y = P256Curve.modSub(P256Curve.p, y)
        }

        self.x = x
        self.y = y
    }

    /// Serialize to SEC1 uncompressed format (04 || x || y, 65 bytes).
    var uncompressed: Data {
        var data = Data(capacity: 65)
        data.append(0x04)
        data.append(bigIntToBytes(x, count: 32))
        data.append(bigIntToBytes(y, count: 32))
        return data
    }
}

// MARK: - BigUInt Multiplication and Addition

/// Full multiplication of two BigUInts (needed for modular reduction).
func bigMul(_ a: BigUInt, _ b: BigUInt) -> BigUInt {
    let aCount = a.effectiveCount
    let bCount = b.effectiveCount
    if aCount == 0 || bCount == 0 { return BigUInt(0) }

    var result = BigUInt()
    // Ensure enough space
    for i in 0..<(aCount + bCount) {
        result[i] = 0
    }

    for i in 0..<aCount {
        var carry: UInt64 = 0
        for j in 0..<bCount {
            let (high, low) = a[i].multipliedFullWidth(by: b[j])
            let (sum1, overflow1) = result[i + j].addingReportingOverflow(low)
            let (sum2, overflow2) = sum1.addingReportingOverflow(carry)
            result[i + j] = sum2
            carry = high + (overflow1 ? 1 : 0) + (overflow2 ? 1 : 0)
        }
        result[i + bCount] = result[i + bCount] &+ carry
    }
    return result
}

/// Addition of two BigUInts.
func bigAdd(_ a: BigUInt, _ b: BigUInt) -> BigUInt {
    let count = max(a.effectiveCount, b.effectiveCount)
    var result = BigUInt()
    var carry: UInt64 = 0
    for i in 0..<count {
        let (sum1, overflow1) = a[i].addingReportingOverflow(b[i])
        let (sum2, overflow2) = sum1.addingReportingOverflow(carry)
        result[i] = sum2
        carry = (overflow1 ? 1 : 0) + (overflow2 ? 1 : 0)
    }
    if carry > 0 {
        result[count] = carry
    }
    return result
}
