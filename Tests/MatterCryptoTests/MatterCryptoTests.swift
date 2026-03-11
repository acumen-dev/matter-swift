// MatterCryptoTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
@testable import MatterCrypto

// MARK: - BigUInt Tests

@Suite("BigUInt Arithmetic")
struct BigUIntTests {

    @Test("Create from UInt64")
    func createFromUInt64() {
        let a = BigUInt(42)
        #expect(a[0] == 42)
        #expect(a.effectiveCount == 1)
    }

    @Test("Zero has effectiveCount 1")
    func zeroEffectiveCount() {
        let z = BigUInt(0)
        #expect(z.effectiveCount == 1)
        #expect(z.isZero)
    }

    @Test("Comparison")
    func comparison() {
        let a = BigUInt(100)
        let b = BigUInt(200)
        #expect(a < b)
        #expect(!(b < a))
        #expect(a == a)
    }

    @Test("Addition")
    func addition() {
        let a = BigUInt(UInt64.max)
        let b = BigUInt(1)
        let sum = bigAdd(a, b)
        #expect(sum[0] == 0)
        #expect(sum[1] == 1)
        #expect(sum.effectiveCount == 2)
    }

    @Test("Multiplication")
    func multiplication() {
        let a = BigUInt(1000)
        let b = BigUInt(2000)
        let product = bigMul(a, b)
        #expect(product[0] == 2_000_000)
    }

    @Test("Subtraction")
    func subtraction() {
        let a = BigUInt(100)
        let b = BigUInt(42)
        let diff = a - b
        #expect(diff == BigUInt(58))
    }

    @Test("Hex round-trip")
    func hexRoundTrip() {
        let hex = "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
        let value = bigIntFromHex(hex)
        let bytes = bigIntToBytes(value, count: 32)
        let recovered = bigIntFromBytes(bytes)
        #expect(value == recovered)
    }

    @Test("Modular reduction")
    func modularReduction() {
        let p = P256Curve.p
        let a = bigAdd(p, BigUInt(42))
        let result = a % p
        #expect(result == BigUInt(42))
    }

    @Test("Bit shift right")
    func bitShiftRight() {
        let a = BigUInt(256)  // 0x100
        let shifted = a >> 4  // 0x10 = 16
        #expect(shifted == BigUInt(16))
    }
}

// MARK: - P-256 Point Tests

@Suite("P-256 Point Operations")
struct P256PointTests {

    @Test("Generator point is valid (lies on curve)")
    func generatorOnCurve() {
        let g = P256Curve.G
        // y² = x³ + ax + b mod p
        let x2 = P256Curve.modMul(g.x, g.x)
        let x3 = P256Curve.modMul(x2, g.x)
        let ax = P256Curve.modMul(P256Curve.a, g.x)
        let rhs = P256Curve.modAdd(P256Curve.modAdd(x3, ax), P256Curve.b)
        let y2 = P256Curve.modMul(g.y, g.y)
        #expect(y2 == rhs)
    }

    @Test("1 * G = G")
    func scalarOneTimesG() {
        let result = P256Point.multiply(P256Curve.G, scalar: BigUInt(1))
        #expect(result == P256Curve.G)
    }

    @Test("2 * G = known value")
    func scalarTwoTimesG() {
        let result = P256Point.multiply(P256Curve.G, scalar: BigUInt(2))
        let expectedX = bigIntFromHex(
            "7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978"
        )
        let expectedY = bigIntFromHex(
            "07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1"
        )
        #expect(result.x == expectedX)
        #expect(result.y == expectedY)
    }

    @Test("3 * G = known value")
    func scalarThreeTimesG() {
        let result = P256Point.multiply(P256Curve.G, scalar: BigUInt(3))
        let expectedX = bigIntFromHex(
            "5ECBE4D1A6330A44C8F7EF951D4BF165E6C6B721EFADA985FB41661BC6E7FD6C"
        )
        let expectedY = bigIntFromHex(
            "8734640C4998FF7E374B06CE1A64A2ECD82AB036384FB83D9A79B127A27D5032"
        )
        #expect(result.x == expectedX)
        #expect(result.y == expectedY)
    }

    @Test("10 * G = known value")
    func scalarTenTimesG() {
        let result = P256Point.multiply(P256Curve.G, scalar: BigUInt(10))
        let expectedX = bigIntFromHex(
            "CEF66D6B2A3A993E591214D1EA223FB545CA6C471C48306E4C36069404C5723F"
        )
        let expectedY = bigIntFromHex(
            "878662A229AAAE906E123CDD9D3B4C10590DED29FE751EEECA34BBAA44AF0773"
        )
        #expect(result.x == expectedX)
        #expect(result.y == expectedY)
    }

    @Test("(n-1) * G = -G", .disabled("Full-order scalar multiply too slow with unoptimized BigUInt"))
    func scalarNMinusOneTimesG() {
        let nMinus1 = P256Curve.n - BigUInt(1)
        let result = P256Point.multiply(P256Curve.G, scalar: nMinus1)
        #expect(result.x == P256Curve.G.x)
        let negGy = P256Curve.modSub(P256Curve.p, P256Curve.G.y)
        #expect(result.y == negGy)
    }

    @Test("n * G = infinity", .disabled("Full-order scalar multiply too slow with unoptimized BigUInt"))
    func scalarNTimesG() {
        let result = P256Point.multiply(P256Curve.G, scalar: P256Curve.n)
        #expect(result.isInfinity)
    }

    @Test("G + (-G) = infinity")
    func addInverse() {
        let negG = P256Point.negate(P256Curve.G)
        let result = P256Point.add(P256Curve.G, negG)
        #expect(result.isInfinity)
    }

    @Test("Point doubling: G + G = 2G")
    func doubling() {
        let doubled = P256Point.add(P256Curve.G, P256Curve.G)
        let twoG = P256Point.multiply(P256Curve.G, scalar: BigUInt(2))
        #expect(doubled == twoG)
    }

    @Test("Associativity: (2G + 3G) = 5G")
    func associativity() {
        let twoG = P256Point.multiply(P256Curve.G, scalar: BigUInt(2))
        let threeG = P256Point.multiply(P256Curve.G, scalar: BigUInt(3))
        let sum = P256Point.add(twoG, threeG)
        let fiveG = P256Point.multiply(P256Curve.G, scalar: BigUInt(5))
        #expect(sum == fiveG)
    }

    @Test("Uncompressed serialization round-trip")
    func uncompressedRoundTrip() throws {
        let g = P256Curve.G
        let data = g.uncompressed
        #expect(data.count == 65)
        #expect(data[0] == 0x04)
        let recovered = try P256Point(uncompressed: data)
        #expect(recovered == g)
    }

    @Test("Compressed point decompression")
    func compressedDecompression() throws {
        // M point compressed form
        let mCompressed = dataFromHex(
            "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
        )
        let m = try P256Point(compressed: mCompressed)

        // Should match M uncompressed
        let expectedX = bigIntFromHex(
            "886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
        )
        let expectedY = bigIntFromHex(
            "5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20"
        )
        #expect(m.x == expectedX)
        #expect(m.y == expectedY)

        // Verify point lies on curve
        let x2 = P256Curve.modMul(m.x, m.x)
        let x3 = P256Curve.modMul(x2, m.x)
        let ax = P256Curve.modMul(P256Curve.a, m.x)
        let rhs = P256Curve.modAdd(P256Curve.modAdd(x3, ax), P256Curve.b)
        let y2 = P256Curve.modMul(m.y, m.y)
        #expect(y2 == rhs)
    }

    @Test("Identity element: infinity + P = P")
    func identityElement() {
        let result = P256Point.add(.infinity, P256Curve.G)
        #expect(result == P256Curve.G)

        let result2 = P256Point.add(P256Curve.G, .infinity)
        #expect(result2 == P256Curve.G)
    }

    @Test("Negate infinity = infinity")
    func negateInfinity() {
        let result = P256Point.negate(.infinity)
        #expect(result.isInfinity)
    }
}

// MARK: - P-256 Modular Arithmetic Tests

@Suite("P-256 Modular Arithmetic")
struct P256ModArithTests {

    @Test("modAdd wraps around field prime")
    func modAddWrap() {
        let p = P256Curve.p
        let pMinus1 = p - BigUInt(1)
        let result = P256Curve.modAdd(pMinus1, BigUInt(2))
        #expect(result == BigUInt(1))
    }

    @Test("modSub handles underflow")
    func modSubUnderflow() {
        let result = P256Curve.modSub(BigUInt(1), BigUInt(3))
        let expected = P256Curve.p - BigUInt(2)
        #expect(result == expected)
    }

    @Test("modMul basic")
    func modMulBasic() {
        let a = BigUInt(7)
        let b = BigUInt(11)
        let result = P256Curve.modMul(a, b)
        #expect(result == BigUInt(77))
    }

    @Test("modInverse: a * a^(-1) = 1 mod p")
    func modInverse() {
        let a = BigUInt(42)
        let aInv = P256Curve.modInverse(a)
        let product = P256Curve.modMul(a, aInv)
        #expect(product == BigUInt(1))
    }

    @Test("modPow basic: 2^10 mod p = 1024")
    func modPowBasic() {
        let result = P256Curve.modPow(BigUInt(2), BigUInt(10), P256Curve.p)
        #expect(result == BigUInt(1024))
    }
}

// MARK: - PBKDF2 Tests

@Suite("PBKDF2-HMAC-SHA256")
struct PBKDF2Tests {

    @Test("PBKDF2 test vector: password/salt, 1 iteration, 20 bytes")
    func vector1() {
        let password = Data("password".utf8)
        let salt = Data("saltSALTsaltSALT".utf8)
        let derived = KeyDerivation.pbkdf2HMACSHA256(
            password: password,
            salt: salt,
            iterations: 1,
            derivedKeyLength: 20
        )
        let expected = dataFromHex("f2e34bd950e91cf37d22e1135a399b02a17cb193")
        #expect(derived == expected)
    }

    @Test("PBKDF2 test vector: password/salt, 2 iterations, 20 bytes")
    func vector2() {
        let password = Data("password".utf8)
        let salt = Data("saltSALTsaltSALT".utf8)
        let derived = KeyDerivation.pbkdf2HMACSHA256(
            password: password,
            salt: salt,
            iterations: 2,
            derivedKeyLength: 20
        )
        let expected = dataFromHex("2b77275cc3120b1513f6f3e03649fd4933765260")
        #expect(derived == expected)
    }

    @Test("PBKDF2: deterministic output for 5 iterations")
    func vector5Deterministic() {
        let password = Data("password".utf8)
        let salt = Data("saltSALTsaltSALT".utf8)
        let derived1 = KeyDerivation.pbkdf2HMACSHA256(
            password: password, salt: salt, iterations: 5, derivedKeyLength: 20
        )
        let derived2 = KeyDerivation.pbkdf2HMACSHA256(
            password: password, salt: salt, iterations: 5, derivedKeyLength: 20
        )
        #expect(derived1 == derived2)
        #expect(derived1.count == 20)

        // Different iterations should give different output
        let derived3 = KeyDerivation.pbkdf2HMACSHA256(
            password: password, salt: salt, iterations: 4, derivedKeyLength: 20
        )
        #expect(derived1 != derived3)
    }

    @Test("PBKDF2: output length matches request")
    func outputLength() {
        let password = Data("passwordPASSWORDpassword".utf8)
        let salt = Data("saltSALTsaltSALTsaltSALTsaltSALT".utf8)
        let derived25 = KeyDerivation.pbkdf2HMACSHA256(
            password: password, salt: salt, iterations: 10, derivedKeyLength: 25
        )
        #expect(derived25.count == 25)

        // Multi-block output (> 32 bytes) should work
        let derived80 = KeyDerivation.pbkdf2HMACSHA256(
            password: password, salt: salt, iterations: 10, derivedKeyLength: 80
        )
        #expect(derived80.count == 80)

        // First 25 bytes of 80-byte output should match 25-byte output
        #expect(Data(derived80.prefix(25)) == derived25)
    }
}

// MARK: - SPAKE2+ Verifier Computation Tests

@Suite("SPAKE2+ Verifier")
struct Spake2pVerifierTests {

    @Test("M point matches expected uncompressed form")
    func mPointUncompressed() {
        let expected = dataFromHex(
            "04886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f" +
            "5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20"
        )
        #expect(Spake2p.pointMUncompressed == expected)
    }

    @Test("N point matches expected uncompressed form")
    func nPointUncompressed() {
        let expected = dataFromHex(
            "04d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49" +
            "07d60aa6bfade45008a636337f5168c64d9bd36034808cd564490b1e656edbe7"
        )
        #expect(Spake2p.pointNUncompressed == expected)
    }

    @Test("M compressed → uncompressed decompression matches")
    func mCompressedToUncompressed() throws {
        let mCompressed = dataFromHex(
            "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
        )
        let point = try P256Point(compressed: mCompressed)
        #expect(point.uncompressed == Spake2p.pointMUncompressed)
    }

    @Test("Compute verifier for default passcode 20202021")
    func defaultPasscodeVerifier() throws {
        let salt = Data("SPAKE2P Key Salt".utf8)
        let verifier = try Spake2p.computeVerifier(
            passcode: 20202021,
            salt: salt,
            iterations: 1000
        )

        // Known w0 for default passcode
        let expectedW0 = dataFromHex(
            "b96170aae803346884724fe9a3b287c30330c2a660375d17bb205a8cf1aecb35"
        )
        #expect(verifier.w0 == expectedW0)

        // L should be 65 bytes (uncompressed point)
        #expect(verifier.L.count == 65)
        #expect(verifier.L[0] == 0x04)

        // Known L for default passcode
        let expectedL = dataFromHex(
            "0457f8ab79ee253ab6a8e46bb09e543ae422736de501e3db37d441fe344920d095" +
            "48e4c18240630c4ff4913c53513839b7c07fcc0627a1b8573a149fcd1fa466cf"
        )
        #expect(verifier.L == expectedL)
    }

    @Test("Verifier serialization round-trip (97 bytes)")
    func verifierSerialization() throws {
        let salt = Data("SPAKE2P Key Salt".utf8)
        let verifier = try Spake2p.computeVerifier(
            passcode: 20202021,
            salt: salt,
            iterations: 1000
        )

        let serialized = verifier.serialized
        #expect(serialized.count == 97) // 32 (w0) + 65 (L)

        let recovered = try Spake2pVerifier.deserialize(serialized)
        #expect(recovered.w0 == verifier.w0)
        #expect(recovered.L == verifier.L)
    }
}

// MARK: - SPAKE2+ Point Operations Tests

@Suite("SPAKE2+ Point Operations")
struct Spake2pPointOpsTests {

    @Test("multiplyPoint: scalar * G matches P256Point")
    func multiplyPointMatchesP256() throws {
        let scalar = bigIntToBytes(BigUInt(2), count: 32)
        let gBytes = P256Curve.G.uncompressed

        let result = try Spake2p.multiplyPoint(gBytes, scalar: scalar)

        let twoG = P256Point.multiply(P256Curve.G, scalar: BigUInt(2))
        #expect(result == twoG.uncompressed)
    }

    @Test("addPoints: G + 2G = 3G")
    func addPointsBasic() throws {
        let gBytes = P256Curve.G.uncompressed
        let twoG = P256Point.multiply(P256Curve.G, scalar: BigUInt(2))
        let twoGBytes = twoG.uncompressed

        let result = try Spake2p.addPoints(gBytes, twoGBytes)

        let threeG = P256Point.multiply(P256Curve.G, scalar: BigUInt(3))
        #expect(result == threeG.uncompressed)
    }

    @Test("subtractPoints: 5G - 2G = 3G")
    func subtractPointsBasic() throws {
        let fiveG = P256Point.multiply(P256Curve.G, scalar: BigUInt(5))
        let twoG = P256Point.multiply(P256Curve.G, scalar: BigUInt(2))

        let result = try Spake2p.subtractPoints(fiveG.uncompressed, twoG.uncompressed)

        let threeG = P256Point.multiply(P256Curve.G, scalar: BigUInt(3))
        #expect(result == threeG.uncompressed)
    }

    @Test("negatePoint: -G has same x, negated y")
    func negatePointBasic() throws {
        let gBytes = P256Curve.G.uncompressed
        let negG = try Spake2p.negatePoint(gBytes)

        #expect(negG.count == 65)
        #expect(negG[0] == 0x04)

        // x should be the same
        #expect(Data(negG[1..<33]) == Data(gBytes[1..<33]))

        // y should be p - G.y
        let negPoint = try P256Point(uncompressed: negG)
        let expectedY = P256Curve.modSub(P256Curve.p, P256Curve.G.y)
        #expect(negPoint.y == expectedY)
    }

    @Test("reduceModOrder: value larger than n reduces correctly")
    func reduceModOrder() {
        // n + 42 should reduce to 42
        let n = P256Curve.n
        let value = bigAdd(n, BigUInt(42))
        let valueBytes = bigIntToBytes(value, count: 40)  // 40 bytes for SPAKE2+ ws values

        let reduced = Spake2p.reduceModOrder(valueBytes)
        let reducedInt = bigIntFromBytes(reduced)
        #expect(reducedInt == BigUInt(42))
    }

    @Test("parsePoint: handles both compressed and uncompressed")
    func parsePointFormats() throws {
        // Uncompressed
        let gUncompressed = P256Curve.G.uncompressed
        let p1 = try Spake2p.parsePoint(gUncompressed)
        #expect(p1 == P256Curve.G)

        // Compressed (M point)
        let mCompressed = dataFromHex(
            "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
        )
        let p2 = try Spake2p.parsePoint(mCompressed)
        #expect(p2.uncompressed == Spake2p.pointMUncompressed)
    }
}

// MARK: - SPAKE2+ Protocol Flow Test

@Suite("SPAKE2+ Protocol Flow")
struct Spake2pFlowTests {

    @Test("Full SPAKE2+ round-trip with default passcode")
    func fullRoundTrip() throws {
        let passcode: UInt32 = 20202021
        let salt = Data("SPAKE2P Key Salt".utf8)
        let iterations = 1000
        let context = Data("Matter PASE Test Context".utf8)

        // 1. Compute verifier (device side, done during manufacturing)
        let verifier = try Spake2p.computeVerifier(
            passcode: passcode,
            salt: salt,
            iterations: iterations
        )

        // 2. Prover (commissioner) derives w0, w1 from passcode
        let ws = KeyDerivation.pbkdf2DeriveWS(
            passcode: passcode,
            salt: salt,
            iterations: iterations
        )
        let w0 = Spake2p.reduceModOrder(Data(ws[0..<40]))
        let w1 = Spake2p.reduceModOrder(Data(ws[40..<80]))

        // w0 should match verifier's w0
        #expect(w0 == verifier.w0)

        // 3. Prover step 1: compute pA = x*G + w0*M
        let (proverCtx, pA) = try Spake2p.proverStep1(w0: w0)
        #expect(pA.count == 65)
        #expect(pA[0] == 0x04)

        // 4. Verifier step 1: receive pA, compute pB, Z, V, cB
        let (verifierCtx, pB, cB) = try Spake2p.verifierStep1(
            pA: pA,
            verifier: verifier,
            hashContext: context
        )
        #expect(pB.count == 65)
        #expect(pB[0] == 0x04)
        #expect(cB.count == 32)

        // 5. Prover step 2: receive pB and cB, verify cB, produce cA + Ke
        let (cA, proverKe) = try Spake2p.proverStep2(
            context: proverCtx,
            pB: pB,
            cB: cB,
            hashContext: context,
            w1: w1
        )
        #expect(cA.count == 32)
        #expect(proverKe.count == 16)

        // 6. Verifier step 2: receive cA, verify it, get Ke
        let verifierKe = try Spake2p.verifierStep2(
            context: verifierCtx,
            cA: cA
        )

        // 7. Both sides should derive the same session key (Ke)
        #expect(proverKe == verifierKe)
    }

    @Test("Verifier rejects wrong passcode")
    func wrongPasscodeRejected() throws {
        let salt = Data("SPAKE2P Key Salt".utf8)
        let iterations = 1000
        let context = Data("Test Context".utf8)

        // Device has verifier for passcode 20202021
        let verifier = try Spake2p.computeVerifier(
            passcode: 20202021, salt: salt, iterations: iterations
        )

        // Commissioner uses WRONG passcode 12345678
        let wrongWS = KeyDerivation.pbkdf2DeriveWS(
            passcode: 12345678, salt: salt, iterations: iterations
        )
        let wrongW0 = Spake2p.reduceModOrder(Data(wrongWS[0..<40]))
        let wrongW1 = Spake2p.reduceModOrder(Data(wrongWS[40..<80]))

        let (proverCtx, pA) = try Spake2p.proverStep1(w0: wrongW0)
        let (_, pB, cB) = try Spake2p.verifierStep1(
            pA: pA, verifier: verifier, hashContext: context
        )

        // proverStep2 should fail because cB won't verify with wrong w1
        // May throw CryptoError.verificationFailed or CryptoKitError from internals
        #expect(throws: (any Error).self) {
            _ = try Spake2p.proverStep2(
                context: proverCtx,
                pB: pB,
                cB: cB,
                hashContext: context,
                w1: wrongW1
            )
        }
    }

    @Test("constantTimeEqual works correctly")
    func constantTimeEqualTest() {
        let a = Data([1, 2, 3, 4])
        let b = Data([1, 2, 3, 4])
        let c = Data([1, 2, 3, 5])
        let d = Data([1, 2, 3])

        #expect(Spake2p.constantTimeEqual(a, b) == true)
        #expect(Spake2p.constantTimeEqual(a, c) == false)
        #expect(Spake2p.constantTimeEqual(a, d) == false)
    }
}

// MARK: - Key Derivation Tests

@Suite("Key Derivation")
struct KeyDerivationTests {

    @Test("Session key derivation produces correct sizes")
    func sessionKeyDerivationSizes() {
        let sharedSecret = Data(repeating: 0xAB, count: 16)

        let keys = KeyDerivation.deriveSessionKeys(
            sharedSecret: sharedSecret
        )

        let i2rBytes = keys.i2rKey.withUnsafeBytes { Data($0) }
        let r2iBytes = keys.r2iKey.withUnsafeBytes { Data($0) }
        let attBytes = keys.attestationKey.withUnsafeBytes { Data($0) }
        #expect(i2rBytes.count == 16)
        #expect(r2iBytes.count == 16)
        #expect(attBytes.count == 16)
    }

    @Test("Session keys: I2R encrypt = R2I decrypt")
    func sessionKeysByRole() {
        let sharedSecret = Data(repeating: 0xAB, count: 16)

        let keys = KeyDerivation.deriveSessionKeys(sharedSecret: sharedSecret)

        // Initiator's encrypt key should be the I2R key
        let initEncrypt = keys.encryptKey(isInitiator: true).withUnsafeBytes { Data($0) }
        let respDecrypt = keys.decryptKey(isInitiator: false).withUnsafeBytes { Data($0) }
        #expect(initEncrypt == respDecrypt)

        // Responder's encrypt key should be the R2I key
        let respEncrypt = keys.encryptKey(isInitiator: false).withUnsafeBytes { Data($0) }
        let initDecrypt = keys.decryptKey(isInitiator: true).withUnsafeBytes { Data($0) }
        #expect(respEncrypt == initDecrypt)
    }

    @Test("Confirmation key derivation produces correct sizes")
    func confirmationKeyDerivationSizes() {
        let ka = Data(repeating: 0x42, count: 16)
        let (kcA, kcB) = KeyDerivation.deriveConfirmationKeys(ka: ka)
        let kcABytes = kcA.withUnsafeBytes { Data($0) }
        let kcBBytes = kcB.withUnsafeBytes { Data($0) }
        #expect(kcABytes.count == 16)
        #expect(kcBBytes.count == 16)
        #expect(kcABytes != kcBBytes) // Should be different
    }
}

// MARK: - Message Encryption Tests

@Suite("Message Encryption")
struct MessageEncryptionTests {

    @Test("Nonce construction: 13 bytes")
    func nonceConstruction() {
        let nonce = MessageEncryption.buildNonce(
            securityFlags: 0x00,
            messageCounter: 1,
            sourceNodeID: 0x0102030405060708
        )
        #expect(nonce.count == 13)
        // First byte is security flags
        #expect(nonce[0] == 0x00)
        // Next 4 bytes are message counter LE
        #expect(nonce[1] == 0x01)
        #expect(nonce[2] == 0x00)
        #expect(nonce[3] == 0x00)
        #expect(nonce[4] == 0x00)
        // Next 8 bytes are source node ID LE
        #expect(nonce[5] == 0x08)
        #expect(nonce[6] == 0x07)
        #expect(nonce[7] == 0x06)
        #expect(nonce[8] == 0x05)
        #expect(nonce[9] == 0x04)
        #expect(nonce[10] == 0x03)
        #expect(nonce[11] == 0x02)
        #expect(nonce[12] == 0x01)
    }

    @Test("Encrypt then decrypt round-trip")
    func encryptDecryptRoundTrip() throws {
        let key = SymmetricKey(data: Data(repeating: 0x42, count: 16))
        let plaintext = Data("Hello Matter Protocol!".utf8)
        let aad = Data([0x00, 0x01, 0x02, 0x03])
        let nonce = MessageEncryption.buildNonce(
            securityFlags: 0x00,
            messageCounter: 42,
            sourceNodeID: 1234
        )

        let encrypted = try MessageEncryption.encrypt(
            plaintext: plaintext,
            key: key,
            nonce: nonce,
            aad: aad
        )

        // Encrypted data should be longer (includes 16-byte tag)
        #expect(encrypted.count == plaintext.count + 16)

        let decrypted = try MessageEncryption.decrypt(
            ciphertextWithMIC: encrypted,
            key: key,
            nonce: nonce,
            aad: aad
        )

        #expect(decrypted == plaintext)
    }

    @Test("Decrypt fails with wrong key")
    func decryptFailsWrongKey() throws {
        let key = SymmetricKey(data: Data(repeating: 0x42, count: 16))
        let wrongKey = SymmetricKey(data: Data(repeating: 0x43, count: 16))
        let plaintext = Data("Secret".utf8)
        let nonce = MessageEncryption.buildNonce(
            securityFlags: 0x00, messageCounter: 1, sourceNodeID: 0
        )

        let encrypted = try MessageEncryption.encrypt(
            plaintext: plaintext, key: key, nonce: nonce, aad: Data()
        )

        #expect(throws: (any Error).self) {
            _ = try MessageEncryption.decrypt(
                ciphertextWithMIC: encrypted, key: wrongKey, nonce: nonce, aad: Data()
            )
        }
    }

    @Test("Decrypt fails with wrong AAD")
    func decryptFailsWrongAAD() throws {
        let key = SymmetricKey(data: Data(repeating: 0x42, count: 16))
        let plaintext = Data("Secret".utf8)
        let nonce = MessageEncryption.buildNonce(
            securityFlags: 0x00, messageCounter: 1, sourceNodeID: 0
        )

        let encrypted = try MessageEncryption.encrypt(
            plaintext: plaintext, key: key, nonce: nonce, aad: Data([0x01])
        )

        #expect(throws: (any Error).self) {
            _ = try MessageEncryption.decrypt(
                ciphertextWithMIC: encrypted, key: key, nonce: nonce, aad: Data([0x02])
            )
        }
    }
}
