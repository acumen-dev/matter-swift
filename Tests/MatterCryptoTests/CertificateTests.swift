// CertificateTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
@testable import MatterCrypto
import MatterTypes

@Suite("Matter Certificate")
struct MatterCertificateTests {

    // MARK: - TLV Round-Trip

    @Test("Certificate TLV round-trip")
    func tlvRoundTrip() throws {
        let key = P256.Signing.PrivateKey()
        let cert = try MatterCertificate.generateRCAC(
            key: key,
            fabricID: FabricID(rawValue: 0x0001)
        )

        let encoded = cert.tlvEncode()
        let decoded = try MatterCertificate.fromTLV(encoded)

        #expect(decoded.serialNumber == cert.serialNumber)
        #expect(decoded.issuer == cert.issuer)
        #expect(decoded.subject == cert.subject)
        #expect(decoded.notBefore == cert.notBefore)
        #expect(decoded.notAfter == cert.notAfter)
        #expect(decoded.publicKey == cert.publicKey)
        #expect(decoded.signature == cert.signature)
        #expect(decoded.extensions.count == cert.extensions.count)
    }

    @Test("Distinguished name TLV round-trip")
    func dnRoundTrip() throws {
        let dn = MatterDistinguishedName(
            nodeID: NodeID(rawValue: 0x0102030405060708),
            rcacID: 42,
            fabricID: FabricID(rawValue: 0xABCD),
            caseAuthenticatedTags: [0x1234, 0x5678]
        )

        let element = dn.toTLVElement()
        let decoded = try MatterDistinguishedName.fromTLVElement(element)

        #expect(decoded.nodeID?.rawValue == 0x0102030405060708)
        #expect(decoded.rcacID == 42)
        #expect(decoded.fabricID?.rawValue == 0xABCD)
        #expect(decoded.caseAuthenticatedTags == [0x1234, 0x5678])
        #expect(decoded.icacID == nil)
        #expect(decoded.firmwareSigningID == nil)
    }

    @Test("NOC distinguished name round-trip")
    func nocDNRoundTrip() throws {
        let dn = MatterDistinguishedName(
            nodeID: NodeID(rawValue: 1),
            fabricID: FabricID(rawValue: 1)
        )

        let element = dn.toTLVElement()
        let decoded = try MatterDistinguishedName.fromTLVElement(element)

        #expect(decoded.nodeID?.rawValue == 1)
        #expect(decoded.fabricID?.rawValue == 1)
        #expect(decoded.rcacID == nil)
    }

    // MARK: - Self-Signed RCAC

    @Test("RCAC is self-signed and verifiable")
    func rcacSelfSigned() throws {
        let key = P256.Signing.PrivateKey()
        let rcac = try MatterCertificate.generateRCAC(
            key: key,
            fabricID: FabricID(rawValue: 1)
        )

        #expect(rcac.verifySelfSigned())
        #expect(rcac.issuer == rcac.subject)
        #expect(rcac.subject.rcacID != nil)
        #expect(rcac.subject.fabricID?.rawValue == 1)
    }

    @Test("RCAC verification fails with wrong key")
    func rcacWrongKey() throws {
        let key = P256.Signing.PrivateKey()
        let wrongKey = P256.Signing.PrivateKey()

        let rcac = try MatterCertificate.generateRCAC(
            key: key,
            fabricID: FabricID(rawValue: 1)
        )

        // Verify with wrong key should fail
        #expect(!rcac.verify(with: wrongKey.publicKey))

        // Self-signed should still pass
        #expect(rcac.verifySelfSigned())
    }

    // MARK: - NOC Chain Validation

    @Test("NOC signed by RCAC validates")
    func nocChainValid() throws {
        let rootKey = P256.Signing.PrivateKey()
        let nodeKey = P256.Signing.PrivateKey()

        let rcac = try MatterCertificate.generateRCAC(
            key: rootKey,
            fabricID: FabricID(rawValue: 1)
        )

        let noc = try MatterCertificate.generateNOC(
            signerKey: rootKey,
            issuerDN: rcac.subject,
            nodePublicKey: nodeKey.publicKey,
            nodeID: NodeID(rawValue: 0x1234),
            fabricID: FabricID(rawValue: 1)
        )

        #expect(MatterCertificate.validateChain(noc: noc, rcac: rcac))
        #expect(noc.subject.nodeID?.rawValue == 0x1234)
        #expect(noc.subject.fabricID?.rawValue == 1)
    }

    @Test("NOC with wrong issuer fails validation")
    func nocWrongIssuer() throws {
        let rootKey1 = P256.Signing.PrivateKey()
        let rootKey2 = P256.Signing.PrivateKey()
        let nodeKey = P256.Signing.PrivateKey()

        let rcac1 = try MatterCertificate.generateRCAC(
            key: rootKey1,
            fabricID: FabricID(rawValue: 1)
        )

        let rcac2 = try MatterCertificate.generateRCAC(
            key: rootKey2,
            fabricID: FabricID(rawValue: 2)
        )

        // Sign NOC with rootKey1 but try to validate against rcac2
        let noc = try MatterCertificate.generateNOC(
            signerKey: rootKey1,
            issuerDN: rcac1.subject,
            nodePublicKey: nodeKey.publicKey,
            nodeID: NodeID(rawValue: 1),
            fabricID: FabricID(rawValue: 1)
        )

        #expect(!MatterCertificate.validateChain(noc: noc, rcac: rcac2))
    }

    @Test("Tampered certificate fails verification")
    func tamperedCert() throws {
        let rootKey = P256.Signing.PrivateKey()

        let rcac = try MatterCertificate.generateRCAC(
            key: rootKey,
            fabricID: FabricID(rawValue: 1)
        )

        // Create a tampered cert by changing the fabric ID but keeping the signature
        let tampered = MatterCertificate(
            serialNumber: rcac.serialNumber,
            issuer: rcac.issuer,
            notBefore: rcac.notBefore,
            notAfter: rcac.notAfter,
            subject: MatterDistinguishedName(
                rcacID: rcac.subject.rcacID,
                fabricID: FabricID(rawValue: 999) // changed!
            ),
            publicKey: rcac.publicKey,
            extensions: rcac.extensions,
            signature: rcac.signature
        )

        #expect(!tampered.verifySelfSigned())
    }

    // MARK: - ICAC Chain

    @Test("NOC signed by ICAC signed by RCAC validates")
    func nocIcacChainValid() throws {
        let rootKey = P256.Signing.PrivateKey()
        let icacKey = P256.Signing.PrivateKey()
        let nodeKey = P256.Signing.PrivateKey()

        let rcac = try MatterCertificate.generateRCAC(
            key: rootKey,
            fabricID: FabricID(rawValue: 1)
        )

        // Generate ICAC signed by RCAC
        let icac = try MatterCertificate.generateNOC(
            signerKey: rootKey,
            issuerDN: rcac.subject,
            nodePublicKey: icacKey.publicKey,
            nodeID: NodeID(rawValue: 0), // ICAC doesn't have a nodeID, but we reuse generateNOC
            fabricID: FabricID(rawValue: 1)
        )
        // For a proper ICAC, we'd want isCA=true — but for chain validation test,
        // signature verification is what matters

        let noc = try MatterCertificate.generateNOC(
            signerKey: icacKey,
            issuerDN: icac.subject,
            nodePublicKey: nodeKey.publicKey,
            nodeID: NodeID(rawValue: 0x5678),
            fabricID: FabricID(rawValue: 1)
        )

        #expect(MatterCertificate.validateChain(noc: noc, icac: icac, rcac: rcac))
    }

    // MARK: - Certificate Extensions

    @Test("Certificate extensions round-trip")
    func extensionsRoundTrip() throws {
        let key = P256.Signing.PrivateKey()
        let rcac = try MatterCertificate.generateRCAC(
            key: key,
            fabricID: FabricID(rawValue: 1)
        )

        // RCAC should have basicConstraints, keyUsage, SKID, AKID
        let encoded = rcac.tlvEncode()
        let decoded = try MatterCertificate.fromTLV(encoded)

        #expect(decoded.extensions.count == 4)

        // Check basic constraints
        if case .basicConstraints(let isCA, let pathLength) = decoded.extensions[0] {
            #expect(isCA == true)
            #expect(pathLength == 1)
        } else {
            Issue.record("Expected basicConstraints")
        }

        // Check key usage
        if case .keyUsage(let usage) = decoded.extensions[1] {
            #expect(usage.contains(.keyCertSign))
            #expect(usage.contains(.crlSign))
        } else {
            Issue.record("Expected keyUsage")
        }
    }
}

// MARK: - Fabric Info Tests

@Suite("Fabric Info")
struct FabricInfoTests {

    @Test("Generate test fabric with valid chain")
    func testFabricGeneration() throws {
        let (fabric, _) = try FabricInfo.generateTestFabric(
            fabricID: FabricID(rawValue: 0xABCD),
            nodeID: NodeID(rawValue: 0x1234)
        )

        #expect(fabric.fabricID.rawValue == 0xABCD)
        #expect(fabric.nodeID.rawValue == 0x1234)
        #expect(fabric.validateChain())
    }

    @Test("Compressed fabric ID is deterministic")
    func compressedFabricIDDeterministic() throws {
        let (fabric, _) = try FabricInfo.generateTestFabric()

        let cfid1 = fabric.compressedFabricID()
        let cfid2 = fabric.compressedFabricID()

        #expect(cfid1 == cfid2)
        #expect(cfid1 != 0) // Should not be zero
    }

    @Test("Different fabrics produce different compressed IDs")
    func compressedFabricIDUnique() throws {
        let (fabric1, _) = try FabricInfo.generateTestFabric(fabricID: FabricID(rawValue: 1))
        let (fabric2, _) = try FabricInfo.generateTestFabric(fabricID: FabricID(rawValue: 2))

        #expect(fabric1.compressedFabricID() != fabric2.compressedFabricID())
    }

    /// Verify CompressedFabricID uses HKDF-SHA256 (not HMAC) and the full 64-byte raw key
    /// (X‖Y without the 0x04 uncompressed prefix) as IKM, per the CHIP SDK behaviour.
    ///
    /// Two regressions this test guards against:
    ///   1. Using HMAC-SHA256 instead of HKDF-SHA256.
    ///   2. Using only the 32-byte X coordinate instead of the full 64-byte X‖Y raw key.
    ///
    /// The Matter spec §4.3.1.2.2 says "InputKey = RootPublicKey.X" which is misleading —
    /// the CHIP SDK passes the full 64-byte raw key (X‖Y without 0x04 prefix). Using X only
    /// produces a CFID that homed rejects (discovered via live Apple Home commissioning).
    @Test("CompressedFabricID uses HKDF-SHA256 with 64-byte X‖Y IKM — Matter spec §4.3.1.2.2")
    func compressedFabricIDUsesHKDF() throws {
        let fabricID = FabricID(rawValue: 0xFAB0000000000001)
        let (fabric, _) = try FabricInfo.generateTestFabric(fabricID: fabricID)

        // Reference: HKDF-SHA256(IKM=X‖Y (64 bytes), salt=BE8(fabricID), info="CompressedFabric", len=8)
        let rootKeyX963 = fabric.rootPublicKey.x963Representation
        let rawKey = rootKeyX963[1...]   // 64 bytes: X‖Y, skip the 0x04 uncompressed prefix
        let ikm = SymmetricKey(data: rawKey)

        var salt = Data(count: 8)
        let fid = fabric.fabricID.rawValue
        for i in 0..<8 { salt[i] = UInt8((fid >> (56 - i * 8)) & 0xFF) }

        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm,
            salt: salt,
            info: Data("CompressedFabric".utf8),
            outputByteCount: 8
        )
        var reference: UInt64 = 0
        derived.withUnsafeBytes { bytes in
            for i in 0..<8 { reference = (reference << 8) | UInt64(bytes[i]) }
        }

        let computed = fabric.compressedFabricID()
        #expect(computed == reference,
            "CFID \(String(format: "%016llX", computed)) ≠ HKDF reference \(String(format: "%016llX", reference))")

        // Regression: HMAC(key=X‖Y, data=fabricID) must NOT match
        let hmacResult = HMAC<SHA256>.authenticationCode(
            for: salt,
            using: SymmetricKey(data: rawKey)
        )
        var hmacValue: UInt64 = 0
        hmacResult.withUnsafeBytes { bytes in
            for i in 0..<8 { hmacValue = (hmacValue << 8) | UInt64(bytes[i]) }
        }
        #expect(computed != hmacValue,
            "CFID must NOT equal HMAC(key=X‖Y, data=fabricID) — that was the old broken implementation")

        // Regression: using X-only (32 bytes) as IKM must produce a different (wrong) value
        let xOnlyIkm = SymmetricKey(data: rootKeyX963[1..<33])
        let xOnlyDerived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: xOnlyIkm,
            salt: salt,
            info: Data("CompressedFabric".utf8),
            outputByteCount: 8
        )
        var xOnlyValue: UInt64 = 0
        xOnlyDerived.withUnsafeBytes { bytes in
            for i in 0..<8 { xOnlyValue = (xOnlyValue << 8) | UInt64(bytes[i]) }
        }
        #expect(computed != xOnlyValue,
            "CFID must NOT equal HKDF(IKM=X-only) — that was the second broken implementation")
    }

    /// Known-good vector from a live Apple Home commissioning session.
    ///
    /// Confirms the root cause discovered via independent Python verification (Tools/verify_cfid.py):
    /// the CHIP SDK uses the full 64-byte raw key (X‖Y without 0x04 prefix) as HKDF IKM,
    /// NOT just the 32-byte X coordinate. The spec's wording "RootPublicKey.X" is misleading.
    ///
    /// Session data:
    ///   fabricID (from NOC subject, context tag 21): 0x00000000F48338FE
    ///   RCAC public key (TLV tag 9, 65 bytes, 04‖X‖Y):
    ///     X: 1AB7B3416351C26DF1CB9633D67DC2355DF06425779C702CF62E85FC95C6E3B5
    ///   homed expected CFID (from operational-discovery logs): A26056B529C53957
    ///
    /// Verified:
    ///   HKDF(IKM=X-only (32 bytes), salt=BE8(fabricID), info="CompressedFabric") = D2227ED9E91CEEFC  ← wrong
    ///   HKDF(IKM=X‖Y   (64 bytes), salt=BE8(fabricID), info="CompressedFabric") = A26056B529C53957  ← correct (matches homed)
    ///
    /// This test documents the confirmed X-only result as a regression guard; the FabricInfo
    /// implementation now uses 64-byte IKM and will produce A26056B529C53957 for this session.
    /// (The Y coordinate is not captured in the test data, so we only verify the X-only path here.)
    @Test("CompressedFabricID — Apple Home live commissioning vector (root cause confirmed)")
    func compressedFabricIDAppleHomeVector() throws {
        // fabricID from NOC subject, context tag 21
        let fabricIDValue: UInt64 = 0x00000000F48338FE
        // X coordinate from RCAC public key (TLV tag 9, bytes [1..<33] of 04‖X‖Y)
        let knownX = Data([
            0x1A, 0xB7, 0xB3, 0x41, 0x63, 0x51, 0xC2, 0x6D,
            0xF1, 0xCB, 0x96, 0x33, 0xD6, 0x7D, 0xC2, 0x35,
            0x5D, 0xF0, 0x64, 0x25, 0x77, 0x9C, 0x70, 0x2C,
            0xF6, 0x2E, 0x85, 0xFC, 0x95, 0xC6, 0xE3, 0xB5,
        ])

        var salt = Data(count: 8)
        for i in 0..<8 { salt[i] = UInt8((fabricIDValue >> (56 - i * 8)) & 0xFF) }

        // HKDF with X-only (32 bytes) — the old wrong algorithm
        let xOnlyDerived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: knownX),
            salt: salt,
            info: Data("CompressedFabric".utf8),
            outputByteCount: 8
        )
        var xOnlyCFID: UInt64 = 0
        xOnlyDerived.withUnsafeBytes { bytes in
            for i in 0..<8 { xOnlyCFID = (xOnlyCFID << 8) | UInt64(bytes[i]) }
        }

        // X-only gives the wrong value — confirmed via Python verify_cfid.py
        #expect(xOnlyCFID == 0xD2227ED9E91CEEFC,
            "X-only HKDF should give D2227ED9E91CEEFC, got \(String(format: "%016llX", xOnlyCFID))")

        // The correct CFID (matching homed) requires X‖Y (64 bytes) as IKM.
        // Verified externally: HKDF(IKM=X‖Y, salt=BE8(fabricID), info="CompressedFabric") = A26056B529C53957
        // The Y coordinate is not captured in this test's static data, so we assert the known-wrong
        // value above and document the expected correct value here.
        let expectedCorrectCFID: UInt64 = 0xA26056B529C53957
        #expect(xOnlyCFID != expectedCorrectCFID,
            "X-only HKDF must differ from the correct (X‖Y) result — confirms the two algorithms diverge")
    }

    @Test("IPK derivation produces 16 bytes")
    func ipkDerivation() throws {
        let (fabric, _) = try FabricInfo.generateTestFabric()

        let ipk = fabric.deriveIPK()
        #expect(ipk.count == 16)
    }

    @Test("IPK is deterministic for same fabric")
    func ipkDeterministic() throws {
        let (fabric, _) = try FabricInfo.generateTestFabric()

        let ipk1 = fabric.deriveIPK()
        let ipk2 = fabric.deriveIPK()

        #expect(ipk1 == ipk2)
    }

    @Test("Root public key matches RCAC")
    func rootPublicKeyMatchesRCAC() throws {
        let (fabric, rootKey) = try FabricInfo.generateTestFabric()

        let expected = rootKey.publicKey.x963Representation
        let actual = fabric.rootPublicKey.x963Representation

        #expect(Data(expected) == Data(actual))
    }
}
