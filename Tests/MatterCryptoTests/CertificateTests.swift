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
