// GeneratedCDShapeTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
import SwiftASN1
import MatterTypes
@testable import MatterCrypto
import MatterTestSupport

// MARK: - GeneratedCDShapeTests

/// Pins the shape of the CD `testCredentials` writes against the connectedhomeip fixture, because
/// swift-matter's parser cannot be the oracle for swift-matter's writer. The chip-cert check of
/// the same shape is in ReferenceTests.
@Suite("Generated CD shape", .timeLimit(.minutes(5)))
struct GeneratedCDShapeTests {

    /// sha-256 AlgorithmIdentifier with absent parameters (RFC 5754 §2).
    static let sha256Identifier: [UInt8] = [0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]

    /// The ASN.1 tree with the variable content masked: identifiers and structure are kept, as
    /// are the bytes of OBJECT IDENTIFIERs, INTEGERs and NULLs. OCTET STRINGs and the
    /// primitive `[0]` key identifier are masked, so are the lengths that depend on them.
    static func skeleton(_ node: ASN1Node) -> String {
        let identifier = "\(node.identifier.tagClass)/\(node.identifier.tagNumber)"
        switch node.content {
        case .constructed(let children):
            return "\(identifier)(\(children.map(skeleton).joined(separator: ",")))"
        case .primitive(let bytes):
            let keep = node.identifier == .objectIdentifier || node.identifier == .integer || node.identifier == .null
            return keep ? "\(identifier):\(bytes.map { String(format: "%02x", $0) }.joined())" : "\(identifier):*"
        }
    }

    private static func occurrences(of pattern: [UInt8], in bytes: [UInt8]) -> Int {
        guard bytes.count >= pattern.count else { return 0 }
        return (0...(bytes.count - pattern.count)).filter { Array(bytes[$0..<$0 + pattern.count]) == pattern }.count
    }

    @Test("the generated CD has the fixture's skeleton: algorithm identifiers, versions, sid and OIDs")
    func skeletonMatchesFixture() throws {
        let generated = try DeviceAttestationCredentials.testCredentials().certificationDeclaration
        let fixture = try AttestationFixtures.testCD
        let generatedSkeleton = Self.skeleton(try DER.parse(Array(generated)))
        let fixtureSkeleton = Self.skeleton(try DER.parse(Array(fixture)))
        #expect(generatedSkeleton == fixtureSkeleton)
    }

    @Test("sha-256 appears as the exact AlgorithmIdentifier bytes in SignedData and in SignerInfo")
    func sha256IdentifierBytes() throws {
        for (name, cd) in [
            ("generated", try DeviceAttestationCredentials.testCredentials().certificationDeclaration),
            ("fixture", try AttestationFixtures.testCD),
        ] {
            #expect(Self.occurrences(of: Self.sha256Identifier, in: Array(cd)) == 2, "\(name)")
        }
    }

    // MARK: - Parser tolerance

    private static func cd(signedDataNull: Bool, signerInfoNull: Bool) throws -> Data {
        let pem = String(decoding: try AttestationFixtures.testCDSigningKey, as: UTF8.self)
        return try CertificationDeclarationSigner.sign(
            content: CertificationDeclarationSigner.content(vendorID: 0xFFF1, productIDs: [0x8000]),
            key: try P256.Signing.PrivateKey(pemRepresentation: pem),
            keyIdentifier: CertificationDeclarationSigner.testCDKeyIdentifier,
            signedDataDigestNull: signedDataNull, signerInfoDigestNull: signerInfoNull)
    }

    @Test("NULL parameters on SignerInfo.digestAlgorithm are malformed, as chip-cert print-cd cannot read them")
    func signerInfoNullRejected() throws {
        #expect(throws: CertificationDeclarationError.self) {
            _ = try CertificationDeclaration(cmsDER: try Self.cd(signedDataNull: false, signerInfoNull: true))
        }
    }

    @Test("NULL parameters on SignedData.digestAlgorithms are accepted, as upstream tolerates them")
    func signedDataNullAccepted() throws {
        let cd = try CertificationDeclaration(cmsDER: try Self.cd(signedDataNull: true, signerInfoNull: false))
        #expect(cd.vendorID == 0xFFF1)
        #expect(cd.verifySignature(keys: [try CDSigningKey(certificateDER: AttestationFixtures.testCDSigningCert)]) == .valid)
    }

    @Test("absent parameters in both places parse")
    func absentAccepted() throws {
        _ = try CertificationDeclaration(cmsDER: try Self.cd(signedDataNull: false, signerInfoNull: false))
    }
}
