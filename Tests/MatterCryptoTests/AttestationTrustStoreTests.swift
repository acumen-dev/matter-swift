// AttestationTrustStoreTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
import SwiftASN1
import X509
@testable import MatterCrypto
import MatterTestSupport

@Suite("AttestationTrustStore Tests", .timeLimit(.minutes(5)))
struct AttestationTrustStoreTests {

    // MARK: - Helpers

    private static let provenance = TrustStoreProvenance(source: "explicit")

    private static func makeTemporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("attestation-trust-store-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private static func testCDSigningKey() throws -> CDSigningKey {
        try CDSigningKey(certificateDER: AttestationFixtures.testCDSigningCert)
    }

    private static func store(paas: [Data]) throws -> AttestationTrustStore {
        try AttestationTrustStore(paas: paas, cdSigningKeys: [testCDSigningKey()], provenance: provenance)
    }

    /// A fresh self-signed P-256 CA with a given common name and SKI.
    private static func makePAA(commonName: String, key: P256.Signing.PrivateKey = .init(), isCA: Bool = true) throws -> Data {
        let name = try DistinguishedName { CommonName(commonName) }
        let certificateKey = Certificate.PrivateKey(key)
        let certificate = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: certificateKey.publicKey,
            notValidBefore: Date(timeIntervalSince1970: 1_700_000_000),
            notValidAfter: Date(timeIntervalSince1970: 4_000_000_000),
            issuer: name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(isCA ? BasicConstraints.isCertificateAuthority(maxPathLength: nil) : BasicConstraints.notCertificateAuthority)
                SubjectKeyIdentifier(hash: certificateKey.publicKey)
            },
            issuerPrivateKey: certificateKey
        )
        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        return Data(serializer.serializedBytes)
    }

    private static func contents(of directory: URL) throws -> [String: Data] {
        let names = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        return try Dictionary(uniqueKeysWithValues: names.map {
            ($0, try Data(contentsOf: directory.appendingPathComponent($0)))
        })
    }

    private static func ski(_ certificate: Certificate) throws -> Data {
        Data(try #require(try certificate.extensions.subjectKeyIdentifier).keyIdentifier)
    }

    // MARK: - Explicit

    @Test("explicit init accepts the fixture test PAA")
    func explicitAcceptsTestPAA() throws {
        let store = try Self.store(paas: [AttestationFixtures.testPAA])
        #expect(store.paas.count == 1)
        #expect(store.cdSigningKeys.count == 1)
        #expect(store.provenance == Self.provenance)
    }

    @Test("explicit init rejects the dev DAC as a PAA")
    func explicitRejectsDAC() throws {
        let dac = try AttestationFixtures.devDAC
        #expect(throws: AttestationTrustStoreError.notASelfSignedCA("0")) {
            try Self.store(paas: [dac])
        }
    }

    @Test("explicit init rejects a PAI (a CA, but not self-signed)")
    func explicitRejectsPAI() throws {
        let pai = try AttestationFixtures.devPAI
        #expect(throws: AttestationTrustStoreError.notASelfSignedCA("1")) {
            try Self.store(paas: [AttestationFixtures.testPAA, pai])
        }
    }

    @Test("explicit init rejects bytes that are not a certificate")
    func explicitRejectsGarbage() {
        #expect(throws: AttestationTrustStoreError.notACertificate("0")) {
            try Self.store(paas: [Data([0x01, 0x02, 0x03])])
        }
    }

    @Test("a self-signed certificate that is not a CA is rejected")
    func rejectsSelfSignedLeaf() throws {
        let leaf = try Self.makePAA(commonName: "Self-signed leaf", isCA: false)
        #expect(throws: AttestationTrustStoreError.notASelfSignedCA("0")) {
            try Self.store(paas: [leaf])
        }
    }

    // MARK: - CDSigningKey

    @Test("CDSigningKey derives its identifier from the certificate's SKI")
    func cdSigningKeyIdentifier() throws {
        let der = try AttestationFixtures.testCDSigningCert
        let key = try CDSigningKey(certificateDER: der)
        let parsed = try Certificate(derEncoded: Array(der))
        #expect(key.keyIdentifier == (try Self.ski(parsed)))
        #expect(key.keyIdentifier.count == 20)
    }

    @Test("every CSA production CD signing certificate yields a key")
    func productionCDSigningKeys() throws {
        let keys = try AttestationFixtures.productionCDSigningCerts.map { try CDSigningKey(certificateDER: $0) }
        #expect(keys.count == 5)
        #expect(Set(keys.map(\.keyIdentifier)).count == 5)
    }

    @Test("CDSigningKey rejects a certificate without a SubjectKeyIdentifier")
    func cdSigningKeyMissingSKI() throws {
        let key = Certificate.PrivateKey(P256.Signing.PrivateKey())
        let name = try DistinguishedName { CommonName("no ski") }
        let certificate = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: key.publicKey,
            notValidBefore: Date(timeIntervalSince1970: 1_700_000_000),
            notValidAfter: Date(timeIntervalSince1970: 4_000_000_000),
            issuer: name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions(),
            issuerPrivateKey: key
        )
        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        #expect(throws: AttestationTrustStoreError.missingSubjectKeyIdentifier("cd-signing-certificate")) {
            try CDSigningKey(certificateDER: Data(serializer.serializedBytes))
        }
    }

    // MARK: - Directory

    @Test("directory init loads DER and PEM, ignoring other files")
    func directoryLoadsDERAndPEM() throws {
        let directory = try Self.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let der = try AttestationFixtures.testPAA
        let other = try Self.makePAA(commonName: "Other PAA")
        let otherPEM = try Certificate(derEncoded: Array(other)).serializeAsPEM().pemString
        try der.write(to: directory.appendingPathComponent("test-paa.der"))
        try Data(otherPEM.utf8).write(to: directory.appendingPathComponent("other.pem"))
        try Data("not a certificate".utf8).write(to: directory.appendingPathComponent("README"))
        try Data("ignored".utf8).write(to: directory.appendingPathComponent("notes.txt"))

        let store = try AttestationTrustStore(
            directory: directory, cdSigningKeys: [Self.testCDSigningKey()])
        #expect(store.paas.count == 2)
        #expect(store.provenance.source == "directory")
        let loaded = Set(try store.paas.map { try Self.ski($0) })
        let expected = try Set([der, other].map { try Self.ski(Certificate(derEncoded: Array($0))) })
        #expect(loaded == expected)
    }

    @Test("directory init names the offending file when a .der is not a certificate")
    func directoryRejectsBadDER() throws {
        let directory = try Self.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        try Data([0xDE, 0xAD]).write(to: directory.appendingPathComponent("broken.der"))
        #expect(throws: AttestationTrustStoreError.notACertificate("broken.der")) {
            try AttestationTrustStore(directory: directory, cdSigningKeys: [Self.testCDSigningKey()])
        }
    }

    @Test("directory init honours explicit provenance")
    func directoryProvenance() throws {
        let directory = try Self.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let provenance = TrustStoreProvenance(source: "dcl:main-net", snapshotDate: Date(timeIntervalSince1970: 1_000))
        let store = try AttestationTrustStore(
            directory: directory, cdSigningKeys: [], provenance: provenance)
        #expect(store.provenance == provenance)
        #expect(store.paas.isEmpty)
    }

    // MARK: - Write

    @Test("write then directory init round-trips by SKI and DER")
    func writeRoundTrips() throws {
        let root = try Self.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let target = root.appendingPathComponent("paa", isDirectory: true)

        let original = try Self.store(paas: [AttestationFixtures.testPAA, Self.makePAA(commonName: "Second")])
        try original.write(to: target)
        let reloaded = try AttestationTrustStore(directory: target, cdSigningKeys: original.cdSigningKeys)

        func index(_ store: AttestationTrustStore) throws -> [Data: Data] {
            try Dictionary(uniqueKeysWithValues: store.paas.map { certificate in
                var serializer = DER.Serializer()
                try serializer.serialize(certificate)
                return (try Self.ski(certificate), Data(serializer.serializedBytes))
            })
        }
        #expect(try index(reloaded) == index(original))
        #expect(try index(reloaded).count == 2)
        // No temporary siblings are left behind.
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.path) == ["paa"])
    }

    @Test("write over an existing directory replaces its contents")
    func writeReplacesExisting() throws {
        let root = try Self.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let target = root.appendingPathComponent("paa", isDirectory: true)
        try FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
        try Data("stale".utf8).write(to: target.appendingPathComponent("stale.der"))

        let store = try Self.store(paas: [AttestationFixtures.testPAA])
        try store.write(to: target)

        let names = try FileManager.default.contentsOfDirectory(atPath: target.path)
        #expect(names.count == 1)
        #expect(!names.contains("stale.der"))
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.path) == ["paa"])
    }

    @Test("a failed write leaves the old contents intact and no temporary directory")
    func failedWriteKeepsOldContents() throws {
        let root = try Self.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let target = root.appendingPathComponent("paa", isDirectory: true)

        // Establish old contents through a real write.
        let old = try Self.store(paas: [AttestationFixtures.testPAA])
        try old.write(to: target)
        let before = try Self.contents(of: target)
        #expect(before.count == 1)

        // A new store with three PAAs; the injected failure fires on the second file.
        let new = try Self.store(paas: [
            Self.makePAA(commonName: "A"), Self.makePAA(commonName: "B"), Self.makePAA(commonName: "C"),
        ])
        let fileOps = FailingFileOps(failOnWriteNumber: 2)
        #expect(throws: InjectedFailure.self) {
            try new.write(to: target, fileOps: fileOps)
        }
        #expect(fileOps.writeCount == 2)
        #expect(try Self.contents(of: target) == before)
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.path) == ["paa"])
    }

    @Test("a failed swap restores the previous directory")
    func failedSwapRestores() throws {
        let root = try Self.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let target = root.appendingPathComponent("paa", isDirectory: true)
        try Self.store(paas: [AttestationFixtures.testPAA]).write(to: target)
        let before = try Self.contents(of: target)

        let new = try Self.store(paas: [Self.makePAA(commonName: "A")])
        // Move number 1 sets the old directory aside; number 2 is the swap-in and fails.
        let fileOps = FailingFileOps(failOnMoveNumber: 2)
        #expect(throws: InjectedFailure.self) {
            try new.write(to: target, fileOps: fileOps)
        }
        #expect(try Self.contents(of: target) == before)
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.path) == ["paa"])
    }

    // MARK: - Diff

    @Test("diff detects added, removed and changed entries")
    func diffDetectsChanges() throws {
        let keptKey = P256.Signing.PrivateKey()
        let kept = try Self.makePAA(commonName: "Kept", key: keptKey)
        let removed = try Self.makePAA(commonName: "Removed")
        let added = try Self.makePAA(commonName: "Added")

        // Same key (so same SKI), different subject name (so different DER).
        let sharedKey = P256.Signing.PrivateKey()
        let before = try Self.makePAA(commonName: "Shared v1", key: sharedKey)
        let after = try Self.makePAA(commonName: "Shared v2", key: sharedKey)

        let oldStore = try Self.store(paas: [kept, removed, before])
        let newStore = try Self.store(paas: [kept, added, after])
        let diff = newStore.diff(from: oldStore)

        #expect(diff.added.count == 1)
        #expect(diff.removed.count == 1)
        #expect(diff.changed.count == 1)
        #expect(diff.added.first?.subject.contains("Added") == true)
        #expect(diff.removed.first?.subject.contains("Removed") == true)
        #expect(diff.changed.first?.subject.contains("Shared v2") == true)
        #expect(diff.changed.first?.subjectKeyIdentifier == Data(SubjectKeyIdentifier(hash: Certificate.PrivateKey(sharedKey).publicKey).keyIdentifier))
        #expect(diff.excluded.isEmpty)
        #expect(!diff.isEmpty)
    }

    @Test("diff of a store against itself is empty")
    func diffIdentical() throws {
        let store = try Self.store(paas: [AttestationFixtures.testPAA])
        #expect(store.diff(from: store).isEmpty)
    }

    @Test("a diff with only exclusions is not empty")
    func diffExcludedCounts() {
        var diff = TrustStoreDiff(added: [], removed: [], changed: [], excluded: [])
        #expect(diff.isEmpty)
        diff.excluded = ["vendor 1: bad key"]
        #expect(!diff.isEmpty)
    }

    // MARK: - Matter attributes

    @Test("the PAA's VID is read from the subject attribute")
    func paaVendorID() throws {
        let paa = try Certificate(derEncoded: Array(AttestationFixtures.testPAA))
        #expect(MatterCertificateAttributes.vendorID(in: paa.subject) == 0xFFF1)
        #expect(MatterCertificateAttributes.productID(in: paa.subject) == nil)

        let store = try Self.store(paas: [AttestationFixtures.testPAA])
        let other = try Self.store(paas: [])
        #expect(store.diff(from: other).added.first?.vendorID == 0xFFF1)
    }

    @Test("DAC subject carries both VID and PID")
    func dacVendorAndProductID() throws {
        let dac = try Certificate(derEncoded: Array(AttestationFixtures.devDAC))
        #expect(MatterCertificateAttributes.vendorID(in: dac.subject) == 0xFFF1)
        #expect(MatterCertificateAttributes.productID(in: dac.subject) == 0x8000)
    }

    @Test("VID and PID are read from the legacy CN form")
    func legacyCommonNameForm() throws {
        let name = try DistinguishedName { CommonName("Matter Test Mvid:FFF1 Mpid:8000") }
        #expect(MatterCertificateAttributes.vendorID(in: name) == 0xFFF1)
        #expect(MatterCertificateAttributes.productID(in: name) == 0x8000)

        let vidOnly = try DistinguishedName { CommonName("Matter Test Mvid:FFF2") }
        #expect(MatterCertificateAttributes.vendorID(in: vidOnly) == 0xFFF2)
        #expect(MatterCertificateAttributes.productID(in: vidOnly) == nil)

        let none = try DistinguishedName { CommonName("Matter Test") }
        #expect(MatterCertificateAttributes.vendorID(in: none) == nil)
    }

    @Test("malformed VID text is ignored")
    func malformedVendorID() throws {
        let name = try DistinguishedName { CommonName("Mvid:XYZ1 Mpid:80") }
        #expect(MatterCertificateAttributes.vendorID(in: name) == nil)
        #expect(MatterCertificateAttributes.productID(in: name) == nil)
    }

    @Test("commissioner DUT fixtures exercise the legacy CN form")
    func legacyFormFixtures() throws {
        let cases = Dictionary(uniqueKeysWithValues: try AttestationFixtures.negativeCases.map { ($0.name, $0.vector) })

        func subjects(_ suffix: String) throws -> (dac: DistinguishedName, pai: DistinguishedName) {
            let vector = try #require(cases["struct_dac_vidpid_fallback_encoding_\(suffix)"])
            let pai = try #require(cases["struct_pai_vidpid_fallback_encoding_\(suffix)"])
            return (
                try Certificate(derEncoded: Array(vector.dacCert)).subject,
                try Certificate(derEncoded: Array(pai.paiCert)).subject
            )
        }

        // Well-formed legacy encodings, in either order and comma-separated.
        for suffix in ["01", "02", "03"] {
            let (dac, pai) = try subjects(suffix)
            for name in [dac, pai] {
                #expect(MatterCertificateAttributes.vendorID(in: name) == 0xFFF1, "case \(suffix)")
                #expect(MatterCertificateAttributes.productID(in: name) == 0x00B1, "case \(suffix)")
            }
            // These certificates have no dedicated attribute, so the CN form is what was read.
            #expect(!dac.contains { $0.contains { $0.type == MatterCertificateAttributes.vendorIDOID } })
        }

        // Malformed encodings read as absent: no separator, short VID, lowercase hex, wrong case key.
        for suffix in ["04", "06", "07", "13", "14"] {
            let (dac, _) = try subjects(suffix)
            #expect(MatterCertificateAttributes.vendorID(in: dac) == nil, "case \(suffix)")
        }
    }
}

// MARK: - Fault Injection

private struct InjectedFailure: Error {}

/// A file-operations double that performs real work until the configured call, which throws.
private final class FailingFileOps: AttestationFileOps, @unchecked Sendable {
    private let lock = NSLock()
    private let failOnWriteNumber: Int?
    private let failOnMoveNumber: Int?
    private var writes = 0
    private var moves = 0
    private let real = FoundationAttestationFileOps()

    init(failOnWriteNumber: Int? = nil, failOnMoveNumber: Int? = nil) {
        self.failOnWriteNumber = failOnWriteNumber
        self.failOnMoveNumber = failOnMoveNumber
    }

    var writeCount: Int { lock.withLock { writes } }

    func createDirectory(at url: URL) throws { try real.createDirectory(at: url) }
    func fileExists(at url: URL) -> Bool { real.fileExists(at: url) }
    func removeItem(at url: URL) throws { try real.removeItem(at: url) }

    func write(_ data: Data, to url: URL) throws {
        let number = lock.withLock { () -> Int in writes += 1; return writes }
        if number == failOnWriteNumber { throw InjectedFailure() }
        try real.write(data, to: url)
    }

    func moveItem(at source: URL, to destination: URL) throws {
        let number = lock.withLock { () -> Int in moves += 1; return moves }
        if number == failOnMoveNumber { throw InjectedFailure() }
        try real.moveItem(at: source, to: destination)
    }
}
