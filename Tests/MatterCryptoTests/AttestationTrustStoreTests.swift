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

    /// A self-signed (or self-issued) CA certificate. A different `signer` produces a self-issued
    /// certificate whose signature does not verify.
    private static func makePAA(
        commonName: String,
        key: P256.Signing.PrivateKey = .init(),
        isCA: Bool = true,
        withSKI: Bool = true,
        signer: Certificate.PrivateKey? = nil
    ) throws -> Data {
        try makeCertificate(
            commonName: commonName, key: Certificate.PrivateKey(key), algorithm: .ecdsaWithSHA256,
            isCA: isCA, withSKI: withSKI, signer: signer)
    }

    private static func makeCertificate(
        commonName: String,
        key: Certificate.PrivateKey,
        algorithm: Certificate.SignatureAlgorithm,
        isCA: Bool = true,
        withSKI: Bool = true,
        skiBytes: [UInt8]? = nil,
        signer: Certificate.PrivateKey? = nil
    ) throws -> Data {
        let name = try DistinguishedName { CommonName(commonName) }
        let certificate = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: key.publicKey,
            notValidBefore: Date(timeIntervalSince1970: 1_700_000_000),
            notValidAfter: Date(timeIntervalSince1970: 4_000_000_000),
            issuer: name,
            subject: name,
            signatureAlgorithm: algorithm,
            extensions: try Certificate.Extensions {
                Critical(isCA ? BasicConstraints.isCertificateAuthority(maxPathLength: nil) : BasicConstraints.notCertificateAuthority)
                if let skiBytes {
                    SubjectKeyIdentifier(keyIdentifier: ArraySlice(skiBytes))
                } else if withSKI {
                    SubjectKeyIdentifier(hash: key.publicKey)
                }
            },
            issuerPrivateKey: signer ?? key
        )
        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        return Data(serializer.serializedBytes)
    }

    private static func rdn(_ type: ASN1ObjectIdentifier, _ text: String) -> RelativeDistinguishedName {
        RelativeDistinguishedName(.init(type: type, utf8String: text))
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

    @Test("a self-issued CA signed by a different key is rejected")
    func rejectsSelfIssuedForeignSigned() throws {
        let forged = try Self.makePAA(commonName: "Forged", signer: Certificate.PrivateKey(P256.Signing.PrivateKey()))
        #expect(throws: AttestationTrustStoreError.notASelfSignedCA("0")) {
            try Self.store(paas: [forged])
        }
    }

    @Test("a self-signed P-384 CA reports unsupportedKey")
    func rejectsP384() throws {
        let p384 = try Self.makeCertificate(
            commonName: "P-384 root", key: Certificate.PrivateKey(P384.Signing.PrivateKey()),
            algorithm: .ecdsaWithSHA384)
        #expect(throws: AttestationTrustStoreError.unsupportedKey("0")) {
            try Self.store(paas: [p384])
        }
    }

    @Test("a self-signed CA without a SubjectKeyIdentifier is rejected")
    func rejectsMissingSKI() throws {
        let noSKI = try Self.makePAA(commonName: "No SKI", withSKI: false)
        #expect(throws: AttestationTrustStoreError.missingSubjectKeyIdentifier("0")) {
            try Self.store(paas: [noSKI])
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

    @Test("CDSigningKey rejects an empty SubjectKeyIdentifier")
    func cdSigningKeyEmptySKI() throws {
        let der = try Self.makeCertificate(
            commonName: "empty ski", key: Certificate.PrivateKey(P256.Signing.PrivateKey()),
            algorithm: .ecdsaWithSHA256, skiBytes: [])
        #expect(throws: AttestationTrustStoreError.missingSubjectKeyIdentifier("cd-signing-certificate")) {
            try CDSigningKey(certificateDER: der)
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

    @Test("a subdirectory named like a certificate throws naming it")
    func directoryRejectsSubdirectoryNamedDER() throws {
        let directory = try Self.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(
            at: directory.appendingPathComponent("x.der"), withIntermediateDirectories: false)
        #expect(throws: AttestationTrustStoreError.notACertificate("x.der")) {
            try AttestationTrustStore(directory: directory, cdSigningKeys: [])
        }
    }

    @Test("a chip-tool style .der and .pem pair of one certificate loads once")
    func directoryCollapsesDERAndPEMPair() throws {
        let directory = try Self.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let der = try AttestationFixtures.testPAA
        try der.write(to: directory.appendingPathComponent("paa.der"))
        let pem = try Certificate(derEncoded: Array(der)).serializeAsPEM().pemString
        try Data(pem.utf8).write(to: directory.appendingPathComponent("paa.pem"))
        let store = try AttestationTrustStore(directory: directory, cdSigningKeys: [])
        #expect(store.paas.count == 1)
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
        let fileOps = FailingFileOps(failOnMoveNumbers: [2])
        #expect(throws: InjectedFailure.self) {
            try new.write(to: target, fileOps: fileOps)
        }
        #expect(try Self.contents(of: target) == before)
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.path) == ["paa"])
    }

    @Test("two PAAs sharing a key identifier both survive write and reload")
    func sharedSKISurvivesWrite() throws {
        let root = try Self.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let target = root.appendingPathComponent("paa", isDirectory: true)
        let key = P256.Signing.PrivateKey()
        let v1 = try Self.makePAA(commonName: "Reissued v1", key: key)
        let v2 = try Self.makePAA(commonName: "Reissued v2", key: key)
        let original = try Self.store(paas: [v1, v2, v1])  // duplicate bytes collapse
        #expect(original.paas.count == 2)

        try original.write(to: target)
        #expect(try FileManager.default.contentsOfDirectory(atPath: target.path).count == 2)
        let reloaded = try AttestationTrustStore(directory: target, cdSigningKeys: [])
        #expect(reloaded.paas.count == 2)
        #expect(reloaded.diff(from: original).isEmpty)
    }

    @Test("a stranded previous store is restored by init(directory:)")
    func strandedStoreRestoredOnLoad() throws {
        let root = try Self.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let target = root.appendingPathComponent("paa", isDirectory: true)
        try Self.store(paas: [AttestationFixtures.testPAA]).write(to: target)

        // Strand the old store: the swap-in (move 2) and the rollback (move 3) both fail.
        let new = try Self.store(paas: [Self.makePAA(commonName: "New")])
        let fileOps = FailingFileOps(failOnMoveNumbers: [2, 3])
        #expect(throws: InjectedFailure.self) { try new.write(to: target, fileOps: fileOps) }
        #expect(!FileManager.default.fileExists(atPath: target.path))
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.path).count == 1)

        let recovered = try AttestationTrustStore(directory: target, cdSigningKeys: [])
        #expect(recovered.paas.count == 1)
        #expect(try Self.ski(recovered.paas[0]) == Self.ski(Certificate(derEncoded: Array(AttestationFixtures.testPAA))))
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.path) == ["paa"])
    }

    @Test("write(to:) restores a stranded previous store before replacing it")
    func strandedStoreRestoredOnWrite() throws {
        let root = try Self.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let target = root.appendingPathComponent("paa", isDirectory: true)
        try Self.store(paas: [AttestationFixtures.testPAA]).write(to: target)
        let stranding = FailingFileOps(failOnMoveNumbers: [2, 3])
        #expect(throws: InjectedFailure.self) {
            try Self.store(paas: [Self.makePAA(commonName: "Lost")]).write(to: target, fileOps: stranding)
        }

        // The next write fails at the swap-in: the restored original must be what remains.
        let failing = FailingFileOps(failOnMoveNumbers: [3])  // recovery = move 1, aside = 2, swap-in = 3
        #expect(throws: InjectedFailure.self) {
            try Self.store(paas: [Self.makePAA(commonName: "Next")]).write(to: target, fileOps: failing)
        }
        let after = try AttestationTrustStore(directory: target, cdSigningKeys: [])
        #expect(after.paas.count == 1)
        #expect(try Self.ski(after.paas[0]) == Self.ski(Certificate(derEncoded: Array(AttestationFixtures.testPAA))))
    }

    @Test("a failed restore names where the previous store is")
    func failedRestoreNamesLocation() throws {
        let root = try Self.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let target = root.appendingPathComponent("paa", isDirectory: true)
        try Self.store(paas: [AttestationFixtures.testPAA]).write(to: target)
        let stranding = FailingFileOps(failOnMoveNumbers: [2, 3])
        _ = try? Self.store(paas: [Self.makePAA(commonName: "Lost")]).write(to: target, fileOps: stranding)

        let restoring = FailingFileOps(failOnMoveNumbers: [1])
        do {
            _ = try AttestationTrustStore(
                directory: target, cdSigningKeys: [], provenance: nil, fileOps: restoring)
            Issue.record("expected recoveryFailed")
        } catch AttestationTrustStoreError.recoveryFailed(let message) {
            #expect(message.contains(".old-"))
            #expect(message.contains(root.lastPathComponent))
        }
    }

    @Test("two stranded siblings are ambiguous and are not restored")
    func ambiguousStrandedSiblings() throws {
        let root = try Self.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let target = root.appendingPathComponent("paa", isDirectory: true)
        for suffix in ["a", "b"] {
            try FileManager.default.createDirectory(
                at: root.appendingPathComponent("paa.old-\(suffix)"), withIntermediateDirectories: false)
        }
        #expect(throws: (any Error).self) {
            try AttestationTrustStore(directory: target, cdSigningKeys: [])
        }
        #expect(!FileManager.default.fileExists(atPath: target.path))
    }

    @Test("a set-aside copy that cannot be removed is reported with its path")
    func setAsideNotRemoved() throws {
        let root = try Self.makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let target = root.appendingPathComponent("paa", isDirectory: true)
        try Self.store(paas: [AttestationFixtures.testPAA]).write(to: target)
        let fileOps = FailingFileOps(failRemovals: true)
        do {
            try Self.store(paas: [Self.makePAA(commonName: "New")]).write(to: target, fileOps: fileOps)
            Issue.record("expected setAsideNotRemoved")
        } catch AttestationTrustStoreError.setAsideNotRemoved(let path) {
            #expect(path.contains(".old-"))
        }
        // The new store is in place.
        #expect(try AttestationTrustStore(directory: target, cdSigningKeys: []).paas.count == 1)
    }

    // MARK: - Diff

    @Test("diff detects added, removed and changed entries")
    func diffDetectsChanges() throws {
        let kept = try Self.makePAA(commonName: "Kept")
        let removed = try Self.makePAA(commonName: "Removed")
        let added = try Self.makePAA(commonName: "Added")
        let sharedKey = P256.Signing.PrivateKey()
        let before = try Self.makePAA(commonName: "Shared v1", key: sharedKey)
        let after = try Self.makePAA(commonName: "Shared v2", key: sharedKey)

        let oldStore = try Self.store(paas: [kept, removed, before])
        let newStore = try Self.store(paas: [kept, added, after])
        let diff = newStore.diff(from: oldStore)

        // Per certificate: v1 left, v2 arrived. And the shared key identifier's set changed.
        #expect(diff.added.count == 2)
        #expect(diff.removed.count == 2)
        #expect(diff.changed.count == 1)
        #expect(diff.added.contains { $0.subject.contains("Added") })
        #expect(diff.added.contains { $0.subject.contains("Shared v2") })
        #expect(diff.removed.contains { $0.subject.contains("Removed") })
        #expect(diff.removed.contains { $0.subject.contains("Shared v1") })
        #expect(diff.changed.first?.subject.contains("Shared v2") == true)
        #expect(diff.changed.first?.subjectKeyIdentifier == Data(SubjectKeyIdentifier(hash: Certificate.PrivateKey(sharedKey).publicKey).keyIdentifier))
        #expect(diff.excluded.isEmpty)
        #expect(!diff.isEmpty)
    }

    @Test("diff sees the removal of one of two certificates sharing a key identifier")
    func diffSharedSKIRemoval() throws {
        let key = P256.Signing.PrivateKey()
        let v1 = try Self.makePAA(commonName: "Reissued v1", key: key)
        let v2 = try Self.makePAA(commonName: "Reissued v2", key: key)
        let diff = try Self.store(paas: [v2]).diff(from: Self.store(paas: [v1, v2]))
        #expect(diff.added.isEmpty)
        #expect(diff.removed.count == 1)
        #expect(diff.removed.first?.subject.contains("Reissued v1") == true)
        #expect(diff.changed.count == 1)
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
        let ids = try MatterCertificateAttributes.identifiers(in: paa.subject)
        #expect(ids.vendorID == 0xFFF1)
        #expect(ids.productID == nil)

        let store = try Self.store(paas: [AttestationFixtures.testPAA])
        let other = try Self.store(paas: [])
        #expect(store.diff(from: other).added.first?.vendorID == 0xFFF1)
    }

    @Test("DAC subject carries both VID and PID")
    func dacVendorAndProductID() throws {
        let dac = try Certificate(derEncoded: Array(AttestationFixtures.devDAC))
        let ids = try MatterCertificateAttributes.identifiers(in: dac.subject)
        #expect(ids.vendorID == 0xFFF1)
        #expect(ids.productID == 0x8000)
    }

    @Test("legacy CN form uses substring semantics")
    func legacyCommonNameForm() throws {
        func ids(_ cn: String) throws -> (vendorID: UInt16?, productID: UInt16?) {
            try MatterCertificateAttributes.identifiers(in: DistinguishedName { CommonName(cn) })
        }
        let both = try ids("Matter Test Mvid:FFF1 Mpid:8000")
        #expect(both.vendorID == 0xFFF1 && both.productID == 0x8000)
        let glued = try ids("xMvid:FFF1Mpid:00B1y")
        #expect(glued.vendorID == 0xFFF1 && glued.productID == 0x00B1)
        let vidOnly = try ids("Matter Test Mvid:FFF2")
        #expect(vidOnly.vendorID == 0xFFF2 && vidOnly.productID == nil)
        let none = try ids("Matter Test")
        #expect(none.vendorID == nil && none.productID == nil)
        // Prefixes are case sensitive and need the colon: absent, not invalid.
        let wrongPrefix = try ids("MVID:FFF1 Mpid_00B1")
        #expect(wrongPrefix.vendorID == nil && wrongPrefix.productID == nil)
    }

    @Test("a prefix without four uppercase hex digits is invalid")
    func malformedLegacyForm() {
        for cn in ["Mvid:XYZ1 Mpid:0001", "Mvid:fff1", "Mpid:B1", "Mpid:", "Mvid:FFF"] {
            #expect(throws: MatterCertificateAttributes.Failure.self, "\(cn)") {
                try MatterCertificateAttributes.identifiers(in: DistinguishedName { CommonName(cn) })
            }
        }
    }

    @Test("a Matter attribute suppresses the CN form for both ids")
    func oidSuppressesCommonName() throws {
        let name = DistinguishedName([
            Self.rdn(.RDNAttributeType.commonName, "Mvid:FFF1 Mpid:00B1"),
            Self.rdn(MatterCertificateAttributes.productIDOID, "00B2"),
        ])
        let ids = try MatterCertificateAttributes.identifiers(in: name)
        #expect(ids.vendorID == nil)
        #expect(ids.productID == 0x00B2)
    }

    @Test("malformed and duplicate Matter attributes are invalid")
    func malformedOIDAttributes() throws {
        let bad = DistinguishedName([Self.rdn(MatterCertificateAttributes.vendorIDOID, "fff1")])
        #expect(throws: MatterCertificateAttributes.Failure.self) {
            try MatterCertificateAttributes.identifiers(in: bad)
        }
        let duplicate = DistinguishedName([
            Self.rdn(MatterCertificateAttributes.vendorIDOID, "FFF1"),
            Self.rdn(MatterCertificateAttributes.vendorIDOID, "FFF2"),
        ])
        #expect(throws: MatterCertificateAttributes.Failure.self) {
            try MatterCertificateAttributes.identifiers(in: duplicate)
        }
    }

    /// Every upstream fallback-encoding vector, DAC and PAI. Success cases must read the expected
    /// ids; failure cases must throw, be unparseable, or read other ids (which a verifier rejects).
    @Test("upstream VID/PID fallback vectors")
    func fallbackVectors() throws {
        let cases = Dictionary(uniqueKeysWithValues: try AttestationFixtures.negativeCases.map { ($0.name, $0.vector) })
        var rows: [String] = []
        for role in ["dac", "pai"] {
            for number in 1...19 {
                let suffix = String(format: "%02d", number)
                let name = "struct_\(role)_vidpid_fallback_encoding_\(suffix)"
                let vector = try #require(cases[name], "\(name)")
                let der = role == "dac" ? vector.dacCert : vector.paiCert

                var outcome = "unparseable"
                var matches = false
                if let subject = try? Certificate(derEncoded: Array(der)).subject {
                    do {
                        let ids = try MatterCertificateAttributes.identifiers(in: subject)
                        matches = ids.vendorID == 0xFFF1 && ids.productID == vector.basicInfoPID
                        outcome = "ids \(ids.vendorID.map { String($0, radix: 16) } ?? "-")/\(ids.productID.map { String($0, radix: 16) } ?? "-")"
                    } catch {
                        outcome = "throws"
                    }
                }
                rows.append("TABLE \(name) success=\(vector.isSuccessCase) \(outcome) match=\(matches)")
                if vector.isSuccessCase {
                    #expect(matches, "\(name): \(outcome)")
                } else {
                    #expect(!matches, "\(name): \(outcome)")
                }
            }
        }
        for row in rows { print(row) }
    }
}

// MARK: - Fault Injection

private struct InjectedFailure: Error {}

/// A file-operations double that performs real work until a configured call, which throws.
private final class FailingFileOps: AttestationFileOps, @unchecked Sendable {
    private let lock = NSLock()
    private let failOnWriteNumber: Int?
    private let failOnMoveNumbers: Set<Int>
    private let failRemovals: Bool
    private var writes = 0
    private var moves = 0
    private let real = FoundationAttestationFileOps()

    init(failOnWriteNumber: Int? = nil, failOnMoveNumbers: Set<Int> = [], failRemovals: Bool = false) {
        self.failOnWriteNumber = failOnWriteNumber
        self.failOnMoveNumbers = failOnMoveNumbers
        self.failRemovals = failRemovals
    }

    var writeCount: Int { lock.withLock { writes } }

    func createDirectory(at url: URL) throws { try real.createDirectory(at: url) }
    func fileExists(at url: URL) -> Bool { real.fileExists(at: url) }
    func contentsOfDirectory(at url: URL) throws -> [String] { try real.contentsOfDirectory(at: url) }

    func removeItem(at url: URL) throws {
        if failRemovals && url.lastPathComponent.contains(".old-") { throw InjectedFailure() }
        try real.removeItem(at: url)
    }

    func write(_ data: Data, to url: URL) throws {
        let number = lock.withLock { () -> Int in writes += 1; return writes }
        if number == failOnWriteNumber { throw InjectedFailure() }
        try real.write(data, to: url)
    }

    func moveItem(at source: URL, to destination: URL) throws {
        let number = lock.withLock { () -> Int in moves += 1; return moves }
        if failOnMoveNumbers.contains(number) { throw InjectedFailure() }
        try real.moveItem(at: source, to: destination)
    }
}
