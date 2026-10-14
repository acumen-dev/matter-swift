// BundledTrustStoreTests.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Testing
import Crypto
@testable import MatterCrypto
import MatterTestSupport

// MARK: - BundledTrustStoreTests

@Suite("BundledTrustStore Tests", .timeLimit(.minutes(5)))
struct BundledTrustStoreTests {

    // Pinned to the committed snapshot. A refresh changes these deliberately.
    static let pinnedPAACount = 72
    static let pinnedExcludedCount = 1
    static let pinnedCDKeyCount = 5

    private struct Manifest: Decodable {
        struct Entry: Decodable { let file: String; let sha256: String }
        struct Excluded: Decodable { let subject: String; let sha256: String; let reason: String }
        let snapshotDate: String
        let dclEndpoint: String
        let connectedhomeipVersion: String
        let paa: [Entry]
        let cd: [Entry]
        let excluded: [Excluded]
    }

    private static func manifest() throws -> Manifest {
        let url = try AttestationTrustStore.bundleDirectory().appendingPathComponent("manifest.json")
        return try JSONDecoder().decode(Manifest.self, from: Data(contentsOf: url))
    }

    /// A temporary copy of the bundle, removed by the caller.
    private static func copyOfBundle() throws -> URL {
        let copy = FileManager.default.temporaryDirectory
            .appendingPathComponent("bundle-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.copyItem(at: AttestationTrustStore.bundleDirectory(), to: copy)
        return copy
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Loading

    @Test("the bundled snapshot loads with the pinned PAA count and bundled provenance")
    func loads() throws {
        let manifest = try Self.manifest()
        let store = try AttestationTrustStore.bundledProduction()
        #expect(manifest.paa.count == Self.pinnedPAACount)
        #expect(manifest.excluded.count == Self.pinnedExcludedCount)
        #expect(store.paas.count == Self.pinnedPAACount)
        #expect(store.paas.count == manifest.paa.count)
        #expect(store.cdSigningKeys.count == Self.pinnedCDKeyCount)
        #expect(store.provenance.source == "bundled")
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        let date = try #require(store.provenance.snapshotDate)
        let parts = calendar.dateComponents([.year, .month, .day], from: date)
        let expected = manifest.snapshotDate.split(separator: "-").compactMap { Int($0) }
        #expect([parts.year, parts.month, parts.day] == expected.map { Optional($0) })
        #expect(manifest.connectedhomeipVersion == "v1.4.0.0")
        #expect(manifest.dclEndpoint.hasPrefix("https://"))
    }

    @Test("every bundled PAA satisfies the runtime PAA profile")
    func everyBundledPAAConforms() throws {
        let store = try AttestationTrustStore.bundledProduction()
        for certificate in store.paas {
            let violation = MatterAttestationPolicy.profileViolation(certificate, role: .paa)
            #expect(violation == nil, "\(certificate.subject): \(violation ?? "")")
        }
    }

    @Test("every excluded entry names a reason")
    func excludedEntriesAreExplained() throws {
        for entry in try Self.manifest().excluded {
            #expect(!entry.reason.isEmpty && !entry.subject.isEmpty && entry.sha256.count == 64)
        }
    }

    @Test("the fixture test PAAs are not in the production bundle")
    func testPAAsAreAbsent() throws {
        let store = try AttestationTrustStore.bundledProduction()
        let bundled = Set(try Self.manifest().paa.map(\.sha256))
        #expect(bundled.count == store.paas.count)
        #expect(!bundled.contains(Self.sha256(try AttestationFixtures.testPAA)))
        #expect(!bundled.contains(Self.sha256(try AttestationFixtures.testPAANoVID)))
    }

    // MARK: - CD signing keys

    @Test("the bundled CD signing keys are the CSA production set")
    func cdKeys() throws {
        let bundled = try AttestationTrustStore.bundledCDSigningKeys()
        let expected = try AttestationFixtures.productionCDSigningCerts.map { try CDSigningKey(certificateDER: $0) }
        #expect(bundled.count == Self.pinnedCDKeyCount)
        #expect(Set(bundled) == Set(expected))
        let directory = try Self.manifest().cd.map(\.sha256)
        let fixtureHashes = try AttestationFixtures.productionCDSigningCerts.map(Self.sha256)
        #expect(Set(directory) == Set(fixtureHashes))
    }

    @Test("a directory store defaults to the bundled CD signing keys")
    func directoryDefaultsToBundledKeys() throws {
        let empty = FileManager.default.temporaryDirectory
            .appendingPathComponent("empty-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: empty, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: empty) }
        let store = try AttestationTrustStore(directory: empty)
        #expect(Set(store.cdSigningKeys) == Set(try AttestationTrustStore.bundledCDSigningKeys()))
    }

    // MARK: - Integrity

    @Test("an untouched copy loads")
    func copyLoads() throws {
        let copy = try Self.copyOfBundle()
        defer { try? FileManager.default.removeItem(at: copy) }
        #expect(try AttestationTrustStore.loadBundle(at: copy).paas.count == Self.pinnedPAACount)
    }

    @Test("one changed byte is bundleCorrupt", arguments: ["paa", "cd"])
    func changedByte(folder: String) throws {
        let copy = try Self.copyOfBundle()
        defer { try? FileManager.default.removeItem(at: copy) }
        let directory = copy.appendingPathComponent(folder)
        let name = try #require(try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted().first)
        let file = directory.appendingPathComponent(name)
        var data = try Data(contentsOf: file)
        data[data.count - 1] ^= 0x01
        try data.write(to: file)
        Self.expectBundleCorrupt(copy)
    }

    @Test("a removed file is bundleCorrupt", arguments: ["paa", "cd"])
    func removedFile(folder: String) throws {
        let copy = try Self.copyOfBundle()
        defer { try? FileManager.default.removeItem(at: copy) }
        let directory = copy.appendingPathComponent(folder)
        let name = try #require(try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted().first)
        try FileManager.default.removeItem(at: directory.appendingPathComponent(name))
        Self.expectBundleCorrupt(copy)
    }

    @Test("an unlisted file is bundleCorrupt", arguments: ["paa", "cd", "."])
    func extraFile(folder: String) throws {
        let copy = try Self.copyOfBundle()
        defer { try? FileManager.default.removeItem(at: copy) }
        try Data([0x30, 0x00]).write(to: copy.appendingPathComponent(folder).appendingPathComponent("extra.der"))
        Self.expectBundleCorrupt(copy)
    }

    @Test("a missing manifest is bundleCorrupt")
    func missingManifest() throws {
        let copy = try Self.copyOfBundle()
        defer { try? FileManager.default.removeItem(at: copy) }
        try FileManager.default.removeItem(at: copy.appendingPathComponent("manifest.json"))
        Self.expectBundleCorrupt(copy)
    }

    @Test("a duplicate manifest entry is bundleCorrupt")
    func duplicateEntry() throws {
        let copy = try Self.copyOfBundle()
        defer { try? FileManager.default.removeItem(at: copy) }
        try Self.editManifest(in: copy) { manifest in
            var paa = manifest["paa"] as! [[String: Any]]
            paa.append(paa[0])
            manifest["paa"] = paa
        }
        Self.expectBundleCorrupt(copy)
    }

    @Test("a manifest entry that escapes its folder or names a dot-file is bundleCorrupt")
    func escapingEntry() throws {
        // Each case would load cleanly without the guard: the file exists and the hash is true.
        for kind in ["dot-file", "parent-traversal"] {
            let copy = try Self.copyOfBundle()
            defer { try? FileManager.default.removeItem(at: copy) }
            let real = try #require(try Self.manifest().paa.first).file
            let data = try Data(contentsOf: copy.appendingPathComponent(real))
            let name = (real as NSString).lastPathComponent
            let listed: String
            if kind == "dot-file" {
                listed = "paa/.x.der"
                try data.write(to: copy.appendingPathComponent(listed))
            } else {
                listed = "paa/../paa/\(name)"
            }
            try Self.editManifest(in: copy) { manifest in
                var paa = manifest["paa"] as! [[String: Any]]
                paa.append(["file": listed, "sha256": Self.sha256(data)])
                manifest["paa"] = paa
            }
            Self.expectBundleCorrupt(copy)
        }
    }

    @Test("a nested extra directory is bundleCorrupt")
    func nestedExtraDirectory() throws {
        let copy = try Self.copyOfBundle()
        defer { try? FileManager.default.removeItem(at: copy) }
        try FileManager.default.createDirectory(
            at: copy.appendingPathComponent("paa/nested"), withIntermediateDirectories: false)
        Self.expectBundleCorrupt(copy)
    }

    @Test("a tampered manifest hash is bundleCorrupt")
    func tamperedManifestHash() throws {
        let copy = try Self.copyOfBundle()
        defer { try? FileManager.default.removeItem(at: copy) }
        try Self.editManifest(in: copy) { manifest in
            var cd = manifest["cd"] as! [[String: Any]]
            cd[0]["sha256"] = String(repeating: "0", count: 64)
            manifest["cd"] = cd
        }
        Self.expectBundleCorrupt(copy)
    }

    @Test("dot-files such as .DS_Store are tolerated")
    func dotFilesTolerated() throws {
        let copy = try Self.copyOfBundle()
        defer { try? FileManager.default.removeItem(at: copy) }
        for path in [".DS_Store", "paa/.DS_Store", "cd/.DS_Store"] {
            try Data([0x00]).write(to: copy.appendingPathComponent(path))
        }
        #expect(try AttestationTrustStore.loadBundle(at: copy).paas.count == Self.pinnedPAACount)
    }

    private static func editManifest(in directory: URL, _ edit: (inout [String: Any]) -> Void) throws {
        let url = directory.appendingPathComponent("manifest.json")
        var manifest = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        edit(&manifest)
        try JSONSerialization.data(withJSONObject: manifest).write(to: url)
    }

    private static func expectBundleCorrupt(_ directory: URL, sourceLocation: SourceLocation = #_sourceLocation) {
        do {
            _ = try AttestationTrustStore.loadBundle(at: directory)
            Issue.record("expected bundleCorrupt", sourceLocation: sourceLocation)
        } catch let error as AttestationTrustStoreError {
            if case .bundleCorrupt = error { return }
            Issue.record("expected bundleCorrupt, got \(error)", sourceLocation: sourceLocation)
        } catch {
            Issue.record("unexpected error \(error)", sourceLocation: sourceLocation)
        }
    }
}
