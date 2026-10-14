// DCLTrustStoreFetcherTests.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Testing
import Crypto
import MatterCrypto
import MatterTestSupport
@testable import MatterController

// MARK: - Recorded client

/// Replays recorded responses keyed by request path, and records every request made.
private struct RecordedDCLClient: DCLHTTPClient {

    /// Path (with the `/dcl/pki/` prefix, each segment percent-decoded) to body and status.
    let responses: [String: (Data, Int)]
    let requests: LockedValue<[String]>

    init(_ responses: [String: (Data, Int)]) {
        self.responses = responses
        self.requests = LockedValue([])
    }

    func get(_ url: URL) async throws -> (Data, Int) {
        let text = url.absoluteString
        let prefix = "https://dcl.example"
        precondition(text.hasPrefix(prefix), "unexpected host in \(text)")
        let decoded = text.dropFirst(prefix.count).split(separator: "/", omittingEmptySubsequences: false)
            .map { String($0).removingPercentEncoding ?? String($0) }.joined(separator: "/")
        requests.withLock { $0.append(decoded) }
        return responses[decoded] ?? (Data(), 404)
    }
}

// MARK: - Fixtures

private enum DCLFixtures {

    static let now = SyntheticAttestationChain.date(2026, month: 10, day: 14)
    static let base = URL(string: "https://dcl.example")!

    static let fixtureDirectory = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().appendingPathComponent("Fixtures/DCL")

    private static let file = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().appendingPathComponent("Fixtures/DCL/dcl-recorded.json")

    struct Recorded: Decodable {
        struct Listing: Decodable { let approvedRootCertificates: Roots }
        struct Roots: Decodable { let certs: [Root] }
        struct Root: Decodable { let subject: String; let subjectKeyId: String }
        let rootCertificates: Listing
        let expectedGood: [Good]
        struct Good: Decodable { let file: String; let sha256: String }

        enum CodingKeys: String, CodingKey {
            case rootCertificates = "root-certificates", expectedGood
        }
    }

    static func recorded() throws -> Recorded {
        try JSONDecoder().decode(Recorded.self, from: Data(contentsOf: file))
    }

    static func rawDocument() throws -> [String: Any] {
        try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any])
    }

    /// The fixture's responses as a client would receive them.
    static func recordedResponses() throws -> [String: (Data, Int)] {
        let document = try rawDocument()
        var responses: [String: (Data, Int)] = [:]
        responses["/dcl/pki/root-certificates"] = (
            try JSONSerialization.data(withJSONObject: try #require(document["root-certificates"])), 200)
        for (key, body) in try #require(document["certificates"] as? [String: Any]) {
            let parts = key.split(separator: " ").map(String.init)
            responses["/dcl/pki/certificates/\(parts[0])/\(parts[1])"] = (
                try JSONSerialization.data(withJSONObject: body), 200)
        }
        return responses
    }

    static func der(fromPEM pem: String) throws -> Data {
        let body = pem.split(whereSeparator: \.isNewline).filter { !$0.hasPrefix("-----") }.joined()
        return try #require(Data(base64Encoded: body))
    }

    /// The certificates the recorded response serves under a synthetic listing label.
    static func recordedCertificate(label: String) throws -> Data {
        let document = try rawDocument()
        let certificates = try #require(document["certificates"] as? [String: Any])
        let subject = Data("fixture:\(label)".utf8).base64EncodedString()
        let entry = try #require(certificates.first { $0.key.hasPrefix(subject + " ") }?.value as? [String: Any])
        let certs = try #require((entry["approvedCertificates"] as? [String: Any])?["certs"] as? [[String: Any]])
        return try der(fromPEM: try #require(certs.first?["pemCert"] as? String))
    }

    /// Every real certificate the recorded response serves, in listing order.
    static func recordedGoodCertificates() throws -> [Data] {
        let document = try rawDocument()
        let certificates = try #require(document["certificates"] as? [String: Any])
        var result: [Data] = []
        for root in try recorded().rootCertificates.approvedRootCertificates.certs {
            guard let entry = certificates["\(root.subject) \(root.subjectKeyId)"] as? [String: Any],
                  !String(data: Data(base64Encoded: root.subject) ?? Data(), encoding: .utf8).map({ $0.hasPrefix("fixture:") })!
            else { continue }
            let certs = try #require((entry["approvedCertificates"] as? [String: Any])?["certs"] as? [[String: Any]])
            for cert in certs { result.append(try der(fromPEM: try #require(cert["pemCert"] as? String))) }
        }
        return result
    }

    static func pem(_ der: Data) -> String {
        let body = der.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN CERTIFICATE-----\n\(body)\n-----END CERTIFICATE-----\n"
    }

    /// A one-root response whose single leaf carries `entries`.
    static func response(_ entries: [(der: Data, vid: Any?)]) throws -> [String: (Data, Int)] {
        let subject = "c3ViamVjdA=="
        let ski = "01:02:03"
        let listing: [String: Any] = ["approvedRootCertificates": ["certs": [["subject": subject, "subjectKeyId": ski]]]]
        let certs: [[String: Any]] = entries.map { entry in
            var record: [String: Any] = ["pemCert": pem(entry.der)]
            if let vid = entry.vid { record["vid"] = vid }
            return record
        }
        let leaf: [String: Any] = ["approvedCertificates": ["certs": certs]]
        return [
            "/dcl/pki/root-certificates": (try JSONSerialization.data(withJSONObject: listing), 200),
            "/dcl/pki/certificates/\(subject)/\(ski)": (try JSONSerialization.data(withJSONObject: leaf), 200),
        ]
    }

    static func chain(paa: ClosedRange<Date>) throws -> SyntheticAttestationChain {
        try SyntheticAttestationChain(
            paaValidity: paa, paiValidity: paa, dacValidity: paa)
    }

    static let longValidity = SyntheticAttestationChain.date(2020)...SyntheticAttestationChain.date(2040)

    static func emptyStore() throws -> AttestationTrustStore {
        try AttestationTrustStore(paas: [], cdSigningKeys: [], provenance: TrustStoreProvenance(source: "explicit"))
    }

    static func fetch(
        _ responses: [String: (Data, Int)], current: AttestationTrustStore? = nil
    ) async throws -> (candidate: AttestationTrustStore, diff: TrustStoreDiff) {
        try await DCLTrustStoreFetcher(baseURL: base, client: RecordedDCLClient(responses))
            .fetchProduction(current: try current ?? emptyStore(), now: now)
    }

    static func sha256(_ der: Data) -> Data { Data(SHA256.hash(data: der)) }
}

// MARK: - DCLTrustStoreFetcherTests

@Suite("DCLTrustStoreFetcher Tests", .timeLimit(.minutes(5)))
struct DCLTrustStoreFetcherTests {

    // MARK: - Happy path

    @Test("the recorded DCL builds a candidate and a diff against a store missing one and holding one extra")
    func happyPath() async throws {
        let good = try DCLFixtures.recordedGoodCertificates()
        #expect(good.count == 6)
        let extra = try DCLFixtures.chain(paa: DCLFixtures.longValidity).paa
        let cdKey = try #require(try AttestationTrustStore.bundledCDSigningKeys().first)
        let current = try AttestationTrustStore(
            paas: Array(good.dropFirst()) + [extra], cdSigningKeys: [cdKey],
            provenance: TrustStoreProvenance(source: "explicit"))

        let client = RecordedDCLClient(try DCLFixtures.recordedResponses())
        let (candidate, diff) = try await DCLTrustStoreFetcher(baseURL: DCLFixtures.base, client: client)
            .fetchProduction(current: current, now: DCLFixtures.now)

        #expect(candidate.paas.count == 6)
        #expect(candidate.cdSigningKeys == [cdKey])
        #expect(candidate.provenance == TrustStoreProvenance(source: "dcl:main-net", snapshotDate: DCLFixtures.now))
        #expect(diff.added.map(\.sha256) == [DCLFixtures.sha256(good[0])])
        #expect(diff.removed.map(\.sha256) == [DCLFixtures.sha256(extra)])
        #expect(diff.changed.isEmpty)
        #expect(Set(try DCLFixtures.recorded().expectedGood.map(\.sha256))
            == Set(good.map { DCLFixtures.sha256($0).map { String(format: "%02x", $0) }.joined() }))
    }

    @Test("every certificate returned for one (subject, SKI) is kept, not only the first")
    func keepsEveryCertificate() async throws {
        let (_, diff) = try await DCLFixtures.fetch(try DCLFixtures.recordedResponses())
        let good = try DCLFixtures.recordedGoodCertificates()
        // good[0] and good[1] are served under the first listing entry.
        let hashes = Set(diff.added.map(\.sha256))
        #expect(hashes.contains(DCLFixtures.sha256(good[0])))
        #expect(hashes.contains(DCLFixtures.sha256(good[1])))
        #expect(hashes.count == 6)
    }

    @Test("the recorded entries that fail are excluded with reasons, never thrown")
    func recordedExclusions() async throws {
        let (_, diff) = try await DCLFixtures.fetch(try DCLFixtures.recordedResponses())
        #expect(diff.excluded.count == 3)
        #expect(diff.excluded.contains { $0.contains("P-256") })
        #expect(diff.excluded.contains { $0.contains("not a self-signed CA") })
        #expect(diff.excluded.contains { $0.contains("does not parse") })
    }

    @Test("the CD-signing CA is never requested")
    func skipsCDSigningCA() async throws {
        let client = RecordedDCLClient(try DCLFixtures.recordedResponses())
        _ = try await DCLTrustStoreFetcher(baseURL: DCLFixtures.base, client: client)
            .fetchProduction(current: try DCLFixtures.emptyStore(), now: DCLFixtures.now)
        let requests = client.requests.value
        #expect(requests.contains("/dcl/pki/root-certificates"))
        #expect(requests.count == 1 + 8)
        #expect(!requests.contains { $0.contains("97:E4:69:D0") })
    }

    @Test("path segments are percent-encoded with no safe characters")
    func encodesSegments() async throws {
        let client = RecordedDCLClient(try DCLFixtures.recordedResponses())
        var raw: [String] = []
        let recording = RawURLClient(inner: client, urls: LockedValue([]))
        _ = try await DCLTrustStoreFetcher(baseURL: DCLFixtures.base, client: recording)
            .fetchProduction(current: try DCLFixtures.emptyStore(), now: DCLFixtures.now)
        raw = recording.urls.value
        for url in raw where url.contains("/certificates/") {
            let segments = url.components(separatedBy: "/certificates/")[1]
            #expect(!segments.contains("+") && !segments.contains("=") && !segments.contains(":"))
            #expect(segments.filter { $0 == "/" }.count == 1)
        }
    }

    // MARK: - Exclusions

    @Test("a certificate that is not self-signed is excluded")
    func nonRoot() async throws {
        let chain = try DCLFixtures.chain(paa: DCLFixtures.longValidity)
        let good = try DCLFixtures.chain(paa: DCLFixtures.longValidity).paa
        let (candidate, diff) = try await DCLFixtures.fetch(
            try DCLFixtures.response([(chain.pai, nil), (good, nil)]))
        #expect(candidate.paas.count == 1)
        #expect(diff.excluded.count == 1)
        #expect(diff.excluded[0].contains("not a self-signed CA"))
    }

    @Test("a non-P-256 certificate is excluded")
    func nonP256() async throws {
        let p384 = try DCLFixtures.recordedCertificate(label: "synthetic-p384")
        let good = try DCLFixtures.chain(paa: DCLFixtures.longValidity).paa
        let (candidate, diff) = try await DCLFixtures.fetch(try DCLFixtures.response([(p384, nil), (good, nil)]))
        #expect(candidate.paas.count == 1)
        #expect(diff.excluded.count == 1)
        #expect(diff.excluded[0].contains("P-256"))
    }

    @Test("an expired certificate is excluded")
    func expired() async throws {
        let old = try DCLFixtures.chain(paa: SyntheticAttestationChain.date(2015)...SyntheticAttestationChain.date(2020)).paa
        let good = try DCLFixtures.chain(paa: DCLFixtures.longValidity).paa
        let (candidate, diff) = try await DCLFixtures.fetch(try DCLFixtures.response([(old, nil), (good, nil)]))
        #expect(candidate.paas.count == 1)
        #expect(diff.excluded.count == 1)
        #expect(diff.excluded[0].contains("expired"))
    }

    @Test("a certificate that is not yet valid is excluded")
    func notYetValid() async throws {
        let future = try DCLFixtures.chain(paa: SyntheticAttestationChain.date(2030)...SyntheticAttestationChain.date(2040)).paa
        let good = try DCLFixtures.chain(paa: DCLFixtures.longValidity).paa
        let (_, diff) = try await DCLFixtures.fetch(try DCLFixtures.response([(future, nil), (good, nil)]))
        #expect(diff.excluded.count == 1)
        #expect(diff.excluded[0].contains("not yet valid"))
    }

    @Test("a VID that disagrees with the DCL record is excluded; agreement and absence are accepted")
    func vidMismatch() async throws {
        let a = try DCLFixtures.chain(paa: DCLFixtures.longValidity).paa
        let b = try DCLFixtures.chain(paa: DCLFixtures.longValidity).paa
        let c = try DCLFixtures.chain(paa: DCLFixtures.longValidity).paa
        let d = try DCLFixtures.chain(paa: DCLFixtures.longValidity).paa
        // The synthetic PAAs name VID 0xFFF1 (65521).
        let (candidate, diff) = try await DCLFixtures.fetch(
            try DCLFixtures.response([(a, 0x1234), (b, 0xFFF1), (c, "65521"), (d, nil)]))
        #expect(candidate.paas.count == 3)
        #expect(diff.excluded.count == 1)
        #expect(diff.excluded[0].contains("does not match the DCL record's VID 0x1234"))
    }

    @Test("a certificate swift-certificates cannot parse is excluded with a parse reason")
    func unparseable() async throws {
        let nullParameter = try DCLFixtures.recordedCertificate(label: "synthetic-null-parameter")
        let good = try DCLFixtures.chain(paa: DCLFixtures.longValidity).paa
        let (candidate, diff) = try await DCLFixtures.fetch(
            try DCLFixtures.response([(nullParameter, nil), (Data([0x30, 0x03, 0x01, 0x01, 0x00]), nil), (good, nil)]))
        #expect(candidate.paas.count == 1)
        #expect(diff.excluded.count == 2)
        #expect(diff.excluded.allSatisfy { $0.contains("does not parse") })
    }

    @Test("an invalid PEM body is excluded, not thrown")
    func invalidPEM() async throws {
        let good = try DCLFixtures.chain(paa: DCLFixtures.longValidity).paa
        var responses = try DCLFixtures.response([(good, nil)])
        let leafKey = try #require(responses.keys.first { $0.contains("/certificates/") })
        let leaf = ["approvedCertificates": ["certs": [["pemCert": "not a pem"], ["pemCert": DCLFixtures.pem(good)]]]]
        responses[leafKey] = (try JSONSerialization.data(withJSONObject: leaf), 200)
        let (candidate, diff) = try await DCLFixtures.fetch(responses)
        #expect(candidate.paas.count == 1)
        #expect(diff.excluded.count == 1)
    }

    // MARK: - Failures

    @Test("HTTP 500 on the listing is httpStatus(500)")
    func httpError() async throws {
        await #expect(throws: DCLFetchError.httpStatus(500)) {
            try await DCLFixtures.fetch(["/dcl/pki/root-certificates": (Data(), 500)])
        }
    }

    @Test("a non-200 on a leaf is httpStatus")
    func leafHTTPError() async throws {
        var responses = try DCLFixtures.recordedResponses()
        let leafKey = try #require(responses.keys.first { $0.contains("/certificates/") })
        responses[leafKey] = (Data(), 404)
        await #expect(throws: DCLFetchError.httpStatus(404)) { try await DCLFixtures.fetch(responses) }
    }

    @Test("garbage JSON is malformedResponse")
    func garbageJSON() async throws {
        do {
            _ = try await DCLFixtures.fetch(["/dcl/pki/root-certificates": (Data("not json".utf8), 200)])
            Issue.record("expected malformedResponse")
        } catch let error as DCLFetchError {
            guard case .malformedResponse = error else { Issue.record("got \(error)"); return }
        }
    }

    @Test("valid JSON of the wrong shape is malformedResponse")
    func wrongShape() async throws {
        do {
            _ = try await DCLFixtures.fetch(["/dcl/pki/root-certificates": (Data("{\"x\":1}".utf8), 200)])
            Issue.record("expected malformedResponse")
        } catch let error as DCLFetchError {
            guard case .malformedResponse = error else { Issue.record("got \(error)"); return }
        }
    }

    @Test("no valid roots is noRoots")
    func noRoots() async throws {
        let old = try DCLFixtures.chain(paa: SyntheticAttestationChain.date(2015)...SyntheticAttestationChain.date(2020)).paa
        await #expect(throws: DCLFetchError.noRoots) {
            try await DCLFixtures.fetch(try DCLFixtures.response([(old, nil)]))
        }
        await #expect(throws: DCLFetchError.noRoots) {
            try await DCLFixtures.fetch(["/dcl/pki/root-certificates": (
                Data("{\"approvedRootCertificates\":{\"certs\":[]}}".utf8), 200)])
        }
    }

    // MARK: - No side effects

    @Test("a fetch writes nothing: the fetcher takes no directory and the working directory is unchanged")
    func writesNothing() async throws {
        let cwd = FileManager.default.currentDirectoryPath
        let before = try FileManager.default.subpathsOfDirectory(atPath: DCLFixtures.fixtureDirectory.path).sorted()
        let cwdBefore = try FileManager.default.contentsOfDirectory(atPath: cwd).sorted()
        _ = try await DCLFixtures.fetch(try DCLFixtures.recordedResponses())
        #expect(try FileManager.default.subpathsOfDirectory(atPath: DCLFixtures.fixtureDirectory.path).sorted() == before)
        #expect(try FileManager.default.contentsOfDirectory(atPath: cwd).sorted() == cwdBefore)
    }

    // MARK: - Live

    @Test("the real DCL yields at least one root",
          .enabled(if: ProcessInfo.processInfo.environment["MATTER_LIVE_DCL"] == "1"))
    func live() async throws {
        let (candidate, _) = try await DCLTrustStoreFetcher().fetchProduction(
            current: try AttestationTrustStore.bundledProduction(), now: Date())
        #expect(candidate.paas.count >= 1)
    }
}

// MARK: - Helpers

/// Records the raw (still percent-encoded) URLs, then delegates.
private struct RawURLClient: DCLHTTPClient {
    let inner: RecordedDCLClient
    let urls: LockedValue<[String]>

    func get(_ url: URL) async throws -> (Data, Int) {
        urls.withLock { $0.append(url.absoluteString) }
        return try await inner.get(url)
    }
}
