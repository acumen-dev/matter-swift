// DCLTrustStoreFetcherTests.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Testing
import Crypto
import MatterCrypto
import MatterTestSupport
@testable import MatterController

// MARK: - Recorded client

/// Replays canned responses and records every request.
private struct RecordedDCLClient: DCLHTTPClient {

    /// "roots", or "<subject>\n<ski>" for a leaf, to body and status.
    let responses: [String: (Data, Int)]
    /// The raw (still percent-encoded) URLs requested.
    let requests: LockedValue<[String]>

    init(_ responses: [String: (Data, Int)]) {
        self.responses = responses
        self.requests = LockedValue([])
    }

    func get(_ url: URL) async throws -> (Data, Int) {
        let text = url.absoluteString
        requests.withLock { $0.append(text) }
        let path = String(text.dropFirst(DCLFixtures.base.absoluteString.count))
        let key: String
        if path == "/dcl/pki/root-certificates" {
            key = "roots"
        } else if path.hasPrefix("/dcl/pki/certificates/") {
            let segments = path.dropFirst("/dcl/pki/certificates/".count).split(separator: "/", omittingEmptySubsequences: false)
            key = segments.map { String($0).removingPercentEncoding ?? String($0) }.joined(separator: "\n")
        } else {
            key = path
        }
        return responses[key] ?? (Data(), 404)
    }
}

// MARK: - Fixtures

private enum DCLFixtures {

    static let now = SyntheticAttestationChain.date(2026, month: 10, day: 14)
    static let base = URL(string: "https://dcl.example")!

    static let directory = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()  // MatterControllerTests/
        .deletingLastPathComponent()  // Tests/
        .appendingPathComponent("Fixtures/DCL")

    static func json(_ name: String) throws -> [String: Any] {
        try #require(try JSONSerialization.jsonObject(
            with: Data(contentsOf: directory.appendingPathComponent(name))) as? [String: Any])
    }

    static func derFromPEM(_ pem: String) throws -> Data {
        let body = pem.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("-----") }.joined()
        return try #require(Data(base64Encoded: body))
    }

    static func pem(_ der: Data) -> String {
        let body = der.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN CERTIFICATE-----\n\(body)\n-----END CERTIFICATE-----\n"
    }

    static func key(_ subject: String, _ ski: String) -> String { "\(subject)\n\(ski)" }

    static func body(_ object: Any) throws -> (Data, Int) { (try JSONSerialization.data(withJSONObject: object), 200) }

    // MARK: Recorded (real) responses

    struct Leaf {
        let subject: String
        let ski: String
        let body: [String: Any]
        let certs: [[String: Any]]
        var der: Data { get throws { try derFromPEM(try #require(certs[0]["pemCert"] as? String)) } }
        var vid: Int? { certs[0]["vid"] as? Int }
        var text: String { certs[0]["subjectAsText"] as? String ?? "" }
    }

    static func recordedLeaves() throws -> [Leaf] {
        try (try #require(json("dcl-recorded.json")["leaves"] as? [[String: Any]])).map { leaf in
            let set = try #require(leaf["approvedCertificates"] as? [String: Any])
            return Leaf(
                subject: try #require(set["subject"] as? String), ski: try #require(set["subjectKeyId"] as? String),
                body: leaf, certs: try #require(set["certs"] as? [[String: Any]]))
        }
    }

    static func recordedResponses() throws -> [String: (Data, Int)] {
        var responses = ["roots": try body(try #require(json("dcl-recorded.json")["root-certificates"]))]
        for leaf in try recordedLeaves() { responses[key(leaf.subject, leaf.ski)] = try body(leaf.body) }
        return responses
    }

    /// The recorded roots that are PAAs the fetcher should keep (everything but the NXP PAA).
    static func recordedLeaf(containing text: String) throws -> Leaf {
        try #require(try recordedLeaves().first { $0.text.contains(text) })
    }

    // MARK: Synthetic entries

    struct Synthetic {
        let label: String
        let subject: String
        let ski: String
        let certs: [[String: Any]]
    }

    static func synthetic(_ label: String) throws -> Synthetic {
        let entries = try #require(json("dcl-synthetic.json")["entries"] as? [[String: Any]])
        let entry = try #require(entries.first { $0["label"] as? String == label })
        return Synthetic(
            label: label, subject: try #require(entry["subject"] as? String), ski: try #require(entry["subjectKeyId"] as? String),
            certs: try #require(entry["certs"] as? [[String: Any]]))
    }

    static func syntheticDER(_ label: String) throws -> Data {
        try derFromPEM(try #require(try synthetic(label).certs[0]["pemCert"] as? String))
    }

    /// A response made of listing entries `(subject, ski, certs)`, each served as its own leaf.
    static func response(_ roots: [(subject: String, ski: String, certs: [[String: Any]])]) throws -> [String: (Data, Int)] {
        let listing: [String: Any] = ["approvedRootCertificates": [
            "certs": roots.map { ["subject": $0.subject, "subjectKeyId": $0.ski] }]]
        var responses = ["roots": try body(listing)]
        for root in roots {
            responses[key(root.subject, root.ski)] = try body(
                ["approvedCertificates": ["subject": root.subject, "subjectKeyId": root.ski, "certs": root.certs]])
        }
        return responses
    }

    static func response(_ entries: [Synthetic]) throws -> [String: (Data, Int)] {
        try response(entries.map { ($0.subject, $0.ski, $0.certs) })
    }

    /// One listing entry serving `ders`, each record with the given `vid`.
    static func response(serving ders: [Data], vid: Any = 0) throws -> [String: (Data, Int)] {
        try response([("c3ViamVjdA==", "01:02:03", ders.map { ["pemCert": pem($0), "vid": vid] })])
    }

    // MARK: Fetching

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

    static let longValidity = SyntheticAttestationChain.date(2020)...SyntheticAttestationChain.date(2040)

    static func syntheticPAA(validity: ClosedRange<Date>? = nil) throws -> Data {
        let range = validity ?? longValidity
        return try SyntheticAttestationChain(paaValidity: range, paiValidity: range, dacValidity: range).paa
    }
}

// MARK: - DCLTrustStoreFetcherTests

@Suite("DCLTrustStoreFetcher Tests", .timeLimit(.minutes(5)))
struct DCLTrustStoreFetcherTests {

    // MARK: - Recorded DCL

    @Test("the recorded DCL builds a candidate and a diff against a store missing one and holding one extra")
    func happyPath() async throws {
        let leaves = try DCLFixtures.recordedLeaves()
        #expect(leaves.count == 7)
        let good = try leaves.filter { !$0.text.contains("NXP") }.map { try $0.der }
        #expect(good.count == 6)
        let extra = try DCLFixtures.syntheticPAA()
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
        // The one real certificate swift-certificates cannot parse is excluded, not thrown.
        #expect(diff.excluded.count == 1)
        #expect(diff.excluded[0].contains("does not parse"))
        // The CD-signing CA is listed but never requested.
        #expect(client.requests.value.count == 1 + 7)
        #expect(!client.requests.value.contains { $0.contains("97%3AE4%3A69%3AD0") })
    }

    @Test("records with vid 0 whose subjects name a VID are accepted: 0 means absent")
    func zeroVIDIsAbsent() async throws {
        let zero = try DCLFixtures.recordedLeaves().filter { $0.vid == 0 && $0.text.contains("vid=0x") }
        #expect(zero.count == 3)
        let (candidate, diff) = try await DCLFixtures.fetch(try DCLFixtures.recordedResponses())
        let kept = Set(diff.added.map(\.sha256))
        for leaf in zero { #expect(kept.contains(DCLFixtures.sha256(try leaf.der)), "\(leaf.text)") }
        #expect(candidate.paas.count == 6)
        #expect(!diff.excluded.contains { $0.contains("does not match") })
    }

    // MARK: - Synthetic exclusions

    @Test("synthetic entries that fail are excluded with a reason, and good neighbours survive",
          arguments: [
            ("p384", "P-256"), ("not-self-signed", "not a self-signed CA"), ("null-parameter", "does not parse"),
            ("not-der", "does not parse"), ("pid-in-subject", "carries a PID"),
            ("vid-mismatch", "does not match the DCL record's VID 0x117D"),
          ])
    func syntheticExclusion(label: String, reason: String) async throws {
        let good = try DCLFixtures.recordedLeaf(containing: "Feit")
        let (candidate, diff) = try await DCLFixtures.fetch(try DCLFixtures.response([
            (good.subject, good.ski, good.certs), DCLFixtures.synthetic(label).asRoot,
        ]))
        #expect(candidate.paas.count == 1)
        #expect(diff.excluded.count == 1)
        #expect(diff.excluded[0].contains(reason), "\(diff.excluded)")
    }

    @Test("assessPAA rejects a PAA whose subject carries a PID")
    func assessmentRejectsPID() throws {
        let assessment = AttestationTrustStore.assessPAA(try DCLFixtures.syntheticDER("pid-in-subject"))
        #expect(assessment.rejection == "carries a PID")
        #expect(assessment.vendorID == 0xFFF1)
    }

    @Test("a listing subject containing '/' and '+' is percent-encoded, and its certificate accepted")
    func encodesSegments() async throws {
        let entry = try DCLFixtures.synthetic("slash-and-plus")
        #expect(entry.subject.contains("/") && entry.subject.contains("+"))
        let client = RecordedDCLClient(try DCLFixtures.response([entry]))
        let (candidate, _) = try await DCLTrustStoreFetcher(baseURL: DCLFixtures.base, client: client)
            .fetchProduction(current: try DCLFixtures.emptyStore(), now: DCLFixtures.now)
        #expect(candidate.paas.count == 1)
        #expect(client.requests.value.last == "https://dcl.example/dcl/pki/certificates/a%2Bb%2Fc%2Bd%2Fe%3D%3D/AB%3ACD%3AEF%3A01")
    }

    @Test("every certificate in a leaf is kept, not only the first")
    func keepsEveryCertificate() async throws {
        let a = try DCLFixtures.recordedLeaf(containing: "Feit").der
        let b = try DCLFixtures.recordedLeaf(containing: "Legrand").der
        let (candidate, diff) = try await DCLFixtures.fetch(try DCLFixtures.response(serving: [a, b]))
        #expect(candidate.paas.count == 2)
        #expect(Set(diff.added.map(\.sha256)) == [DCLFixtures.sha256(a), DCLFixtures.sha256(b)])
    }

    @Test("validity dates are not judged: expired and not-yet-valid PAAs are kept")
    func validityNotJudged() async throws {
        let old = try DCLFixtures.syntheticPAA(
            validity: SyntheticAttestationChain.date(2015)...SyntheticAttestationChain.date(2020))
        let future = try DCLFixtures.syntheticPAA(
            validity: SyntheticAttestationChain.date(2030)...SyntheticAttestationChain.date(2040))
        let (candidate, diff) = try await DCLFixtures.fetch(try DCLFixtures.response(serving: [old, future]))
        #expect(candidate.paas.count == 2)
        #expect(diff.excluded.isEmpty)
        #expect(AttestationTrustStore.assessPAA(old).rejection == nil)
    }

    @Test("a leaf with no certificates records an exclusion")
    func emptyLeaf() async throws {
        let good = try DCLFixtures.recordedLeaf(containing: "Feit")
        let (candidate, diff) = try await DCLFixtures.fetch(try DCLFixtures.response([
            (good.subject, good.ski, good.certs), ("ZW1wdHk=", "AA:BB", []),
        ]))
        #expect(candidate.paas.count == 1)
        #expect(diff.excluded.count == 1)
        #expect(diff.excluded[0].contains("the DCL returned no approved certificate"))
    }

    @Test("an invalid PEM body is excluded with a parse reason, not thrown")
    func invalidPEM() async throws {
        let good = try DCLFixtures.recordedLeaf(containing: "Feit")
        let (candidate, diff) = try await DCLFixtures.fetch(try DCLFixtures.response([
            ("c3ViamVjdA==", "01:02:03", [["pemCert": "not a pem", "vid": 0], good.certs[0]]),
        ]))
        #expect(candidate.paas.count == 1)
        #expect(diff.excluded.count == 1)
        #expect(diff.excluded[0].contains("does not parse as a certificate"))
    }

    // MARK: - Failures

    @Test("HTTP 500 on the listing is httpStatus(500)")
    func httpError() async throws {
        await #expect(throws: DCLFetchError.httpStatus(500)) {
            try await DCLFixtures.fetch(["roots": (Data(), 500)])
        }
    }

    @Test("a non-200 on a leaf is httpStatus")
    func leafHTTPError() async throws {
        var responses = try DCLFixtures.recordedResponses()
        let leaf = try #require(try DCLFixtures.recordedLeaves().first)
        responses[DCLFixtures.key(leaf.subject, leaf.ski)] = (Data(), 404)
        await #expect(throws: DCLFetchError.httpStatus(404)) { try await DCLFixtures.fetch(responses) }
    }

    @Test("garbage JSON, the wrong shape, a bad vid and pagination are malformedResponse",
          arguments: [
            "not json", "{\"x\":1}",
            "{\"approvedRootCertificates\":{\"certs\":[]},\"pagination\":{\"next_key\":\"AAAA\",\"total\":\"0\"}}",
          ])
    func malformedListing(body: String) async throws {
        do {
            _ = try await DCLFixtures.fetch(["roots": (Data(body.utf8), 200)])
            Issue.record("expected malformedResponse")
        } catch let error as DCLFetchError {
            guard case .malformedResponse = error else { Issue.record("got \(error)"); return }
        }
    }

    @Test("a non-numeric or out-of-range vid is malformedResponse", arguments: ["70000", "-1", "\"0x1188\"", "true"])
    func badVID(json: String) async throws {
        let good = try DCLFixtures.recordedLeaf(containing: "Feit")
        do {
            _ = try await DCLFixtures.fetch(try DCLFixtures.response(
                serving: [try good.der],
                vid: try JSONSerialization.jsonObject(with: Data(json.utf8), options: .fragmentsAllowed)))
            Issue.record("expected malformedResponse")
        } catch let error as DCLFetchError {
            guard case .malformedResponse = error else { Issue.record("got \(error)"); return }
        }
    }

    @Test("a paginated leaf is malformedResponse")
    func paginatedLeaf() async throws {
        var responses = try DCLFixtures.recordedResponses()
        let leaf = try #require(try DCLFixtures.recordedLeaves().first)
        var body = leaf.body
        body["pagination"] = ["next_key": "AAAA"]
        responses[DCLFixtures.key(leaf.subject, leaf.ski)] = try DCLFixtures.body(body)
        do {
            _ = try await DCLFixtures.fetch(responses)
            Issue.record("expected malformedResponse")
        } catch let error as DCLFetchError {
            guard case .malformedResponse = error else { Issue.record("got \(error)"); return }
        }
    }

    @Test("no surviving certificate is noRoots")
    func noRoots() async throws {
        let bad = try DCLFixtures.synthetic("p384")
        await #expect(throws: DCLFetchError.noRoots) { try await DCLFixtures.fetch(try DCLFixtures.response([bad])) }
        await #expect(throws: DCLFetchError.noRoots) {
            try await DCLFixtures.fetch(try DCLFixtures.response([] as [DCLFixtures.Synthetic]))
        }
    }

    // MARK: - No side effects

    @Test("a fetch writes nothing: the fetcher takes no directory and the working directory is unchanged")
    func writesNothing() async throws {
        let cwd = FileManager.default.currentDirectoryPath
        let before = try FileManager.default.subpathsOfDirectory(atPath: DCLFixtures.directory.path).sorted()
        let cwdBefore = try FileManager.default.contentsOfDirectory(atPath: cwd).sorted()
        _ = try await DCLFixtures.fetch(try DCLFixtures.recordedResponses())
        #expect(try FileManager.default.subpathsOfDirectory(atPath: DCLFixtures.directory.path).sorted() == before)
        #expect(try FileManager.default.contentsOfDirectory(atPath: cwd).sorted() == cwdBefore)
    }

    // MARK: - Live

    @Test("the real DCL keeps every bundled root: nothing removed, nothing mismatched",
          .enabled(if: ProcessInfo.processInfo.environment["MATTER_LIVE_DCL"] == "1"))
    func live() async throws {
        let (candidate, diff) = try await DCLTrustStoreFetcher().fetchProduction(
            current: try AttestationTrustStore.bundledProduction(), now: Date())
        print("live DCL: \(candidate.paas.count) roots, added \(diff.added.count), removed \(diff.removed.count), "
            + "changed \(diff.changed.count), excluded \(diff.excluded.count)")
        print("live DCL excluded: \(diff.excluded)\nlive DCL removed: \(diff.removed.map(\.subject))")
        #expect(candidate.paas.count >= 1)
        #expect(!diff.excluded.contains { $0.contains("does not match") })
        #expect(diff.removed.isEmpty, "\(diff.removed.map(\.subject))")
        // Only the known unparseable NXP PAA may be excluded.
        #expect(diff.excluded.count <= 1)
        #expect(diff.excluded.allSatisfy { $0.contains("does not parse") })
    }
}

private extension DCLFixtures.Synthetic {
    var asRoot: (subject: String, ski: String, certs: [[String: Any]]) { (subject, ski, certs) }
}
