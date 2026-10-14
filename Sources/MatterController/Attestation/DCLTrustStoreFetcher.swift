// DCLTrustStoreFetcher.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import MatterCrypto

// MARK: - DCLHTTPClient

/// The HTTP GET the fetcher needs, as a seam so tests can replay recorded responses.
public protocol DCLHTTPClient: Sendable {
    /// Returns the response body and HTTP status. Non-2xx statuses are returned, not thrown.
    func get(_ url: URL) async throws -> (Data, Int)
}

/// The production client, on `URLSession`.
public struct URLSessionDCLHTTPClient: DCLHTTPClient {

    private let session: URLSession

    public init(session: URLSession = .shared) {
        self.session = session
    }

    public func get(_ url: URL) async throws -> (Data, Int) {
        let (data, response) = try await session.data(from: url)
        guard let http = response as? HTTPURLResponse else { throw URLError(.badServerResponse) }
        return (data, http.statusCode)
    }
}

// MARK: - DCLFetchError

public enum DCLFetchError: Error, Sendable, Equatable {
    /// The DCL answered a request with this HTTP status.
    case httpStatus(Int)
    /// A response was not the expected JSON; the message says what was wrong.
    case malformedResponse(String)
    /// No certificate survived validation.
    case noRoots
    /// The trust store refused a certificate set that every member had passed assessment for.
    /// This is a bug in swift-matter; the message is the store's own.
    case internalInconsistency(String)
}

// MARK: - DCLTrustStoreFetcher

/// Fetches the PAAs the Distributed Compliance Ledger publishes and turns them into a candidate
/// ``AttestationTrustStore`` plus its ``TrustStoreDiff`` from a current store.
///
/// It reads the same two REST endpoints as the connectedhomeip `fetch_paa_certs_from_dcl.py`
/// script and `Tools/Attestation/refresh-trust-store`: the list of approved root certificates,
/// then the certificates for each (subject, SubjectKeyIdentifier). The CSA CD-signing CA is
/// published as a root but is not a PAA, so it is skipped without being fetched.
///
/// swift-matter ships the mechanism only. This never writes a file, takes no directory, and
/// applies nothing: the caller inspects the diff and decides. DCL revocation is out of scope.
public struct DCLTrustStoreFetcher: Sendable {

    /// The production DCL.
    public static let mainNet = URL(string: "https://on.dcl.csa-iot.org")!

    private let baseURL: URL
    private let client: any DCLHTTPClient

    public init(baseURL: URL = mainNet, client: any DCLHTTPClient = URLSessionDCLHTTPClient()) {
        self.baseURL = baseURL
        self.client = client
    }

    /// Fetches the production PAAs, validates each, and returns a candidate store plus its diff
    /// from `current`. Never writes or applies anything.
    ///
    /// Every certificate the DCL returns for a (subject, key identifier) is considered, not only
    /// the first. A certificate is kept only if ``AttestationTrustStore/assessPAA(_:)`` accepts
    /// it (it parses, is a self-signed P-256 CA, conforms to the PAA profile, names no PID) and
    /// its VID agrees with the DCL record's `vid`. The DCL serialises an absent VID as `0`, so a
    /// zero `vid` means the record has none; likewise a certificate whose subject names no VID is
    /// not contradicted by the record. Validity dates are not judged (the runtime accepts a PAA
    /// that was valid when the DAC's validity began); diff entries carry `notValidAfter`.
    /// Anything that fails is excluded rather than thrown: its reason is in
    /// ``TrustStoreDiff/excluded``, and the rest of the response is still used.
    ///
    /// The candidate keeps `current.cdSigningKeys` and has provenance `dcl:main-net` stamped
    /// with `now`, whatever `baseURL` is: provenance is informational and names the network the
    /// fetcher is for, not the host it happened to reach.
    ///
    /// - Throws: ``DCLFetchError``; or whatever the HTTP client throws.
    public func fetchProduction(current: AttestationTrustStore, now: Date) async throws
        -> (candidate: AttestationTrustStore, diff: TrustStoreDiff)
    {
        let listing: RootListing = try await getJSON(path: "/dcl/pki/root-certificates")
        var accepted: [Data] = []
        var excluded: [String] = []

        for root in listing.approvedRootCertificates.certs {
            if root.subject == Self.cdSigningCASubject && root.subjectKeyId == Self.cdSigningCASKI { continue }
            let path = "/dcl/pki/certificates/\(Self.escape(root.subject))/\(Self.escape(root.subjectKeyId))"
            let leaf: CertificateSet = try await getJSON(path: path)
            if leaf.approvedCertificates.certs.isEmpty {
                excluded.append("\(Self.label(root)): the DCL returned no approved certificate")
            }
            for record in leaf.approvedCertificates.certs {
                guard let der = Self.der(fromPEM: record.pemCert) else {
                    excluded.append("\(Self.label(root)): does not parse as a certificate (the PEM is not valid)")
                    continue
                }
                let assessment = AttestationTrustStore.assessPAA(der)
                let label = assessment.subject ?? Self.label(root)
                if let rejection = assessment.rejection {
                    excluded.append("\(label): \(rejection)")
                } else if let recorded = record.vid, recorded != 0, let actual = assessment.vendorID, recorded != actual {
                    excluded.append("\(label): VID 0x\(String(actual, radix: 16, uppercase: true)) "
                        + "does not match the DCL record's VID 0x\(String(recorded, radix: 16, uppercase: true))")
                } else {
                    accepted.append(der)
                }
            }
        }

        guard !accepted.isEmpty else { throw DCLFetchError.noRoots }
        let provenance = TrustStoreProvenance(source: "dcl:main-net", snapshotDate: now)
        let candidate: AttestationTrustStore
        do {
            candidate = try AttestationTrustStore(
                paas: accepted, cdSigningKeys: current.cdSigningKeys, provenance: provenance)
        } catch {
            // Each certificate passed assessment alone, so the store refusing the set is our bug.
            // Retrying certificate by certificate could not recover: the refusal is of the set.
            assertionFailure("an assessed certificate set was refused by the store: \(error)")
            throw DCLFetchError.internalInconsistency("\(error)")
        }
        var diff = candidate.diff(from: current)
        diff.excluded = excluded
        return (candidate, diff)
    }

    // MARK: - Requests

    private func getJSON<T: DCLResponse>(path: String) async throws -> T {
        let base = baseURL.absoluteString.hasSuffix("/") ? String(baseURL.absoluteString.dropLast()) : baseURL.absoluteString
        guard let url = URL(string: base + path) else {
            throw DCLFetchError.malformedResponse("\(path) does not form a URL")
        }
        let (data, status) = try await client.get(url)
        guard status == 200 else { throw DCLFetchError.httpStatus(status) }
        let decoded: T
        do {
            decoded = try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw DCLFetchError.malformedResponse("\(path): \(error)")
        }
        // Tripwire: the live DCL does not paginate either endpoint. If it starts to, a partial
        // read must not pass for the whole trust store.
        if let next = decoded.pagination?.nextKey, !next.isEmpty {
            throw DCLFetchError.malformedResponse("\(path): the response is paginated, which is not supported")
        }
        return decoded
    }

    // MARK: - Wire shapes

    private struct Pagination: Decodable {
        let nextKey: String?
        enum CodingKeys: String, CodingKey { case nextKey = "next_key" }
    }

    private protocol DCLResponse: Decodable {
        var pagination: Pagination? { get }
    }

    private struct RootListing: DCLResponse {
        let pagination: Pagination?
        struct Certs: Decodable {
            let certs: [Root]
        }
        let approvedRootCertificates: Certs
    }

    private struct Root: Decodable {
        let subject: String
        let subjectKeyId: String
    }

    private struct CertificateSet: DCLResponse {
        let pagination: Pagination?
        struct Certs: Decodable {
            let certs: [Record]
        }
        let approvedCertificates: Certs
    }

    private struct Record: Decodable {
        let pemCert: String
        /// The DCL serialises an absent VID as `0`. A VID outside UInt16 is a malformed response.
        let vid: UInt16?
    }

    // MARK: - Helpers

    /// The CSA Matter Certification and Testing CA: published as a DCL root, but a CD-signing
    /// authority rather than a PAA. The refresh script and connectedhomeip skip it too.
    private static let cdSigningCASubject =
        "MFIxDDAKBgNVBAoMA0NTQTEsMCoGA1UEAwwjTWF0dGVyIENlcnRpZmljYXRpb24gYW5kIFRlc3RpbmcgQ0ExFDASBgorBgEEAYKifAIBDARDNUEw"
    private static let cdSigningCASKI = "97:E4:69:D0:C5:04:14:C2:6F:C7:01:F7:7E:94:77:39:09:8D:F6:A5"

    /// Percent-encodes a path segment with no safe characters beyond the RFC 3986 unreserved set.
    private static func escape(_ segment: String) -> String {
        let unreserved = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        return segment.addingPercentEncoding(withAllowedCharacters: unreserved) ?? segment
    }

    private static func label(_ root: Root) -> String {
        "DCL root \(root.subject) (SKI \(root.subjectKeyId))"
    }

    private static func der(fromPEM pem: String) -> Data? {
        // The live DCL sometimes ends a PEM with a stray space after the final newline.
        let body = pem.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("-----") }
            .joined()
        guard !body.isEmpty else { return nil }
        return Data(base64Encoded: body)
    }
}
