// BundledTrustStore.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto

// MARK: - Bundled snapshot

extension AttestationTrustStore {

    /// The production snapshot bundled with MatterCrypto: the PAAs the main-net DCL published
    /// at the manifest's `snapshotDate`, restricted to those that satisfy the runtime rules.
    /// Public data only. It is a starting point; swift-matter never refreshes or applies a
    /// store on its own.
    ///
    /// Throws ``AttestationTrustStoreError/bundleCorrupt(_:)`` if any file is missing, extra,
    /// fails its manifest SHA-256, or does not parse.
    public static func bundledProduction() throws -> AttestationTrustStore {
        try loadBundle(at: bundleDirectory())
    }

    /// The CSA production Certification Declaration signing keys from the bundled snapshot.
    public static func bundledCDSigningKeys() throws -> [CDSigningKey] {
        try loadBundleContents(at: bundleDirectory()).cdSigningKeys
    }

    /// Loads a bundle-shaped directory (`manifest.json`, `paa/`, `cd/`) with the bundle's
    /// integrity rules. Internal so tests can corrupt a copy.
    static func loadBundle(at directory: URL) throws -> AttestationTrustStore {
        let contents = try loadBundleContents(at: directory)
        do {
            return try AttestationTrustStore(
                paas: contents.paas, cdSigningKeys: contents.cdSigningKeys,
                provenance: TrustStoreProvenance(source: "bundled", snapshotDate: contents.snapshotDate))
        } catch {
            throw AttestationTrustStoreError.bundleCorrupt("a bundled PAA is not valid: \(error)")
        }
    }

    /// The directory holding the bundled snapshot inside MatterCrypto's resource bundle.
    static func bundleDirectory() throws -> URL {
        guard let url = Bundle.module.url(forResource: "Attestation", withExtension: nil) else {
            throw AttestationTrustStoreError.bundleCorrupt("the Attestation resource directory is missing")
        }
        return url
    }

    // MARK: - Loading

    private struct Manifest: Decodable {
        struct Entry: Decodable {
            let file: String
            let sha256: String
        }
        let snapshotDate: String
        let paa: [Entry]
        let cd: [Entry]
    }

    private struct BundleContents {
        let snapshotDate: Date
        let paas: [Data]
        let cdSigningKeys: [CDSigningKey]
    }

    private static func loadBundleContents(at directory: URL) throws -> BundleContents {
        func corrupt(_ message: String) -> AttestationTrustStoreError { .bundleCorrupt(message) }

        let manifest: Manifest
        do {
            manifest = try JSONDecoder().decode(
                Manifest.self, from: Data(contentsOf: directory.appendingPathComponent("manifest.json")))
        } catch {
            throw corrupt("manifest.json is missing or unreadable")
        }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withFullDate]
        formatter.timeZone = TimeZone(identifier: "UTC")
        guard let snapshotDate = formatter.date(from: manifest.snapshotDate) else {
            throw corrupt("manifest snapshotDate \(manifest.snapshotDate) is not a date")
        }

        func loadFiles(_ entries: [Manifest.Entry], folder: String) throws -> [Data] {
            let listed = Set(entries.map(\.file))
            guard listed.count == entries.count else { throw corrupt("\(folder) lists a file twice") }
            let onDisk: [String]
            do {
                onDisk = try FileManager.default.contentsOfDirectory(atPath: directory.appendingPathComponent(folder).path)
                    .map { "\(folder)/\($0)" }
            } catch {
                throw corrupt("\(folder) is missing")
            }
            if let extra = Set(onDisk).subtracting(listed).sorted().first {
                throw corrupt("\(extra) is not listed in the manifest")
            }
            var result: [Data] = []
            for entry in entries {
                guard entry.file.hasPrefix("\(folder)/"), !entry.file.contains("..") else {
                    throw corrupt("\(entry.file) is outside \(folder)")
                }
                let data: Data
                do {
                    data = try Data(contentsOf: directory.appendingPathComponent(entry.file))
                } catch {
                    throw corrupt("\(entry.file) is missing")
                }
                guard SHA256.hash(data: data).map({ String(format: "%02x", $0) }).joined() == entry.sha256.lowercased()
                else { throw corrupt("\(entry.file) does not match its manifest SHA-256") }
                result.append(data)
            }
            return result
        }

        let rootNames = (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
        if let extra = Set(rootNames).subtracting(["manifest.json", "paa", "cd"]).sorted().first {
            throw corrupt("\(extra) is not part of the bundle")
        }

        let paas = try loadFiles(manifest.paa, folder: "paa")
        let cdFiles = try loadFiles(manifest.cd, folder: "cd")
        do {
            return BundleContents(
                snapshotDate: snapshotDate, paas: paas,
                cdSigningKeys: try cdFiles.map { try CDSigningKey(certificateDER: $0) })
        } catch {
            throw corrupt("a CD signing certificate is not valid: \(error)")
        }
    }
}
