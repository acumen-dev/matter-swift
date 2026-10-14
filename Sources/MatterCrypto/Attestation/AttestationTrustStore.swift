// AttestationTrustStore.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import SwiftASN1
import X509

// MARK: - TrustStoreProvenance

/// Where a trust store came from. Informational; swift-matter attaches no policy to it.
public struct TrustStoreProvenance: Sendable, Hashable, Codable {

    /// For example `"dcl:main-net"`, `"directory"`, `"explicit"` or `"bundled"`.
    public var source: String

    /// When the contents were captured, if known.
    public var snapshotDate: Date?

    public init(source: String, snapshotDate: Date? = nil) {
        self.source = source
        self.snapshotDate = snapshotDate
    }
}

// MARK: - CDSigningKey

/// A public key that may sign Certification Declarations, identified by its certificate's SKI.
public struct CDSigningKey: Sendable, Hashable {

    /// SubjectKeyIdentifier of the CD signing certificate.
    public let keyIdentifier: Data

    /// The certificate's P-256 public key.
    public let publicKey: P256.Signing.PublicKey

    /// Derives the key identifier from the certificate's SubjectKeyIdentifier extension.
    public init(certificateDER: Data) throws {
        let label = "cd-signing-certificate"
        let certificate: Certificate
        do {
            certificate = try Certificate(derEncoded: Array(certificateDER))
        } catch {
            throw AttestationTrustStoreError.notACertificate(label)
        }
        guard let ski = try? certificate.extensions.subjectKeyIdentifier, !ski.keyIdentifier.isEmpty else {
            throw AttestationTrustStoreError.missingSubjectKeyIdentifier(label)
        }
        guard let key = P256.Signing.PublicKey(certificate.publicKey) else {
            throw AttestationTrustStoreError.unsupportedKey(label)
        }
        self.keyIdentifier = Data(ski.keyIdentifier)
        self.publicKey = key
    }

    public static func == (lhs: CDSigningKey, rhs: CDSigningKey) -> Bool {
        lhs.keyIdentifier == rhs.keyIdentifier && lhs.publicKey.x963Representation == rhs.publicKey.x963Representation
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(keyIdentifier)
        hasher.combine(publicKey.x963Representation)
    }
}

// MARK: - TrustStoreWriteOutcome

/// The result of a completed ``AttestationTrustStore/write(to:)``. The new store is in place.
public struct TrustStoreWriteOutcome: Sendable, Equatable {

    /// A set-aside copy of the previous store that could not be removed, if any. It is pruned
    /// by the next write; the caller may also delete it.
    public let leftoverPath: URL?

    public init(leftoverPath: URL?) {
        self.leftoverPath = leftoverPath
    }
}

// MARK: - AttestationTrustStoreError

public enum AttestationTrustStoreError: Error, Sendable, Equatable {
    /// The named file or index did not parse as a certificate.
    case notACertificate(String)
    /// The named certificate is not a self-signed CA.
    case notASelfSignedCA(String)
    /// The named certificate's key is not P-256.
    case unsupportedKey(String)
    /// The named certificate has no SubjectKeyIdentifier extension.
    case missingSubjectKeyIdentifier(String)
    /// The bundled trust data is missing, altered, incomplete or has unlisted files; the message says which.
    case bundleCorrupt(String)
    /// A directory swap was interrupted and the previous store could not be restored, or
    /// several stranded copies make the right one ambiguous; the message names where they are.
    case recoveryFailed(String)
}

// MARK: - AttestationTrustStore

/// The roots a controller trusts when verifying device attestation: PAA certificates plus the
/// keys allowed to sign Certification Declarations.
///
/// swift-matter ships the mechanism only. Nothing here refreshes or applies a store on its own.
public struct AttestationTrustStore: Sendable {

    /// Self-signed P-256 CA roots.
    public let paas: [Certificate]

    public let cdSigningKeys: [CDSigningKey]

    public let provenance: TrustStoreProvenance

    /// Builds a store from DER-encoded PAAs, validating each. Byte-identical certificates
    /// collapse to one; distinct certificates sharing a SubjectKeyIdentifier are all kept.
    public init(paas: [Data], cdSigningKeys: [CDSigningKey], provenance: TrustStoreProvenance) throws {
        var loaded: [Certificate] = []
        for (index, der) in paas.enumerated() {
            loaded.append(try Self.parseDER(der, label: String(index)))
        }
        self.paas = try Self.deduplicated(loaded)
        self.cdSigningKeys = cdSigningKeys
        self.provenance = provenance
    }

    /// Loads every `*.der` and `*.pem` in `directory` as a PAA (the chip-tool
    /// `--paa-trust-store-path` layout), in file-name order. Other files are ignored, and a
    /// certificate present as both `.der` and `.pem` loads once.
    ///
    /// Loading is strict: one invalid or unreadable `.der` or `.pem` makes the whole directory
    /// unloadable, naming the file. chip-tool skips such files; this deliberately does not.
    ///
    /// If an interrupted ``write(to:)`` left the directory absent with exactly one
    /// `<directory>.old-*` sibling, that previous store is restored first.
    ///
    /// Assumes no concurrent writer of `directory`.
    ///
    /// `cdSigningKeys` defaults to ``bundledCDSigningKeys()``.
    public init(directory: URL, cdSigningKeys: [CDSigningKey]? = nil, provenance: TrustStoreProvenance? = nil) throws {
        try self.init(
            directory: directory, cdSigningKeys: try cdSigningKeys ?? Self.bundledCDSigningKeys(),
            provenance: provenance, fileOps: FoundationAttestationFileOps())
    }

    init(
        directory: URL, cdSigningKeys: [CDSigningKey], provenance: TrustStoreProvenance?,
        fileOps: any AttestationFileOps
    ) throws {
        try Self.recoverStrandedStore(at: directory, fileOps: fileOps)
        let names = try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted()
        var loaded: [Certificate] = []
        for name in names {
            let lowered = name.lowercased()
            let isDER = lowered.hasSuffix(".der")
            guard isDER || lowered.hasSuffix(".pem") else { continue }
            let data: Data
            do {
                data = try Data(contentsOf: directory.appendingPathComponent(name))
            } catch {
                throw AttestationTrustStoreError.notACertificate(name)
            }
            loaded.append(isDER ? try Self.parseDER(data, label: name) : try Self.parsePEM(data, label: name))
        }
        self.paas = try Self.deduplicated(loaded)
        self.cdSigningKeys = cdSigningKeys
        self.provenance = provenance ?? TrustStoreProvenance(source: "directory")
    }

    // MARK: - Validation

    private static func parseDER(_ der: Data, label: String) throws -> Certificate {
        let certificate: Certificate
        do {
            certificate = try Certificate(derEncoded: Array(der))
        } catch {
            throw AttestationTrustStoreError.notACertificate(label)
        }
        return try validatePAA(certificate, label: label)
    }

    private static func parsePEM(_ data: Data, label: String) throws -> Certificate {
        let certificate: Certificate
        do {
            guard let text = String(data: data, encoding: .utf8) else {
                throw AttestationTrustStoreError.notACertificate(label)
            }
            certificate = try Certificate(pemEncoded: text)
        } catch {
            throw AttestationTrustStoreError.notACertificate(label)
        }
        return try validatePAA(certificate, label: label)
    }

    /// Key type is checked before the signature so a non-P-256 root reports `unsupportedKey`.
    private static func validatePAA(_ certificate: Certificate, label: String) throws -> Certificate {
        guard P256.Signing.PublicKey(certificate.publicKey) != nil else {
            throw AttestationTrustStoreError.unsupportedKey(label)
        }
        guard certificate.issuer == certificate.subject,
              certificate.publicKey.isValidSignature(certificate.signature, for: certificate),
              case .isCertificateAuthority? = try? certificate.extensions.basicConstraints
        else {
            throw AttestationTrustStoreError.notASelfSignedCA(label)
        }
        guard let ski = try? certificate.extensions.subjectKeyIdentifier, !ski.keyIdentifier.isEmpty else {
            throw AttestationTrustStoreError.missingSubjectKeyIdentifier(label)
        }
        return certificate
    }

    private static func derBytes(_ certificate: Certificate) throws -> [UInt8] {
        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        return serializer.serializedBytes
    }

    /// Collapses byte-identical certificates, keeping first-seen order.
    private static func deduplicated(_ certificates: [Certificate]) throws -> [Certificate] {
        var seen = Set<[UInt8]>()
        var result: [Certificate] = []
        for certificate in certificates where seen.insert(try derBytes(certificate)).inserted {
            result.append(certificate)
        }
        return result
    }

    // MARK: - Writing

    /// Replaces the directory's contents without ever exposing a mix of old and new files.
    ///
    /// Each PAA is written as `<SKI hex>-<first 8 bytes of SHA-256 hex>.der` into a sibling
    /// `<directory>.tmp-<uuid>`, so certificates sharing a key identifier coexist. If
    /// `directory` already exists it is renamed aside (`<directory>.old-<uuid>`), the new
    /// directory is renamed into place, and the old one is removed. A failure before the
    /// swap-in succeeds removes the temporary directory and restores the original, so a reader
    /// observes the old contents or the new, never a blend. Directory replacement uses two POSIX
    /// renames rather than `FileManager.replaceItemAt`, whose behaviour for directories differs
    /// between Darwin and swift-corelibs-foundation.
    ///
    /// Once the swap-in has succeeded this method does not throw: removing the set-aside copy
    /// is best effort, and a copy that could not be removed is reported in the returned
    /// ``TrustStoreWriteOutcome``. When `directory` exists, every stale `<directory>.old-*`
    /// sibling is pruned (best effort) at the start of the next write.
    ///
    /// Between the renames `directory` does not exist. A crash there strands the previous store
    /// as `<directory>.old-*`; the next ``init(directory:cdSigningKeys:provenance:)`` or
    /// `write(to:)` restores it when it is the only such sibling. If that restore fails, or
    /// several stranded siblings exist, ``AttestationTrustStoreError/recoveryFailed(_:)`` names
    /// where they are. If both the swap-in and the rollback fail it names the set-aside copy.
    ///
    /// Assumes a single writer and no concurrent reader of `directory`; it is not safe against
    /// either. Only the PAAs are persisted. CD signing keys and provenance belong to the consumer.
    @discardableResult
    public func write(to directory: URL) throws -> TrustStoreWriteOutcome {
        try write(to: directory, fileOps: FoundationAttestationFileOps())
    }

    @discardableResult
    func write(to directory: URL, fileOps: any AttestationFileOps) throws -> TrustStoreWriteOutcome {
        try Self.recoverStrandedStore(at: directory, fileOps: fileOps)
        let parent = directory.deletingLastPathComponent()
        let name = directory.lastPathComponent
        if fileOps.fileExists(at: directory) {
            // Stale set-asides from earlier writes would defeat single-sibling recovery.
            for sibling in Self.strandedSiblings(of: directory, fileOps: fileOps) {
                try? fileOps.removeItem(at: sibling)
            }
        }
        let token = UUID().uuidString
        let staging = parent.appendingPathComponent("\(name).tmp-\(token)", isDirectory: true)
        let aside = parent.appendingPathComponent("\(name).old-\(token)", isDirectory: true)

        do {
            try fileOps.createDirectory(at: staging)
            for certificate in paas {
                let der = try Self.derBytes(certificate)
                let ski = Self.hex(try certificate.extensions.subjectKeyIdentifier?.keyIdentifier ?? [])
                let digest = Self.hex(SHA256.hash(data: der).prefix(8))
                try fileOps.write(Data(der), to: staging.appendingPathComponent("\(ski)-\(digest).der"))
            }
        } catch {
            try? fileOps.removeItem(at: staging)
            throw error
        }

        let hadExisting = fileOps.fileExists(at: directory)
        do {
            if hadExisting { try fileOps.moveItem(at: directory, to: aside) }
        } catch {
            try? fileOps.removeItem(at: staging)
            throw error
        }
        do {
            try fileOps.moveItem(at: staging, to: directory)
        } catch {
            try? fileOps.removeItem(at: staging)
            if hadExisting {
                do {
                    try fileOps.moveItem(at: aside, to: directory)
                } catch let rollbackError {
                    throw AttestationTrustStoreError.recoveryFailed(
                        "previous store remains at \(aside.path); swap-in failed (\(error)) and restoring it to "
                        + "\(directory.path) failed (\(rollbackError))")
                }
            }
            throw error
        }
        guard hadExisting else { return TrustStoreWriteOutcome(leftoverPath: nil) }
        do {
            try fileOps.removeItem(at: aside)
            return TrustStoreWriteOutcome(leftoverPath: nil)
        } catch {
            return TrustStoreWriteOutcome(leftoverPath: aside)
        }
    }

    private static func strandedSiblings(of directory: URL, fileOps: any AttestationFileOps) -> [URL] {
        let parent = directory.deletingLastPathComponent()
        let prefix = directory.lastPathComponent + ".old-"
        guard let siblings = try? fileOps.contentsOfDirectory(at: parent) else { return [] }
        return siblings.filter { $0.hasPrefix(prefix) }.sorted()
            .map { parent.appendingPathComponent($0, isDirectory: true) }
    }

    /// Restores a store stranded by an interrupted swap: `directory` absent and exactly one
    /// `<directory>.old-*` sibling. Several siblings are ambiguous and throw.
    private static func recoverStrandedStore(at directory: URL, fileOps: any AttestationFileOps) throws {
        guard !fileOps.fileExists(at: directory) else { return }
        let stranded = strandedSiblings(of: directory, fileOps: fileOps)
        if stranded.count > 1 {
            throw AttestationTrustStoreError.recoveryFailed(
                "\(directory.path) is missing and \(stranded.count) stranded previous stores exist, so none was "
                + "restored: \(stranded.map(\.path).joined(separator: ", "))")
        }
        guard let source = stranded.first else { return }
        do {
            try fileOps.moveItem(at: source, to: directory)
        } catch {
            throw AttestationTrustStoreError.recoveryFailed(
                "previous store remains at \(source.path); restoring it to \(directory.path) failed: \(error)")
        }
    }

    private static func hex<S: Sequence>(_ bytes: S) -> String where S.Element == UInt8 {
        bytes.map { String(format: "%02X", $0) }.joined()
    }

    // MARK: - Diff

    /// What changed going from `other` (old) to `self` (new).
    ///
    /// Certificates are identified by SubjectKeyIdentifier and SHA-256 of their DER, so a store
    /// may hold several certificates for one key identifier. `added` and `removed` list
    /// individual certificates; `changed` lists, once per key identifier present on both sides,
    /// the symmetric difference's entry when the two certificate sets differ: a certificate new
    /// to this store if there is one, otherwise one removed from it. Entries carry the
    /// certificate's SHA-256 and expiry so otherwise identical subjects stay distinguishable.
    public func diff(from other: AttestationTrustStore) -> TrustStoreDiff {
        let newIndex = Self.index(paas)
        let oldIndex = Self.index(other.paas)
        let newKeys = Set(newIndex.map(\.identity))
        let oldKeys = Set(oldIndex.map(\.identity))

        var result = TrustStoreDiff()
        for item in newIndex where !oldKeys.contains(item.identity) { result.added.append(item.entry) }
        for item in oldIndex where !newKeys.contains(item.identity) { result.removed.append(item.entry) }

        let newSKIs = Set(newIndex.map(\.identity.ski))
        let oldSKIs = Set(oldIndex.map(\.identity.ski))
        for ski in newSKIs.intersection(oldSKIs).sorted(by: { $0.lexicographicallyPrecedes($1) }) {
            let newSet = Set(newIndex.filter { $0.identity.ski == ski }.map(\.identity))
            let oldSet = Set(oldIndex.filter { $0.identity.ski == ski }.map(\.identity))
            guard newSet != oldSet else { continue }
            let pick = newIndex.first { $0.identity.ski == ski && !oldSet.contains($0.identity) }
                ?? oldIndex.first { $0.identity.ski == ski && !newSet.contains($0.identity) }
            if let pick { result.changed.append(pick.entry) }
        }
        return result
    }

    private struct Identity: Hashable {
        let ski: Data
        let digest: Data
    }

    private struct IndexedCertificate {
        let identity: Identity
        let entry: TrustStoreDiff.Entry
    }

    /// Entries sorted by (SKI, digest) for stable output.
    private static func index(_ certificates: [Certificate]) -> [IndexedCertificate] {
        var items: [IndexedCertificate] = []
        for certificate in certificates {
            guard let ski = try? certificate.extensions.subjectKeyIdentifier,
                  let der = try? derBytes(certificate)
            else { continue }
            let identifier = Data(ski.keyIdentifier)
            let digest = Data(SHA256.hash(data: der))
            items.append(IndexedCertificate(
                identity: Identity(ski: identifier, digest: digest),
                entry: TrustStoreDiff.Entry(
                    subject: String(describing: certificate.subject),
                    vendorID: (try? MatterCertificateAttributes.identifiers(in: certificate.subject))?.vendorID,
                    subjectKeyIdentifier: identifier,
                    sha256: digest,
                    notValidAfter: certificate.notValidAfter)))
        }
        return items.sorted {
            $0.identity.ski == $1.identity.ski
                ? $0.identity.digest.lexicographicallyPrecedes($1.identity.digest)
                : $0.identity.ski.lexicographicallyPrecedes($1.identity.ski)
        }
    }
}

// MARK: - AttestationFileOps

/// The file operations ``AttestationTrustStore/write(to:)`` performs, as a seam for fault injection.
protocol AttestationFileOps: Sendable {
    func createDirectory(at url: URL) throws
    func write(_ data: Data, to url: URL) throws
    func fileExists(at url: URL) -> Bool
    func contentsOfDirectory(at url: URL) throws -> [String]
    func moveItem(at source: URL, to destination: URL) throws
    func removeItem(at url: URL) throws
}

/// The production implementation, on `FileManager` (available on Darwin and Linux).
struct FoundationAttestationFileOps: AttestationFileOps {
    func createDirectory(at url: URL) throws {
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
    }
    func write(_ data: Data, to url: URL) throws { try data.write(to: url, options: .atomic) }
    func fileExists(at url: URL) -> Bool { FileManager.default.fileExists(atPath: url.path) }
    func contentsOfDirectory(at url: URL) throws -> [String] {
        try FileManager.default.contentsOfDirectory(atPath: url.path)
    }
    func moveItem(at source: URL, to destination: URL) throws {
        try FileManager.default.moveItem(at: source, to: destination)
    }
    func removeItem(at url: URL) throws { try FileManager.default.removeItem(at: url) }
}
