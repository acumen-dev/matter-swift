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
        guard let ski = try? certificate.extensions.subjectKeyIdentifier else {
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
    /// The bundled trust data could not be read (Task 5).
    case bundleCorrupt(String)
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

    /// Builds a store from DER-encoded PAAs, validating each.
    public init(paas: [Data], cdSigningKeys: [CDSigningKey], provenance: TrustStoreProvenance) throws {
        let certificates = try paas.enumerated().map { index, der in
            try Self.parseDER(der, label: String(index))
        }
        self.paas = certificates
        self.cdSigningKeys = cdSigningKeys
        self.provenance = provenance
    }

    /// Loads every `*.der` and `*.pem` in `directory` as a PAA (the chip-tool
    /// `--paa-trust-store-path` layout), in file-name order. Other files are ignored.
    ///
    /// `cdSigningKeys` has no default until the bundled CSA keys exist (Task 5).
    public init(directory: URL, cdSigningKeys: [CDSigningKey], provenance: TrustStoreProvenance? = nil) throws {
        let names = try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted()
        var certificates: [Certificate] = []
        for name in names {
            let lowered = name.lowercased()
            let isDER = lowered.hasSuffix(".der")
            guard isDER || lowered.hasSuffix(".pem") else { continue }
            let data = try Data(contentsOf: directory.appendingPathComponent(name))
            if isDER {
                certificates.append(try Self.parseDER(data, label: name))
            } else {
                certificates.append(try Self.parsePEM(data, label: name))
            }
        }
        self.paas = certificates
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

    private static func validatePAA(_ certificate: Certificate, label: String) throws -> Certificate {
        guard certificate.issuer == certificate.subject,
              certificate.publicKey.isValidSignature(certificate.signature, for: certificate),
              case .isCertificateAuthority? = try? certificate.extensions.basicConstraints
        else {
            throw AttestationTrustStoreError.notASelfSignedCA(label)
        }
        guard P256.Signing.PublicKey(certificate.publicKey) != nil else {
            throw AttestationTrustStoreError.unsupportedKey(label)
        }
        guard let ski = try? certificate.extensions.subjectKeyIdentifier, !ski.keyIdentifier.isEmpty else {
            throw AttestationTrustStoreError.missingSubjectKeyIdentifier(label)
        }
        return certificate
    }

    // MARK: - Writing

    /// Replaces the directory's contents without ever exposing a mix of old and new files.
    ///
    /// Each PAA is written as `<SKI hex>.der` into a sibling `<directory>.tmp-<uuid>`. If
    /// `directory` already exists it is renamed aside (`<directory>.old-<uuid>`), the new
    /// directory is renamed into place, and the old one is removed. A failure at any step
    /// removes the temporary directory and restores the original, so a reader observes the old
    /// contents or the new, never a blend. Directory replacement uses two POSIX renames rather
    /// than `FileManager.replaceItemAt`, whose behaviour for directories differs between
    /// Darwin and swift-corelibs-foundation; there is a brief window between the renames in
    /// which `directory` does not exist.
    ///
    /// Only the PAAs are persisted. CD signing keys and provenance belong to the consumer.
    public func write(to directory: URL) throws {
        try write(to: directory, fileOps: FoundationAttestationFileOps())
    }

    func write(to directory: URL, fileOps: any AttestationFileOps) throws {
        let parent = directory.deletingLastPathComponent()
        let name = directory.lastPathComponent
        let token = UUID().uuidString
        let staging = parent.appendingPathComponent("\(name).tmp-\(token)", isDirectory: true)
        let aside = parent.appendingPathComponent("\(name).old-\(token)", isDirectory: true)

        do {
            try fileOps.createDirectory(at: staging)
            for certificate in paas {
                var serializer = DER.Serializer()
                try serializer.serialize(certificate)
                let ski = try Self.hex(certificate.extensions.subjectKeyIdentifier?.keyIdentifier ?? [])
                try fileOps.write(Data(serializer.serializedBytes), to: staging.appendingPathComponent("\(ski).der"))
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
            if hadExisting { try? fileOps.moveItem(at: aside, to: directory) }
            try? fileOps.removeItem(at: staging)
            throw error
        }
        if hadExisting { try? fileOps.removeItem(at: aside) }
    }

    private static func hex<S: Sequence>(_ bytes: S) -> String where S.Element == UInt8 {
        bytes.map { String(format: "%02X", $0) }.joined()
    }

    // MARK: - Diff

    /// What changed going from `other` (old) to `self` (new), keyed by SubjectKeyIdentifier.
    public func diff(from other: AttestationTrustStore) -> TrustStoreDiff {
        let newIndex = Self.index(paas)
        let oldIndex = Self.index(other.paas)

        var result = TrustStoreDiff()
        for (ski, entry) in newIndex.sorted(by: { $0.key.lexicographicallyPrecedes($1.key) }) {
            if let previous = oldIndex[ski] {
                if previous.der != entry.der { result.changed.append(entry.entry) }
            } else {
                result.added.append(entry.entry)
            }
        }
        for (ski, entry) in oldIndex.sorted(by: { $0.key.lexicographicallyPrecedes($1.key) }) where newIndex[ski] == nil {
            result.removed.append(entry.entry)
        }
        return result
    }

    private static func index(_ certificates: [Certificate]) -> [Data: (der: [UInt8], entry: TrustStoreDiff.Entry)] {
        var index: [Data: (der: [UInt8], entry: TrustStoreDiff.Entry)] = [:]
        for certificate in certificates {
            guard let ski = try? certificate.extensions.subjectKeyIdentifier else { continue }
            var serializer = DER.Serializer()
            guard (try? serializer.serialize(certificate)) != nil else { continue }
            let identifier = Data(ski.keyIdentifier)
            index[identifier] = (
                serializer.serializedBytes,
                TrustStoreDiff.Entry(
                    subject: String(describing: certificate.subject),
                    vendorID: MatterCertificateAttributes.vendorID(in: certificate.subject),
                    subjectKeyIdentifier: identifier)
            )
        }
        return index
    }
}

// MARK: - AttestationFileOps

/// The file operations ``AttestationTrustStore/write(to:)`` performs, as a seam for fault injection.
protocol AttestationFileOps: Sendable {
    func createDirectory(at url: URL) throws
    func write(_ data: Data, to url: URL) throws
    func fileExists(at url: URL) -> Bool
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
    func moveItem(at source: URL, to destination: URL) throws {
        try FileManager.default.moveItem(at: source, to: destination)
    }
    func removeItem(at url: URL) throws { try FileManager.default.removeItem(at: url) }
}
