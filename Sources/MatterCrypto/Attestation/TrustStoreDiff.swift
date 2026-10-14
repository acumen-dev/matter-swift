// TrustStoreDiff.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

// MARK: - TrustStoreDiff

/// The difference between two ``AttestationTrustStore`` values. Certificates are identified by
/// SubjectKeyIdentifier plus SHA-256 of their DER, so a store may hold several per key.
///
/// A diff is information for the consumer to act on. Nothing in swift-matter applies it.
public struct TrustStoreDiff: Sendable, Equatable {

    /// One PAA named in a diff.
    public struct Entry: Sendable, Equatable {
        public let subject: String
        public let vendorID: UInt16?
        public let subjectKeyIdentifier: Data
        /// SHA-256 of the certificate's DER, telling apart certificates with one subject and key.
        public let sha256: Data
        public let notValidAfter: Date

        public init(subject: String, vendorID: UInt16?, subjectKeyIdentifier: Data, sha256: Data, notValidAfter: Date) {
            self.subject = subject
            self.vendorID = vendorID
            self.subjectKeyIdentifier = subjectKeyIdentifier
            self.sha256 = sha256
            self.notValidAfter = notValidAfter
        }
    }

    /// Certificates in the new store and not the old one.
    public var added: [Entry]

    /// Certificates in the old store and not the new one.
    public var removed: [Entry]

    /// A SubjectKeyIdentifier present in both stores whose certificate set differs. The entry is
    /// taken from the symmetric difference (new to this store if any, otherwise removed), so it
    /// never names an unchanged certificate. The same change also appears in `added`/`removed`.
    public var changed: [Entry]

    /// Fetcher-only: entries rejected while building the candidate, each with a reason.
    public var excluded: [String]

    public init(added: [Entry] = [], removed: [Entry] = [], changed: [Entry] = [], excluded: [String] = []) {
        self.added = added
        self.removed = removed
        self.changed = changed
        self.excluded = excluded
    }

    /// True when nothing was added, removed, changed or excluded.
    public var isEmpty: Bool {
        added.isEmpty && removed.isEmpty && changed.isEmpty && excluded.isEmpty
    }
}
