// TrustStoreDiff.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

// MARK: - TrustStoreDiff

/// The difference between two ``AttestationTrustStore`` values, keyed by SubjectKeyIdentifier.
///
/// A diff is information for the consumer to act on. Nothing in swift-matter applies it.
public struct TrustStoreDiff: Sendable, Equatable {

    /// One PAA named in a diff.
    public struct Entry: Sendable, Equatable {
        public let subject: String
        public let vendorID: UInt16?
        public let subjectKeyIdentifier: Data

        public init(subject: String, vendorID: UInt16?, subjectKeyIdentifier: Data) {
            self.subject = subject
            self.vendorID = vendorID
            self.subjectKeyIdentifier = subjectKeyIdentifier
        }
    }

    /// Present in the new store only.
    public var added: [Entry]

    /// Present in the old store only.
    public var removed: [Entry]

    /// Same SubjectKeyIdentifier, different certificate bytes.
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
