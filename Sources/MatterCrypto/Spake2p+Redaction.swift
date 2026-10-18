// Spake2p+Redaction.swift
// Copyright 2026 Monagle Pty Ltd

extension Spake2pProverContext: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// Holds x and w0: never rendered.
    public var description: String { "Spake2pProverContext(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [Mirror.Child](), displayStyle: .struct) }
}

extension Spake2pVerifierContext: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// Holds y, Ke and the confirmation key: never rendered.
    public var description: String { "Spake2pVerifierContext(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [Mirror.Child](), displayStyle: .struct) }
}

extension Spake2pVerifier: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// Holds w0 and L, from which the passcode can be brute-forced offline: never rendered.
    public var description: String { "Spake2pVerifier(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["summary": description], displayStyle: .struct) }
}
