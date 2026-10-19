// ProtocolRedaction.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

extension SecureSession: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// Ids only: the encrypt, decrypt and attestation keys are never rendered.
    public var description: String {
        var parts = [
            "local: \(MatterLogValue.hexString(localSessionID))",
            "peer: \(MatterLogValue.hexString(peerSessionID))",
            establishment == .case ? "case" : "pase",
            "peerNode: \(MatterLogValue.hexString(peerNodeID.rawValue))",
        ]
        if let fabricIndex { parts.append("fabricIndex: \(fabricIndex.rawValue)") }
        parts.append("keys: <redacted>")
        return "SecureSession(\(parts.joined(separator: ", ")))"
    }

    public var debugDescription: String { description }

    public var customMirror: Mirror {
        Mirror(self, children: [
            "localSessionID": localSessionID,
            "peerSessionID": peerSessionID,
            "establishment": establishment,
            "peerNodeID": peerNodeID,
            "keys": "<redacted>",
        ], displayStyle: .class)
    }
}

extension CASEProtocolHandler.InitiatorHandshakeContext: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// The peer only: the ephemeral key, shared secret and IPK-derived state are never rendered.
    public var description: String {
        "InitiatorHandshakeContext(peerNode: \(MatterLogValue.hexString(peerNodeID.rawValue)), peerFabric: \(MatterLogValue.hexString(peerFabricID.rawValue)), keys: <redacted>)"
    }

    public var debugDescription: String { description }

    public var customMirror: Mirror {
        Mirror(self, children: ["peerNodeID": peerNodeID, "keys": "<redacted>"], displayStyle: .struct)
    }
}

extension CASEProtocolHandler.ResponderHandshakeContext: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// Session ids only: the responder's CASE context (ephemeral key, shared secret, IPK) is never rendered.
    public var description: String {
        "ResponderHandshakeContext(initiatorSession: \(MatterLogValue.hexString(initiatorSessionID)), responderSession: \(MatterLogValue.hexString(caseContext.responderSessionID)), keys: <redacted>)"
    }

    public var debugDescription: String { description }

    public var customMirror: Mirror {
        Mirror(self, children: ["summary": description], displayStyle: .struct)
    }
}
