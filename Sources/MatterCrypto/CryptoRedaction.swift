// CryptoRedaction.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

extension SessionKeys: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// Holds the I2R, R2I and attestation keys: never rendered.
    public var description: String { "SessionKeys(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["summary": description], displayStyle: .struct) }
}

extension FabricInfo: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// The fabric's identity only: the operational key and the IPK epoch key are never rendered.
    public var description: String {
        "FabricInfo(fabricIndex: \(fabricIndex.rawValue), fabricID: \(MatterHex.string(fabricID.rawValue)), nodeID: \(MatterHex.string(nodeID.rawValue)), keys: <redacted>)"
    }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["summary": description], displayStyle: .struct) }
}

extension ResumptionTicket: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// The peer and expiry only: the resumption ID and the shared secret are never rendered.
    public var description: String {
        "ResumptionTicket(peerNode: \(MatterHex.string(peerNodeID.rawValue)), peerFabric: \(MatterHex.string(peerFabricID.rawValue)), fabricIndex: \(fabricIndex.rawValue), expires: \(expiryDate), secrets: <redacted>)"
    }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["summary": description], displayStyle: .struct) }
}

extension DeviceAttestationCredentials: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// The DAC private key is never rendered (nor the certificates, which are only noise).
    public var description: String { "DeviceAttestationCredentials(dacPrivateKey: <redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["summary": description], displayStyle: .struct) }
}

extension CASESession.InitiatorContext: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// The session id only: the ephemeral key, the IPK, the fabric's keys and the Sigma1 bytes
    /// are never rendered.
    public var description: String {
        "InitiatorContext(initiatorSession: \(MatterHex.string(initiatorSessionID)), keys: <redacted>)"
    }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["summary": description], displayStyle: .struct) }
}

extension CASESession.ResponderContext: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// The session id only: the ephemeral key, the shared secret, the IPK, the fabric's keys and
    /// the Sigma bytes are never rendered.
    public var description: String {
        "ResponderContext(responderSession: \(MatterHex.string(responderSessionID)), keys: <redacted>)"
    }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["summary": description], displayStyle: .struct) }
}

extension ResumptionTicketStore: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// The capacity only: the tickets (resumption IDs and shared secrets) are never rendered.
    public nonisolated var description: String { "ResumptionTicketStore(maxTickets: \(maxTickets), tickets: <redacted>)" }
    public nonisolated var debugDescription: String { description }
    public nonisolated var customMirror: Mirror { Mirror(self, children: ["summary": description], displayStyle: .class) }
}
