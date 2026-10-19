// StoredTypes+Redaction.swift
// Copyright 2026 Monagle Pty Ltd

// Both types are `Equatable`: their summary-only mirrors also hide their fields in an
// `#expect(a == b)` failure diff. That is accepted; compare fields directly to see them.

extension StoredFabric: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// The fabric's identity only: the operational private key and the IPK epoch key are never rendered.
    public var description: String {
        "StoredFabric(fabricIndex: \(fabricIndex), caseAdminSubject: \(MatterHex.string(caseAdminSubject)), adminVendorId: \(MatterHex.string(adminVendorId)), keys: <redacted>)"
    }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["summary": description], displayStyle: .struct) }
}

extension StoredControllerIdentity: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// The identity only: the root key, the operational private key and the IPK epoch key are never rendered.
    public var description: String {
        "StoredControllerIdentity(fabricIndex: \(fabricIndex), fabricID: \(MatterHex.string(fabricID)), controllerNodeID: \(MatterHex.string(controllerNodeID)), vendorID: \(MatterHex.string(vendorID)), keys: <redacted>)"
    }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["summary": description], displayStyle: .struct) }
}
