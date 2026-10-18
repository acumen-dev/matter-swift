// SetupCode+Redaction.swift
// Copyright 2026 Monagle Pty Ltd

extension SetupCode: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// Everything but the passcode (which, with the discriminator, is the whole secret code).
    public var description: String {
        var parts = ["passcode: <redacted>", "discriminator: \(discriminatorText)"]
        if let vendorID { parts.append("vendorID: \(MatterHex.string(vendorID))") }
        if let productID { parts.append("productID: \(MatterHex.string(productID))") }
        if let commissioningFlow { parts.append("flow: \(commissioningFlow)") }
        return "SetupCode(\(parts.joined(separator: ", ")))"
    }

    public var debugDescription: String { description }

    public var customMirror: Mirror {
        Mirror(self, children: ["passcode": "<redacted>", "discriminator": discriminatorText], displayStyle: .struct)
    }

    private var discriminatorText: String {
        switch discriminator {
        case .long(let value): return "long(\(value))"
        case .short(let value): return "short(\(value))"
        }
    }
}
