// MatterHex.swift
// Copyright 2026 Monagle Pty Ltd

/// How Matter ids are rendered as text.
package enum MatterHex {
    /// `0x` plus upper-case hex, no padding: `0xA`, `0x102`. The id format of the controller's
    /// log metadata, span attributes and redacted descriptions.
    package static func string<T: BinaryInteger>(_ value: T) -> String {
        "0x" + String(value, radix: 16, uppercase: true)
    }
}
