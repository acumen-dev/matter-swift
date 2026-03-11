// StatusReport.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

/// A Matter Status Report message payload.
///
/// Sent via Secure Channel opcode 0x40. Contains a general status,
/// a protocol-specific status, and optional protocol-specific data.
///
/// ## Wire Format
///
/// ```
/// [general status: 2] [protocol ID: 4] [protocol status: 2] [data: variable]
/// ```
public struct StatusReportMessage: Sendable, Equatable {
    /// General status code.
    public var generalStatus: GeneralStatusCode

    /// Fully-qualified protocol ID (vendor << 16 | protocol).
    public var protocolID: UInt32

    /// Protocol-specific status code.
    public var protocolStatus: UInt16

    /// Optional protocol-specific data.
    public var protocolData: Data?

    public init(
        generalStatus: GeneralStatusCode,
        protocolID: UInt32,
        protocolStatus: UInt16,
        protocolData: Data? = nil
    ) {
        self.generalStatus = generalStatus
        self.protocolID = protocolID
        self.protocolStatus = protocolStatus
        self.protocolData = protocolData
    }
}

// MARK: - Encoding

extension StatusReportMessage {
    /// Encode to wire format.
    public func encode() -> Data {
        var buffer = Data(capacity: 8 + (protocolData?.count ?? 0))

        buffer.appendLittleEndian(generalStatus.rawValue)
        buffer.appendLittleEndian(protocolID)
        buffer.appendLittleEndian(protocolStatus)

        if let data = protocolData {
            buffer.append(data)
        }

        return buffer
    }
}

// MARK: - Decoding

extension StatusReportMessage {
    /// Decode from wire format.
    public static func decode(from data: Data) throws -> StatusReportMessage {
        var reader = ByteReader(data: data)

        let generalRaw = try reader.readUInt16()
        guard let general = GeneralStatusCode(rawValue: generalRaw) else {
            // Accept unknown general status codes for forward compatibility
            return StatusReportMessage(
                generalStatus: .failure,
                protocolID: try reader.readUInt32(),
                protocolStatus: try reader.readUInt16(),
                protocolData: reader.remaining.isEmpty ? nil : Data(reader.remaining)
            )
        }

        let protoID = try reader.readUInt32()
        let protoStatus = try reader.readUInt16()
        let remaining = reader.remaining

        return StatusReportMessage(
            generalStatus: general,
            protocolID: protoID,
            protocolStatus: protoStatus,
            protocolData: remaining.isEmpty ? nil : Data(remaining)
        )
    }
}
