// ExchangeHeader.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

/// Matter exchange (protocol) header.
///
/// This header is part of the encrypted payload — it gets encrypted along with
/// the application data. It identifies the exchange, protocol, and message type.
///
/// ## Wire Format
///
/// ```
/// [exchange flags: 1] [protocol opcode: 1] [exchange ID: 2]
/// [protocol vendor ID: 0|2] [protocol ID: 2] [ack counter: 0|4]
/// ```
///
/// Base size: 6 bytes. Maximum: 12 bytes.
public struct ExchangeHeader: Sendable, Equatable {
    /// Exchange behavior flags.
    public var flags: ExchangeFlags

    /// Protocol-specific message type / opcode.
    public var protocolOpcode: UInt8

    /// Exchange identifier, unique within a session.
    public var exchangeID: UInt16

    /// Protocol vendor ID (present when V flag is set, 0 for standard protocols).
    public var protocolVendorID: UInt16

    /// Protocol ID within the vendor namespace.
    public var protocolID: UInt16

    /// Acknowledged message counter (present when A flag is set).
    public var acknowledgedMessageCounter: UInt32?

    public init(
        flags: ExchangeFlags = ExchangeFlags(),
        protocolOpcode: UInt8,
        exchangeID: UInt16,
        protocolVendorID: UInt16 = 0,
        protocolID: UInt16,
        acknowledgedMessageCounter: UInt32? = nil
    ) {
        self.flags = flags
        self.protocolOpcode = protocolOpcode
        self.exchangeID = exchangeID
        self.protocolVendorID = protocolVendorID
        self.protocolID = protocolID
        self.acknowledgedMessageCounter = acknowledgedMessageCounter

        // Sync flags with optional fields
        if acknowledgedMessageCounter != nil {
            self.flags.acknowledgment = true
        }
        if protocolVendorID != 0 {
            self.flags.vendorIDPresent = true
        }
    }
}

// MARK: - Exchange Flags

/// Flags in the exchange header byte.
public struct ExchangeFlags: Sendable, Equatable {
    /// Message sent by the exchange initiator.
    public var initiator: Bool

    /// This message carries an acknowledgment.
    public var acknowledgment: Bool

    /// Sender requests acknowledgment via MRP.
    public var reliableDelivery: Bool

    /// Secured extension block present.
    public var securedExtension: Bool

    /// Vendor ID field is present before protocol ID.
    public var vendorIDPresent: Bool

    public init(
        initiator: Bool = false,
        acknowledgment: Bool = false,
        reliableDelivery: Bool = false,
        securedExtension: Bool = false,
        vendorIDPresent: Bool = false
    ) {
        self.initiator = initiator
        self.acknowledgment = acknowledgment
        self.reliableDelivery = reliableDelivery
        self.securedExtension = securedExtension
        self.vendorIDPresent = vendorIDPresent
    }

    /// Encode to wire format byte.
    public var rawValue: UInt8 {
        var flags: UInt8 = 0
        if initiator { flags |= 0x01 }
        if acknowledgment { flags |= 0x02 }
        if reliableDelivery { flags |= 0x04 }
        if securedExtension { flags |= 0x08 }
        if vendorIDPresent { flags |= 0x10 }
        return flags
    }

    /// Decode from wire format byte.
    public init(rawValue: UInt8) {
        self.initiator = (rawValue & 0x01) != 0
        self.acknowledgment = (rawValue & 0x02) != 0
        self.reliableDelivery = (rawValue & 0x04) != 0
        self.securedExtension = (rawValue & 0x08) != 0
        self.vendorIDPresent = (rawValue & 0x10) != 0
    }
}

// MARK: - Computed Properties

extension ExchangeHeader {
    /// The fully-qualified protocol ID (vendor << 16 | protocol).
    public var qualifiedProtocolID: UInt32 {
        (UInt32(protocolVendorID) << 16) | UInt32(protocolID)
    }

    /// The encoded size of this header in bytes.
    public var encodedSize: Int {
        var size = 6 // flags(1) + opcode(1) + exchangeID(2) + protocolID(2)
        if flags.vendorIDPresent { size += 2 }
        if flags.acknowledgment { size += 4 }
        return size
    }
}

// MARK: - Encoding

extension ExchangeHeader {
    /// Encode the exchange header to bytes.
    public func encode() -> Data {
        var buffer = Data(capacity: encodedSize)

        buffer.append(flags.rawValue)
        buffer.append(protocolOpcode)
        buffer.appendLittleEndian(exchangeID)

        if flags.vendorIDPresent {
            buffer.appendLittleEndian(protocolVendorID)
        }
        buffer.appendLittleEndian(protocolID)

        if flags.acknowledgment, let ack = acknowledgedMessageCounter {
            buffer.appendLittleEndian(ack)
        }

        return buffer
    }
}

// MARK: - Decoding

extension ExchangeHeader {
    /// Decode an exchange header from data, returning the header and bytes consumed.
    public static func decode(from data: Data) throws -> (header: ExchangeHeader, bytesConsumed: Int) {
        var reader = ByteReader(data: data)

        let flagsRaw = try reader.readUInt8()
        let flags = ExchangeFlags(rawValue: flagsRaw)

        let opcode = try reader.readUInt8()
        let exchangeID = try reader.readUInt16()

        var vendorID: UInt16 = 0
        if flags.vendorIDPresent {
            vendorID = try reader.readUInt16()
        }
        let protocolID = try reader.readUInt16()

        var ackCounter: UInt32?
        if flags.acknowledgment {
            ackCounter = try reader.readUInt32()
        }

        let header = ExchangeHeader(
            flags: flags,
            protocolOpcode: opcode,
            exchangeID: exchangeID,
            protocolVendorID: vendorID,
            protocolID: protocolID,
            acknowledgedMessageCounter: ackCounter
        )

        return (header, reader.offset)
    }
}
