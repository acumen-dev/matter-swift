// MessageHeader.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

/// Matter message header (unencrypted plain header).
///
/// Every Matter message starts with this header, which is never encrypted.
/// It contains session identification, message counter for replay protection,
/// and optional source/destination addressing.
///
/// ## Wire Format
///
/// ```
/// [message flags: 1] [session ID: 2] [security flags: 1] [message counter: 4]
/// [source node ID: 0|8] [destination: 0|2|8] [message extensions: variable]
/// ```
///
/// Minimum size: 8 bytes. Maximum: 28 bytes (plus extensions).
public struct MessageHeader: Sendable, Equatable {
    /// Message format version (upper 4 bits of message flags). Currently 0.
    public var version: UInt8

    /// Whether the source node ID field is present.
    public var hasSourceNodeID: Bool

    /// Destination field encoding.
    public var destinationEncoding: DestinationEncoding

    /// Session identifier. 0x0000 = unsecured session.
    public var sessionID: UInt16

    /// Security configuration flags.
    public var securityFlags: SecurityFlags

    /// Monotonically increasing counter for replay protection.
    public var messageCounter: UInt32

    /// Source node ID (present when S flag is set).
    public var sourceNodeID: NodeID?

    /// Destination node ID (present when DSIZ = 0x01).
    public var destinationNodeID: NodeID?

    /// Destination group ID (present when DSIZ = 0x02).
    public var destinationGroupID: GroupID?

    public init(
        version: UInt8 = 0,
        sessionID: UInt16,
        securityFlags: SecurityFlags = SecurityFlags(),
        messageCounter: UInt32,
        sourceNodeID: NodeID? = nil,
        destinationNodeID: NodeID? = nil,
        destinationGroupID: GroupID? = nil
    ) {
        self.version = version
        self.hasSourceNodeID = sourceNodeID != nil
        self.destinationEncoding = if destinationNodeID != nil {
            .nodeID
        } else if destinationGroupID != nil {
            .groupID
        } else {
            .none
        }
        self.sessionID = sessionID
        self.securityFlags = securityFlags
        self.messageCounter = messageCounter
        self.sourceNodeID = sourceNodeID
        self.destinationNodeID = destinationNodeID
        self.destinationGroupID = destinationGroupID
    }
}

// MARK: - Destination Encoding

extension MessageHeader {
    /// How the destination field is encoded in the message flags (DSIZ bits 1:0).
    public enum DestinationEncoding: UInt8, Sendable, Equatable {
        /// No destination field present.
        case none = 0x00
        /// 64-bit destination node ID.
        case nodeID = 0x01
        /// 16-bit destination group ID.
        case groupID = 0x02
    }
}

// MARK: - Security Flags

extension MessageHeader {
    /// Security flags byte of the message header.
    public struct SecurityFlags: Sendable, Equatable {
        /// Privacy enhancements enabled (source/dest/counter encrypted).
        public var privacy: Bool

        /// Secure session control message.
        public var controlMessage: Bool

        /// Message extension data follows the header.
        public var messageExtension: Bool

        /// Session type.
        public var sessionType: SessionType

        public init(
            privacy: Bool = false,
            controlMessage: Bool = false,
            messageExtension: Bool = false,
            sessionType: SessionType = .unicast
        ) {
            self.privacy = privacy
            self.controlMessage = controlMessage
            self.messageExtension = messageExtension
            self.sessionType = sessionType
        }

        /// Encode to wire format byte.
        public var rawValue: UInt8 {
            var flags: UInt8 = sessionType.rawValue
            if privacy { flags |= 0x80 }
            if controlMessage { flags |= 0x40 }
            if messageExtension { flags |= 0x20 }
            return flags
        }

        /// Decode from wire format byte.
        public init(rawValue: UInt8) {
            self.privacy = (rawValue & 0x80) != 0
            self.controlMessage = (rawValue & 0x40) != 0
            self.messageExtension = (rawValue & 0x20) != 0
            self.sessionType = SessionType(rawValue: rawValue & 0x03) ?? .unicast
        }
    }
}

// MARK: - Session Type

extension MessageHeader {
    /// Matter session types.
    public enum SessionType: UInt8, Sendable, Equatable {
        /// Unicast session (also used for unsecured when session ID = 0).
        case unicast = 0
        /// Group/multicast session.
        case group = 1
    }
}

// MARK: - Computed Properties

extension MessageHeader {
    /// Whether this is an unsecured session (session ID 0, unicast).
    public var isUnsecured: Bool {
        sessionID == 0 && securityFlags.sessionType == .unicast
    }

    /// The encoded size of this header in bytes.
    public var encodedSize: Int {
        var size = 8 // fixed: flags(1) + sessionID(2) + secFlags(1) + counter(4)
        if sourceNodeID != nil { size += 8 }
        switch destinationEncoding {
        case .none: break
        case .nodeID: size += 8
        case .groupID: size += 2
        }
        return size
    }
}

// MARK: - Encoding

extension MessageHeader {
    /// Encode the header to bytes.
    public func encode() -> Data {
        var buffer = Data(capacity: encodedSize)

        // Message flags byte
        var flags: UInt8 = (version & 0x0F) << 4
        if sourceNodeID != nil { flags |= 0x04 }
        flags |= destinationEncoding.rawValue & 0x03
        buffer.append(flags)

        // Session ID (uint16 LE)
        buffer.appendLittleEndian(sessionID)

        // Security flags
        buffer.append(securityFlags.rawValue)

        // Message counter (uint32 LE)
        buffer.appendLittleEndian(messageCounter)

        // Optional source node ID (uint64 LE)
        if let source = sourceNodeID {
            buffer.appendLittleEndian(source.rawValue)
        }

        // Optional destination
        if let dest = destinationNodeID {
            buffer.appendLittleEndian(dest.rawValue)
        } else if let group = destinationGroupID {
            buffer.appendLittleEndian(group.rawValue)
        }

        return buffer
    }
}

// MARK: - Decoding

extension MessageHeader {
    /// Decode a message header from data, returning the header and bytes consumed.
    public static func decode(from data: Data) throws -> (header: MessageHeader, bytesConsumed: Int) {
        var reader = ByteReader(data: data)

        // Message flags
        let flags = try reader.readUInt8()
        let version = (flags >> 4) & 0x0F
        let hasSource = (flags & 0x04) != 0
        let dsiz = flags & 0x03

        guard let destEncoding = DestinationEncoding(rawValue: dsiz) else {
            throw MessageError.invalidDestinationEncoding(dsiz)
        }

        // Session ID
        let sessionID = try reader.readUInt16()

        // Security flags
        let secFlagsRaw = try reader.readUInt8()
        let secFlags = SecurityFlags(rawValue: secFlagsRaw)

        // Message counter
        let counter = try reader.readUInt32()

        // Source node ID
        let sourceNodeID: NodeID? = if hasSource {
            NodeID(rawValue: try reader.readUInt64())
        } else {
            nil
        }

        // Destination
        var destNodeID: NodeID?
        var destGroupID: GroupID?
        switch destEncoding {
        case .none: break
        case .nodeID:
            destNodeID = NodeID(rawValue: try reader.readUInt64())
        case .groupID:
            destGroupID = GroupID(rawValue: try reader.readUInt16())
        }

        // Skip message extensions if present
        if secFlags.messageExtension {
            let extLength = Int(try reader.readUInt16())
            try reader.skip(extLength)
        }

        var header = MessageHeader(
            version: version,
            sessionID: sessionID,
            securityFlags: secFlags,
            messageCounter: counter,
            sourceNodeID: sourceNodeID,
            destinationNodeID: destNodeID,
            destinationGroupID: destGroupID
        )
        header.hasSourceNodeID = hasSource
        header.destinationEncoding = destEncoding

        return (header, reader.offset)
    }
}

// MARK: - Errors

/// Errors from message header parsing.
public enum MessageError: Error, Sendable, Equatable {
    case unexpectedEndOfData
    case invalidDestinationEncoding(UInt8)
    case invalidExchangeFlags(UInt8)
    case invalidSessionType(UInt8)
}
