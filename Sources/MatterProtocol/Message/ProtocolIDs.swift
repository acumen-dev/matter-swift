// ProtocolIDs.swift
// Copyright 2026 Monagle Pty Ltd

// MARK: - Protocol IDs

/// Standard Matter protocol identifiers.
///
/// Protocol IDs are conceptually 32-bit (vendor << 16 | protocol),
/// but for standard protocols the vendor ID is 0 and omitted on the wire.
public enum MatterProtocolID: UInt16, Sendable, Equatable {
    /// Secure Channel (PASE, CASE, MRP standalone ACK, status report).
    case secureChannel = 0x0000

    /// Interaction Model (read, write, subscribe, invoke).
    case interactionModel = 0x0001

    /// Bulk Data Exchange.
    case bdx = 0x0002

    /// User Directed Commissioning.
    case userDirectedCommissioning = 0x0003

    /// Echo (testing).
    case echo = 0x0004
}

// MARK: - Secure Channel Opcodes

/// Opcodes for the Secure Channel protocol (0x0000).
public enum SecureChannelOpcode: UInt8, Sendable, Equatable {
    /// Message counter synchronization request.
    case msgCounterSyncReq = 0x00

    /// Message counter synchronization response.
    case msgCounterSyncRsp = 0x01

    /// MRP standalone acknowledgment (no payload).
    case standaloneAck = 0x10

    /// PASE: PBKDF parameter request.
    case pbkdfParamRequest = 0x20

    /// PASE: PBKDF parameter response.
    case pbkdfParamResponse = 0x21

    /// PASE: SPAKE2+ round 1 (pA).
    case pasePake1 = 0x22

    /// PASE: SPAKE2+ round 2 (pB, cB).
    case pasePake2 = 0x23

    /// PASE: SPAKE2+ round 3 (cA).
    case pasePake3 = 0x24

    /// CASE: Sigma1 (initiator hello).
    case caseSigma1 = 0x30

    /// CASE: Sigma2 (responder hello).
    case caseSigma2 = 0x31

    /// CASE: Sigma3 (initiator finish).
    case caseSigma3 = 0x32

    /// CASE: Sigma2 session resumption.
    case caseSigma2Resume = 0x33

    /// Status report message.
    case statusReport = 0x40

    /// ICD (Intermittently Connected Device) check-in.
    case icdCheckIn = 0x50
}

// MARK: - Interaction Model Opcodes

/// Opcodes for the Interaction Model protocol (0x0001).
public enum InteractionModelOpcode: UInt8, Sendable, Equatable {
    /// Status response to a prior request.
    case statusResponse = 0x01

    /// Read attribute/event request.
    case readRequest = 0x02

    /// Subscribe to attribute/event changes.
    case subscribeRequest = 0x03

    /// Subscription confirmation.
    case subscribeResponse = 0x04

    /// Data report (read response / subscription notification).
    case reportData = 0x05

    /// Write attribute request.
    case writeRequest = 0x06

    /// Write attribute response.
    case writeResponse = 0x07

    /// Invoke command request.
    case invokeRequest = 0x08

    /// Invoke command response.
    case invokeResponse = 0x09

    /// Timed interaction request.
    case timedRequest = 0x0A
}

// MARK: - BDX Opcodes

/// Opcodes for the Bulk Data Exchange protocol (0x0002).
public enum BDXOpcode: UInt8, Sendable, Equatable {
    case sendInit = 0x01
    case sendAccept = 0x02
    case receiveInit = 0x04
    case receiveAccept = 0x05
    case blockQuery = 0x10
    case block = 0x11
    case blockEOF = 0x12
    case blockAck = 0x13
    case blockAckEOF = 0x14
    case blockQueryWithSkip = 0x15
}

// MARK: - General Status Codes

/// General status codes used in Status Report messages.
public enum GeneralStatusCode: UInt16, Sendable, Equatable {
    case success = 0
    case failure = 1
    case badPrecondition = 2
    case outOfRange = 3
    case badRequest = 4
    case unsupported = 5
    case unexpected = 6
    case resourceExhausted = 7
    case busy = 8
    case timeout = 9
    case `continue` = 10
    case aborted = 11
    case invalidArgument = 12
    case notFound = 13
    case alreadyExists = 14
    case permissionDenied = 15
    case dataLoss = 16
}

// MARK: - Secure Channel Status Codes

/// Protocol-specific status codes for the Secure Channel protocol.
public enum SecureChannelStatusCode: UInt16, Sendable, Equatable {
    case success = 0
    case noSharedTrustRoots = 1
    case invalidParameter = 2
    case closeSession = 3
    case busy = 4
    case sessionNotFound = 5
}
