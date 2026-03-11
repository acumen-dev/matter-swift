// StatusCode.swift
// Copyright 2026 Monagle Pty Ltd

/// Matter Interaction Model status codes.
///
/// These are returned in Status Response messages and embedded in
/// Write/Invoke response payloads.
public enum IMStatusCode: UInt8, Sendable, Equatable {
    case success                        = 0x00
    case failure                        = 0x01
    case invalidSubscription            = 0x7D
    case unsupportedAccess              = 0x7E
    case unsupportedEndpoint            = 0x7F
    case invalidAction                  = 0x80
    case unsupportedCommand             = 0x81
    case invalidCommand                 = 0x85
    case unsupportedAttribute           = 0x86
    case constraintError                = 0x87
    case unsupportedWrite               = 0x88
    case resourceExhausted              = 0x89
    case notFound                       = 0x8B
    case unreportableAttribute          = 0x8C
    case invalidDataType                = 0x8D
    case unsupportedRead                = 0x8F
    case dataVersionMismatch            = 0x92
    case timeout                        = 0x94
    case busy                           = 0x9C
    case pathsExhausted                 = 0xC8
    case timedRequestMismatch           = 0xCB
    case failsafeRequired               = 0xCA
    case needsTimedInteraction          = 0xC6
    case unsupportedCluster             = 0xC3
    case duplicateExists                = 0xC9
}

/// Matter protocol-level status codes.
///
/// These are carried in the secure message layer for session/protocol errors.
public enum ProtocolStatusCode: UInt16, Sendable, Equatable {
    case success            = 0x0000
    case noSharedTrustRoots = 0x0001
    case invalidParam       = 0x0002
    case closeSession       = 0x0003
    case busy               = 0x0004
}
