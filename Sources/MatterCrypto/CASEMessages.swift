// CASEMessages.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

/// CASE (Certificate Authenticated Session Establishment) message structures.
///
/// CASE uses a 3-message Sigma protocol:
/// - **Sigma1** (Initiator → Responder): ephemeral public key, destination ID
/// - **Sigma2** (Responder → Initiator): ephemeral public key, encrypted payload
/// - **Sigma3** (Initiator → Responder): encrypted payload
///
/// Each message is TLV-encoded with context-specific tags per the Matter spec (Section 4.13).

// MARK: - Sigma1

/// Sigma1 message — sent by the initiator to begin CASE.
///
/// ```
/// Structure {
///   1: initiatorRandom (octet string, 32 bytes)
///   2: initiatorSessionID (unsigned int, 16-bit)
///   3: destinationID (octet string, 32 bytes)
///   4: initiatorEphPubKey (octet string, 65 bytes)
///   5: initiatorSessionParams (structure, optional)
///   6: resumptionID (octet string, 16 bytes, optional)
///   7: initiatorResumeMIC (octet string, 16 bytes, optional)
/// }
/// ```
public struct Sigma1Message: Sendable, Equatable {

    private enum Tag {
        static let initiatorRandom: UInt8 = 1
        static let initiatorSessionID: UInt8 = 2
        static let destinationID: UInt8 = 3
        static let initiatorEphPubKey: UInt8 = 4
        static let initiatorSessionParams: UInt8 = 5
        static let resumptionID: UInt8 = 6
        static let initiatorResumeMIC: UInt8 = 7
    }

    /// 32 bytes of random data from the initiator.
    public let initiatorRandom: Data

    /// The initiator's proposed session ID.
    public let initiatorSessionID: UInt16

    /// HMAC-SHA256 targeting a specific fabric+node (32 bytes).
    public let destinationID: Data

    /// Initiator's ephemeral P-256 public key (65 bytes, uncompressed).
    public let initiatorEphPubKey: Data

    /// Optional session parameter negotiations.
    public let initiatorSessionParams: SessionParameters?

    /// Optional resumption ID (16 bytes, for session resumption).
    public let resumptionID: Data?

    /// Optional resumption MIC (16 bytes).
    public let initiatorResumeMIC: Data?

    public init(
        initiatorRandom: Data,
        initiatorSessionID: UInt16,
        destinationID: Data,
        initiatorEphPubKey: Data,
        initiatorSessionParams: SessionParameters? = nil,
        resumptionID: Data? = nil,
        initiatorResumeMIC: Data? = nil
    ) {
        self.initiatorRandom = initiatorRandom
        self.initiatorSessionID = initiatorSessionID
        self.destinationID = destinationID
        self.initiatorEphPubKey = initiatorEphPubKey
        self.initiatorSessionParams = initiatorSessionParams
        self.resumptionID = resumptionID
        self.initiatorResumeMIC = initiatorResumeMIC
    }

    // MARK: - TLV Encoding

    public func tlvEncode() -> Data {
        TLVEncoder.encode(toTLVElement())
    }

    public func toTLVElement() -> TLVElement {
        var fields: [TLVElement.TLVField] = []

        fields.append(.init(tag: .contextSpecific(Tag.initiatorRandom), value: .octetString(initiatorRandom)))
        fields.append(.init(tag: .contextSpecific(Tag.initiatorSessionID), value: .unsignedInt(UInt64(initiatorSessionID))))
        fields.append(.init(tag: .contextSpecific(Tag.destinationID), value: .octetString(destinationID)))
        fields.append(.init(tag: .contextSpecific(Tag.initiatorEphPubKey), value: .octetString(initiatorEphPubKey)))

        if let params = initiatorSessionParams {
            fields.append(.init(tag: .contextSpecific(Tag.initiatorSessionParams), value: params.toTLVElement()))
        }
        if let rid = resumptionID {
            fields.append(.init(tag: .contextSpecific(Tag.resumptionID), value: .octetString(rid)))
        }
        if let mic = initiatorResumeMIC {
            fields.append(.init(tag: .contextSpecific(Tag.initiatorResumeMIC), value: .octetString(mic)))
        }

        return .structure(fields)
    }

    // MARK: - TLV Decoding

    public static func fromTLV(_ data: Data) throws -> Sigma1Message {
        let (_, element) = try TLVDecoder.decode(data)
        return try fromTLVElement(element)
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> Sigma1Message {
        guard case .structure(let fields) = element else {
            throw CASEError.invalidMessage("Sigma1: expected structure")
        }

        guard let random = fields.first(where: { $0.tag == .contextSpecific(Tag.initiatorRandom) })?.value.dataValue,
              random.count == 32 else {
            throw CASEError.invalidMessage("Sigma1: missing/invalid initiatorRandom")
        }

        guard let sessionID = fields.first(where: { $0.tag == .contextSpecific(Tag.initiatorSessionID) })?.value.uintValue else {
            throw CASEError.invalidMessage("Sigma1: missing initiatorSessionID")
        }

        guard let destID = fields.first(where: { $0.tag == .contextSpecific(Tag.destinationID) })?.value.dataValue,
              destID.count == 32 else {
            throw CASEError.invalidMessage("Sigma1: missing/invalid destinationID")
        }

        guard let ephPubKey = fields.first(where: { $0.tag == .contextSpecific(Tag.initiatorEphPubKey) })?.value.dataValue,
              ephPubKey.count == 65 else {
            throw CASEError.invalidMessage("Sigma1: missing/invalid initiatorEphPubKey")
        }

        var sessionParams: SessionParameters?
        if let paramsField = fields.first(where: { $0.tag == .contextSpecific(Tag.initiatorSessionParams) }) {
            sessionParams = try SessionParameters.fromTLVElement(paramsField.value)
        }

        let resumptionID = fields.first(where: { $0.tag == .contextSpecific(Tag.resumptionID) })?.value.dataValue
        let resumeMIC = fields.first(where: { $0.tag == .contextSpecific(Tag.initiatorResumeMIC) })?.value.dataValue

        return Sigma1Message(
            initiatorRandom: random,
            initiatorSessionID: UInt16(sessionID),
            destinationID: destID,
            initiatorEphPubKey: ephPubKey,
            initiatorSessionParams: sessionParams,
            resumptionID: resumptionID,
            initiatorResumeMIC: resumeMIC
        )
    }
}

// MARK: - Sigma2

/// Sigma2 message — sent by the responder after processing Sigma1.
///
/// ```
/// Structure {
///   1: responderRandom (octet string, 32 bytes)
///   2: responderSessionID (unsigned int, 16-bit)
///   3: responderEphPubKey (octet string, 65 bytes)
///   4: encrypted2 (octet string — TBS2_Encrypted)
///   5: responderSessionParams (structure, optional)
/// }
/// ```
public struct Sigma2Message: Sendable, Equatable {

    private enum Tag {
        static let responderRandom: UInt8 = 1
        static let responderSessionID: UInt8 = 2
        static let responderEphPubKey: UInt8 = 3
        static let encrypted2: UInt8 = 4
        static let responderSessionParams: UInt8 = 5
    }

    /// 32 bytes of random data from the responder.
    public let responderRandom: Data

    /// The responder's proposed session ID.
    public let responderSessionID: UInt16

    /// Responder's ephemeral P-256 public key (65 bytes, uncompressed).
    public let responderEphPubKey: Data

    /// Encrypted payload containing NOC, ICAC, signature, and resumption ID.
    public let encrypted2: Data

    /// Optional session parameter negotiations.
    public let responderSessionParams: SessionParameters?

    public init(
        responderRandom: Data,
        responderSessionID: UInt16,
        responderEphPubKey: Data,
        encrypted2: Data,
        responderSessionParams: SessionParameters? = nil
    ) {
        self.responderRandom = responderRandom
        self.responderSessionID = responderSessionID
        self.responderEphPubKey = responderEphPubKey
        self.encrypted2 = encrypted2
        self.responderSessionParams = responderSessionParams
    }

    public func tlvEncode() -> Data {
        TLVEncoder.encode(toTLVElement())
    }

    public func toTLVElement() -> TLVElement {
        var fields: [TLVElement.TLVField] = []

        fields.append(.init(tag: .contextSpecific(Tag.responderRandom), value: .octetString(responderRandom)))
        fields.append(.init(tag: .contextSpecific(Tag.responderSessionID), value: .unsignedInt(UInt64(responderSessionID))))
        fields.append(.init(tag: .contextSpecific(Tag.responderEphPubKey), value: .octetString(responderEphPubKey)))
        fields.append(.init(tag: .contextSpecific(Tag.encrypted2), value: .octetString(encrypted2)))

        if let params = responderSessionParams {
            fields.append(.init(tag: .contextSpecific(Tag.responderSessionParams), value: params.toTLVElement()))
        }

        return .structure(fields)
    }

    public static func fromTLV(_ data: Data) throws -> Sigma2Message {
        let (_, element) = try TLVDecoder.decode(data)
        return try fromTLVElement(element)
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> Sigma2Message {
        guard case .structure(let fields) = element else {
            throw CASEError.invalidMessage("Sigma2: expected structure")
        }

        guard let random = fields.first(where: { $0.tag == .contextSpecific(Tag.responderRandom) })?.value.dataValue,
              random.count == 32 else {
            throw CASEError.invalidMessage("Sigma2: missing/invalid responderRandom")
        }

        guard let sessionID = fields.first(where: { $0.tag == .contextSpecific(Tag.responderSessionID) })?.value.uintValue else {
            throw CASEError.invalidMessage("Sigma2: missing responderSessionID")
        }

        guard let ephPubKey = fields.first(where: { $0.tag == .contextSpecific(Tag.responderEphPubKey) })?.value.dataValue,
              ephPubKey.count == 65 else {
            throw CASEError.invalidMessage("Sigma2: missing/invalid responderEphPubKey")
        }

        guard let encrypted = fields.first(where: { $0.tag == .contextSpecific(Tag.encrypted2) })?.value.dataValue else {
            throw CASEError.invalidMessage("Sigma2: missing encrypted2")
        }

        var sessionParams: SessionParameters?
        if let paramsField = fields.first(where: { $0.tag == .contextSpecific(Tag.responderSessionParams) }) {
            sessionParams = try SessionParameters.fromTLVElement(paramsField.value)
        }

        return Sigma2Message(
            responderRandom: random,
            responderSessionID: UInt16(sessionID),
            responderEphPubKey: ephPubKey,
            encrypted2: encrypted,
            responderSessionParams: sessionParams
        )
    }
}

// MARK: - Sigma3

/// Sigma3 message — sent by the initiator to complete CASE.
///
/// ```
/// Structure {
///   1: encrypted3 (octet string — TBS3_Encrypted)
/// }
/// ```
public struct Sigma3Message: Sendable, Equatable {

    private enum Tag {
        static let encrypted3: UInt8 = 1
    }

    /// Encrypted payload containing initiator's NOC, ICAC, and signature.
    public let encrypted3: Data

    public init(encrypted3: Data) {
        self.encrypted3 = encrypted3
    }

    public func tlvEncode() -> Data {
        TLVEncoder.encode(toTLVElement())
    }

    public func toTLVElement() -> TLVElement {
        .structure([
            .init(tag: .contextSpecific(Tag.encrypted3), value: .octetString(encrypted3))
        ])
    }

    public static func fromTLV(_ data: Data) throws -> Sigma3Message {
        let (_, element) = try TLVDecoder.decode(data)
        return try fromTLVElement(element)
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> Sigma3Message {
        guard case .structure(let fields) = element else {
            throw CASEError.invalidMessage("Sigma3: expected structure")
        }

        guard let encrypted = fields.first(where: { $0.tag == .contextSpecific(Tag.encrypted3) })?.value.dataValue else {
            throw CASEError.invalidMessage("Sigma3: missing encrypted3")
        }

        return Sigma3Message(encrypted3: encrypted)
    }
}

// MARK: - TBS Data Structures

/// To-Be-Signed data for Sigma2 (responder's signature input).
///
/// ```
/// Structure {
///   1: responderNOC (octet string — TLV-encoded certificate)
///   2: responderICAC (octet string — TLV-encoded certificate, optional)
///   3: responderEphPubKey (octet string, 65 bytes)
///   4: initiatorEphPubKey (octet string, 65 bytes)
/// }
/// ```
public struct TBSData2: Sendable, Equatable {

    private enum Tag {
        static let responderNOC: UInt8 = 1
        static let responderICAC: UInt8 = 2
        static let responderEphPubKey: UInt8 = 3
        static let initiatorEphPubKey: UInt8 = 4
    }

    public let responderNOC: Data
    public let responderICAC: Data?
    public let responderEphPubKey: Data
    public let initiatorEphPubKey: Data

    public init(
        responderNOC: Data,
        responderICAC: Data? = nil,
        responderEphPubKey: Data,
        initiatorEphPubKey: Data
    ) {
        self.responderNOC = responderNOC
        self.responderICAC = responderICAC
        self.responderEphPubKey = responderEphPubKey
        self.initiatorEphPubKey = initiatorEphPubKey
    }

    public func tlvEncode() -> Data {
        var fields: [TLVElement.TLVField] = []
        fields.append(.init(tag: .contextSpecific(Tag.responderNOC), value: .octetString(responderNOC)))
        if let icac = responderICAC {
            fields.append(.init(tag: .contextSpecific(Tag.responderICAC), value: .octetString(icac)))
        }
        fields.append(.init(tag: .contextSpecific(Tag.responderEphPubKey), value: .octetString(responderEphPubKey)))
        fields.append(.init(tag: .contextSpecific(Tag.initiatorEphPubKey), value: .octetString(initiatorEphPubKey)))
        return TLVEncoder.encode(.structure(fields))
    }
}

/// To-Be-Signed data for Sigma3 (initiator's signature input).
///
/// ```
/// Structure {
///   1: initiatorNOC (octet string — TLV-encoded certificate)
///   2: initiatorICAC (octet string — TLV-encoded certificate, optional)
///   3: initiatorEphPubKey (octet string, 65 bytes)
///   4: responderEphPubKey (octet string, 65 bytes)
/// }
/// ```
public struct TBSData3: Sendable, Equatable {

    private enum Tag {
        static let initiatorNOC: UInt8 = 1
        static let initiatorICAC: UInt8 = 2
        static let initiatorEphPubKey: UInt8 = 3
        static let responderEphPubKey: UInt8 = 4
    }

    public let initiatorNOC: Data
    public let initiatorICAC: Data?
    public let initiatorEphPubKey: Data
    public let responderEphPubKey: Data

    public init(
        initiatorNOC: Data,
        initiatorICAC: Data? = nil,
        initiatorEphPubKey: Data,
        responderEphPubKey: Data
    ) {
        self.initiatorNOC = initiatorNOC
        self.initiatorICAC = initiatorICAC
        self.initiatorEphPubKey = initiatorEphPubKey
        self.responderEphPubKey = responderEphPubKey
    }

    public func tlvEncode() -> Data {
        var fields: [TLVElement.TLVField] = []
        fields.append(.init(tag: .contextSpecific(Tag.initiatorNOC), value: .octetString(initiatorNOC)))
        if let icac = initiatorICAC {
            fields.append(.init(tag: .contextSpecific(Tag.initiatorICAC), value: .octetString(icac)))
        }
        fields.append(.init(tag: .contextSpecific(Tag.initiatorEphPubKey), value: .octetString(initiatorEphPubKey)))
        fields.append(.init(tag: .contextSpecific(Tag.responderEphPubKey), value: .octetString(responderEphPubKey)))
        return TLVEncoder.encode(.structure(fields))
    }
}

/// Decrypted payload from Sigma2's encrypted2 field.
///
/// ```
/// Structure {
///   1: responderNOC (octet string)
///   2: responderICAC (octet string, optional)
///   3: signature (octet string)
///   4: resumptionID (octet string, 16 bytes)
/// }
/// ```
public struct Sigma2Decrypted: Sendable, Equatable {

    private enum Tag {
        static let responderNOC: UInt8 = 1
        static let responderICAC: UInt8 = 2
        static let signature: UInt8 = 3
        static let resumptionID: UInt8 = 4
    }

    public let responderNOC: Data
    public let responderICAC: Data?
    public let signature: Data
    public let resumptionID: Data

    public init(
        responderNOC: Data,
        responderICAC: Data? = nil,
        signature: Data,
        resumptionID: Data
    ) {
        self.responderNOC = responderNOC
        self.responderICAC = responderICAC
        self.signature = signature
        self.resumptionID = resumptionID
    }

    public func tlvEncode() -> Data {
        var fields: [TLVElement.TLVField] = []
        fields.append(.init(tag: .contextSpecific(Tag.responderNOC), value: .octetString(responderNOC)))
        if let icac = responderICAC {
            fields.append(.init(tag: .contextSpecific(Tag.responderICAC), value: .octetString(icac)))
        }
        fields.append(.init(tag: .contextSpecific(Tag.signature), value: .octetString(signature)))
        fields.append(.init(tag: .contextSpecific(Tag.resumptionID), value: .octetString(resumptionID)))
        return TLVEncoder.encode(.structure(fields))
    }

    public static func fromTLV(_ data: Data) throws -> Sigma2Decrypted {
        let (_, element) = try TLVDecoder.decode(data)
        return try fromTLVElement(element)
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> Sigma2Decrypted {
        guard case .structure(let fields) = element else {
            throw CASEError.invalidMessage("Sigma2Decrypted: expected structure")
        }

        guard let noc = fields.first(where: { $0.tag == .contextSpecific(Tag.responderNOC) })?.value.dataValue else {
            throw CASEError.invalidMessage("Sigma2Decrypted: missing responderNOC")
        }

        let icac = fields.first(where: { $0.tag == .contextSpecific(Tag.responderICAC) })?.value.dataValue

        guard let sig = fields.first(where: { $0.tag == .contextSpecific(Tag.signature) })?.value.dataValue else {
            throw CASEError.invalidMessage("Sigma2Decrypted: missing signature")
        }

        guard let rid = fields.first(where: { $0.tag == .contextSpecific(Tag.resumptionID) })?.value.dataValue else {
            throw CASEError.invalidMessage("Sigma2Decrypted: missing resumptionID")
        }

        return Sigma2Decrypted(
            responderNOC: noc,
            responderICAC: icac,
            signature: sig,
            resumptionID: rid
        )
    }
}

/// Decrypted payload from Sigma3's encrypted3 field.
///
/// ```
/// Structure {
///   1: initiatorNOC (octet string)
///   2: initiatorICAC (octet string, optional)
///   3: signature (octet string)
/// }
/// ```
public struct Sigma3Decrypted: Sendable, Equatable {

    private enum Tag {
        static let initiatorNOC: UInt8 = 1
        static let initiatorICAC: UInt8 = 2
        static let signature: UInt8 = 3
    }

    public let initiatorNOC: Data
    public let initiatorICAC: Data?
    public let signature: Data

    public init(
        initiatorNOC: Data,
        initiatorICAC: Data? = nil,
        signature: Data
    ) {
        self.initiatorNOC = initiatorNOC
        self.initiatorICAC = initiatorICAC
        self.signature = signature
    }

    public func tlvEncode() -> Data {
        var fields: [TLVElement.TLVField] = []
        fields.append(.init(tag: .contextSpecific(Tag.initiatorNOC), value: .octetString(initiatorNOC)))
        if let icac = initiatorICAC {
            fields.append(.init(tag: .contextSpecific(Tag.initiatorICAC), value: .octetString(icac)))
        }
        fields.append(.init(tag: .contextSpecific(Tag.signature), value: .octetString(signature)))
        return TLVEncoder.encode(.structure(fields))
    }

    public static func fromTLV(_ data: Data) throws -> Sigma3Decrypted {
        let (_, element) = try TLVDecoder.decode(data)
        return try fromTLVElement(element)
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> Sigma3Decrypted {
        guard case .structure(let fields) = element else {
            throw CASEError.invalidMessage("Sigma3Decrypted: expected structure")
        }

        guard let noc = fields.first(where: { $0.tag == .contextSpecific(Tag.initiatorNOC) })?.value.dataValue else {
            throw CASEError.invalidMessage("Sigma3Decrypted: missing initiatorNOC")
        }

        let icac = fields.first(where: { $0.tag == .contextSpecific(Tag.initiatorICAC) })?.value.dataValue

        guard let sig = fields.first(where: { $0.tag == .contextSpecific(Tag.signature) })?.value.dataValue else {
            throw CASEError.invalidMessage("Sigma3Decrypted: missing signature")
        }

        return Sigma3Decrypted(
            initiatorNOC: noc,
            initiatorICAC: icac,
            signature: sig
        )
    }
}

// MARK: - Session Parameters

/// Session parameter negotiation (idle/active retransmission intervals, active threshold).
///
/// ```
/// Structure {
///   1: sessionIdleInterval (unsigned int, milliseconds, optional)
///   2: sessionActiveInterval (unsigned int, milliseconds, optional)
///   3: sessionActiveThreshold (unsigned int, milliseconds, optional)
///   4: dataModelRevision (unsigned int, optional)
///   5: interactionModelRevision (unsigned int, optional)
///   6: specificationVersion (unsigned int, optional)
///   7: maxPathsPerInvoke (unsigned int, optional)
/// }
/// ```
public struct SessionParameters: Sendable, Equatable {

    private enum Tag {
        static let sessionIdleInterval: UInt8 = 1
        static let sessionActiveInterval: UInt8 = 2
        static let sessionActiveThreshold: UInt8 = 3
        static let dataModelRevision: UInt8 = 4
        static let interactionModelRevision: UInt8 = 5
        static let specificationVersion: UInt8 = 6
        static let maxPathsPerInvoke: UInt8 = 7
    }

    public let sessionIdleInterval: UInt32?
    public let sessionActiveInterval: UInt32?
    public let sessionActiveThreshold: UInt16?
    public let dataModelRevision: UInt16?
    public let interactionModelRevision: UInt16?
    public let specificationVersion: UInt32?
    public let maxPathsPerInvoke: UInt16?

    public init(
        sessionIdleInterval: UInt32? = nil,
        sessionActiveInterval: UInt32? = nil,
        sessionActiveThreshold: UInt16? = nil,
        dataModelRevision: UInt16? = nil,
        interactionModelRevision: UInt16? = nil,
        specificationVersion: UInt32? = nil,
        maxPathsPerInvoke: UInt16? = nil
    ) {
        self.sessionIdleInterval = sessionIdleInterval
        self.sessionActiveInterval = sessionActiveInterval
        self.sessionActiveThreshold = sessionActiveThreshold
        self.dataModelRevision = dataModelRevision
        self.interactionModelRevision = interactionModelRevision
        self.specificationVersion = specificationVersion
        self.maxPathsPerInvoke = maxPathsPerInvoke
    }

    public func toTLVElement() -> TLVElement {
        var fields: [TLVElement.TLVField] = []
        if let v = sessionIdleInterval {
            fields.append(.init(tag: .contextSpecific(Tag.sessionIdleInterval), value: .unsignedInt(UInt64(v))))
        }
        if let v = sessionActiveInterval {
            fields.append(.init(tag: .contextSpecific(Tag.sessionActiveInterval), value: .unsignedInt(UInt64(v))))
        }
        if let v = sessionActiveThreshold {
            fields.append(.init(tag: .contextSpecific(Tag.sessionActiveThreshold), value: .unsignedInt(UInt64(v))))
        }
        if let v = dataModelRevision {
            fields.append(.init(tag: .contextSpecific(Tag.dataModelRevision), value: .unsignedInt(UInt64(v))))
        }
        if let v = interactionModelRevision {
            fields.append(.init(tag: .contextSpecific(Tag.interactionModelRevision), value: .unsignedInt(UInt64(v))))
        }
        if let v = specificationVersion {
            fields.append(.init(tag: .contextSpecific(Tag.specificationVersion), value: .unsignedInt(UInt64(v))))
        }
        if let v = maxPathsPerInvoke {
            fields.append(.init(tag: .contextSpecific(Tag.maxPathsPerInvoke), value: .unsignedInt(UInt64(v))))
        }
        return .structure(fields)
    }

    public static func fromTLVElement(_ element: TLVElement) throws -> SessionParameters {
        guard case .structure(let fields) = element else {
            throw CASEError.invalidMessage("SessionParameters: expected structure")
        }

        return SessionParameters(
            sessionIdleInterval: fields.first(where: { $0.tag == .contextSpecific(Tag.sessionIdleInterval) })?.value.uintValue.map { UInt32($0) },
            sessionActiveInterval: fields.first(where: { $0.tag == .contextSpecific(Tag.sessionActiveInterval) })?.value.uintValue.map { UInt32($0) },
            sessionActiveThreshold: fields.first(where: { $0.tag == .contextSpecific(Tag.sessionActiveThreshold) })?.value.uintValue.map { UInt16($0) },
            dataModelRevision: fields.first(where: { $0.tag == .contextSpecific(Tag.dataModelRevision) })?.value.uintValue.map { UInt16($0) },
            interactionModelRevision: fields.first(where: { $0.tag == .contextSpecific(Tag.interactionModelRevision) })?.value.uintValue.map { UInt16($0) },
            specificationVersion: fields.first(where: { $0.tag == .contextSpecific(Tag.specificationVersion) })?.value.uintValue.map { UInt32($0) },
            maxPathsPerInvoke: fields.first(where: { $0.tag == .contextSpecific(Tag.maxPathsPerInvoke) })?.value.uintValue.map { UInt16($0) }
        )
    }
}

// MARK: - CASE Errors

/// Errors in CASE session establishment.
public enum CASEError: Error, Sendable, Equatable {
    case invalidMessage(String)
    case destinationIDMismatch
    case signatureVerificationFailed
    case certificateChainInvalid
    case decryptionFailed
    case unsupportedResumption
}
