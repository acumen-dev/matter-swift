// PASEMessages.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

/// TLV message structures for the PASE (Password-Authenticated Session
/// Establishment) handshake protocol.
///
/// These messages are exchanged over unsecured sessions during commissioning
/// to establish a shared secret via SPAKE2+.
public enum PASEMessages {

    // MARK: - PBKDFParamRequest

    /// Initiator's first message — requests PBKDF parameters from the device.
    ///
    /// ```
    /// Structure {
    ///   1: initiatorRandom (octet string, 32 bytes)
    ///   2: initiatorSessionId (unsigned int, 16-bit)
    ///   3: passcodeId (unsigned int, 16-bit)
    ///   4: hasPBKDFParameters (bool)
    ///   5: initiatorSessionParams (structure, optional)
    /// }
    /// ```
    public struct PBKDFParamRequest: Sendable, Equatable {

        public let initiatorRandom: Data
        public let initiatorSessionID: UInt16
        public let passcodeID: UInt16
        public let hasPBKDFParameters: Bool

        public init(
            initiatorRandom: Data,
            initiatorSessionID: UInt16,
            passcodeID: UInt16 = 0,
            hasPBKDFParameters: Bool = false
        ) {
            self.initiatorRandom = initiatorRandom
            self.initiatorSessionID = initiatorSessionID
            self.passcodeID = passcodeID
            self.hasPBKDFParameters = hasPBKDFParameters
        }

        public func tlvEncode() -> Data {
            let element = TLVElement.structure([
                .init(tag: .contextSpecific(1), value: .octetString(initiatorRandom)),
                .init(tag: .contextSpecific(2), value: .unsignedInt(UInt64(initiatorSessionID))),
                .init(tag: .contextSpecific(3), value: .unsignedInt(UInt64(passcodeID))),
                .init(tag: .contextSpecific(4), value: .bool(hasPBKDFParameters))
            ])
            return TLVEncoder.encode(element)
        }

        public static func fromTLV(_ data: Data) throws -> PBKDFParamRequest {
            let (_, element) = try TLVDecoder.decode(data)
            guard case .structure(let fields) = element else {
                throw PASEError.invalidStructure
            }
            guard let random = fields.first(where: { $0.tag == .contextSpecific(1) })?.value.dataValue,
                  let sessID = fields.first(where: { $0.tag == .contextSpecific(2) })?.value.uintValue,
                  let pcID = fields.first(where: { $0.tag == .contextSpecific(3) })?.value.uintValue,
                  let hasPBKDF = fields.first(where: { $0.tag == .contextSpecific(4) })?.value.boolValue else {
                throw PASEError.missingField
            }
            return PBKDFParamRequest(
                initiatorRandom: random,
                initiatorSessionID: UInt16(sessID),
                passcodeID: UInt16(pcID),
                hasPBKDFParameters: hasPBKDF
            )
        }
    }

    // MARK: - PBKDFParamResponse

    /// Device's response — provides PBKDF parameters and responder session info.
    ///
    /// ```
    /// Structure {
    ///   1: initiatorRandom (octet string, 32 bytes — echo)
    ///   2: responderRandom (octet string, 32 bytes)
    ///   3: responderSessionId (unsigned int, 16-bit)
    ///   4: pbkdfParameters (structure)
    ///       {
    ///         1: iterations (unsigned int)
    ///         2: salt (octet string)
    ///       }
    ///   5: responderSessionParams (structure, optional)
    /// }
    /// ```
    public struct PBKDFParamResponse: Sendable, Equatable {

        public let initiatorRandom: Data
        public let responderRandom: Data
        public let responderSessionID: UInt16
        public let iterations: UInt32
        public let salt: Data

        public init(
            initiatorRandom: Data,
            responderRandom: Data,
            responderSessionID: UInt16,
            iterations: UInt32,
            salt: Data
        ) {
            self.initiatorRandom = initiatorRandom
            self.responderRandom = responderRandom
            self.responderSessionID = responderSessionID
            self.iterations = iterations
            self.salt = salt
        }

        /// Encode this response as TLV.
        ///
        /// - Parameters:
        ///   - includePBKDFParams: When `false`, tag 4 (pbkdf_parameters) is omitted.
        ///     Per Matter spec §5.3.2.1, if the initiator set `hasPBKDFParameters = true` in its
        ///     request, the responder MUST omit tag 4 — the initiator uses its cached parameters.
        ///   - idleRetransTimeoutMs: MRP idle retransmission timeout in milliseconds for tag 5
        ///     (responderSessionParams). Defaults to 4000 ms (Matter spec Table 13).
        ///   - activeRetransTimeoutMs: MRP active retransmission timeout in milliseconds for tag 5.
        ///     Defaults to 300 ms (Matter spec Table 13).
        ///
        /// Tag 5 (responderSessionParams) is always included — all conformant Matter device
        /// implementations send it, and Apple Home requires it to establish MRP timer state
        /// before accepting the handshake.
        public func tlvEncode(
            includePBKDFParams: Bool = true,
            idleRetransTimeoutMs: UInt32 = 4000,
            activeRetransTimeoutMs: UInt32 = 300
        ) -> Data {
            // Tag 5: responderSessionParams — MRP idle/active retransmission intervals.
            // The CHIP SDK always populates this field. Apple Home appears to require it:
            // responses without tag 5 are silently discarded and never acknowledged.
            let sessionParams = TLVElement.structure([
                .init(tag: .contextSpecific(1), value: .unsignedInt(UInt64(idleRetransTimeoutMs))),
                .init(tag: .contextSpecific(2), value: .unsignedInt(UInt64(activeRetransTimeoutMs)))
            ])

            if includePBKDFParams {
                let pbkdfParams = TLVElement.structure([
                    .init(tag: .contextSpecific(1), value: .unsignedInt(UInt64(iterations))),
                    .init(tag: .contextSpecific(2), value: .octetString(salt))
                ])
                let element = TLVElement.structure([
                    .init(tag: .contextSpecific(1), value: .octetString(initiatorRandom)),
                    .init(tag: .contextSpecific(2), value: .octetString(responderRandom)),
                    .init(tag: .contextSpecific(3), value: .unsignedInt(UInt64(responderSessionID))),
                    .init(tag: .contextSpecific(4), value: pbkdfParams),
                    .init(tag: .contextSpecific(5), value: sessionParams)
                ])
                return TLVEncoder.encode(element)
            } else {
                let element = TLVElement.structure([
                    .init(tag: .contextSpecific(1), value: .octetString(initiatorRandom)),
                    .init(tag: .contextSpecific(2), value: .octetString(responderRandom)),
                    .init(tag: .contextSpecific(3), value: .unsignedInt(UInt64(responderSessionID))),
                    .init(tag: .contextSpecific(5), value: sessionParams)
                ])
                return TLVEncoder.encode(element)
            }
        }

        public static func fromTLV(_ data: Data) throws -> PBKDFParamResponse {
            let (_, element) = try TLVDecoder.decode(data)
            guard case .structure(let fields) = element else {
                throw PASEError.invalidStructure
            }
            guard let iRandom = fields.first(where: { $0.tag == .contextSpecific(1) })?.value.dataValue,
                  let rRandom = fields.first(where: { $0.tag == .contextSpecific(2) })?.value.dataValue,
                  let rSessID = fields.first(where: { $0.tag == .contextSpecific(3) })?.value.uintValue else {
                throw PASEError.missingField
            }

            // Parse nested PBKDF parameters
            guard let pbkdfField = fields.first(where: { $0.tag == .contextSpecific(4) }),
                  case .structure(let pbkdfFields) = pbkdfField.value else {
                throw PASEError.missingField
            }
            guard let iterations = pbkdfFields.first(where: { $0.tag == .contextSpecific(1) })?.value.uintValue,
                  let salt = pbkdfFields.first(where: { $0.tag == .contextSpecific(2) })?.value.dataValue else {
                throw PASEError.missingField
            }

            return PBKDFParamResponse(
                initiatorRandom: iRandom,
                responderRandom: rRandom,
                responderSessionID: UInt16(rSessID),
                iterations: UInt32(iterations),
                salt: salt
            )
        }
    }

    // MARK: - Pake1

    /// Prover's first SPAKE2+ message — contains pA.
    ///
    /// ```
    /// Structure {
    ///   1: pA (octet string, 65 bytes — uncompressed SEC1 point)
    /// }
    /// ```
    public struct Pake1Message: Sendable, Equatable {

        public let pA: Data

        public init(pA: Data) {
            self.pA = pA
        }

        public func tlvEncode() -> Data {
            let element = TLVElement.structure([
                .init(tag: .contextSpecific(1), value: .octetString(pA))
            ])
            return TLVEncoder.encode(element)
        }

        public static func fromTLV(_ data: Data) throws -> Pake1Message {
            let (_, element) = try TLVDecoder.decode(data)
            guard case .structure(let fields) = element else {
                throw PASEError.invalidStructure
            }
            guard let pA = fields.first(where: { $0.tag == .contextSpecific(1) })?.value.dataValue else {
                throw PASEError.missingField
            }
            return Pake1Message(pA: pA)
        }
    }

    // MARK: - Pake2

    /// Verifier's SPAKE2+ message — contains pB and cB.
    ///
    /// ```
    /// Structure {
    ///   1: pB (octet string, 65 bytes — uncompressed SEC1 point)
    ///   2: cB (octet string, 32 bytes — confirmation MAC)
    /// }
    /// ```
    public struct Pake2Message: Sendable, Equatable {

        public let pB: Data
        public let cB: Data

        public init(pB: Data, cB: Data) {
            self.pB = pB
            self.cB = cB
        }

        public func tlvEncode() -> Data {
            let element = TLVElement.structure([
                .init(tag: .contextSpecific(1), value: .octetString(pB)),
                .init(tag: .contextSpecific(2), value: .octetString(cB))
            ])
            return TLVEncoder.encode(element)
        }

        public static func fromTLV(_ data: Data) throws -> Pake2Message {
            let (_, element) = try TLVDecoder.decode(data)
            guard case .structure(let fields) = element else {
                throw PASEError.invalidStructure
            }
            guard let pB = fields.first(where: { $0.tag == .contextSpecific(1) })?.value.dataValue,
                  let cB = fields.first(where: { $0.tag == .contextSpecific(2) })?.value.dataValue else {
                throw PASEError.missingField
            }
            return Pake2Message(pB: pB, cB: cB)
        }
    }

    // MARK: - Pake3

    /// Prover's confirmation message — contains cA.
    ///
    /// ```
    /// Structure {
    ///   1: cA (octet string, 32 bytes — confirmation MAC)
    /// }
    /// ```
    public struct Pake3Message: Sendable, Equatable {

        public let cA: Data

        public init(cA: Data) {
            self.cA = cA
        }

        public func tlvEncode() -> Data {
            let element = TLVElement.structure([
                .init(tag: .contextSpecific(1), value: .octetString(cA))
            ])
            return TLVEncoder.encode(element)
        }

        public static func fromTLV(_ data: Data) throws -> Pake3Message {
            let (_, element) = try TLVDecoder.decode(data)
            guard case .structure(let fields) = element else {
                throw PASEError.invalidStructure
            }
            guard let cA = fields.first(where: { $0.tag == .contextSpecific(1) })?.value.dataValue else {
                throw PASEError.missingField
            }
            return Pake3Message(cA: cA)
        }
    }

    // MARK: - Errors

    public enum PASEError: Error, Sendable {
        case invalidStructure
        case missingField
    }
}
