// GeneralCommissioning.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

/// General Commissioning cluster (0x0030).
///
/// Manages the commissioning process on the device. Used during commissioning
/// to arm the fail-safe timer, set regulatory configuration, and signal
/// commissioning completion.
public enum GeneralCommissioningCluster {

    // MARK: - Cluster ID

    public static let id = ClusterID(rawValue: 0x0030)

    // MARK: - Attribute IDs

    public enum Attribute {
        public static let breadcrumb                 = AttributeID(rawValue: 0x0000)
        public static let basicCommissioningInfo     = AttributeID(rawValue: 0x0001)
        public static let regulatoryConfig           = AttributeID(rawValue: 0x0002)
        public static let locationCapability         = AttributeID(rawValue: 0x0003)
        public static let supportsConcurrentConnection = AttributeID(rawValue: 0x0004)
    }

    // MARK: - Command IDs

    public enum Command {
        public static let armFailSafe            = CommandID(rawValue: 0x00)
        public static let armFailSafeResponse    = CommandID(rawValue: 0x01)
        public static let setRegulatoryConfig    = CommandID(rawValue: 0x02)
        public static let setRegulatoryConfigResponse = CommandID(rawValue: 0x03)
        public static let commissioningComplete  = CommandID(rawValue: 0x04)
        public static let commissioningCompleteResponse = CommandID(rawValue: 0x05)
    }

    // MARK: - Event IDs

    public enum Event {
        /// CommissioningComplete event — emitted when commissioning completes. Priority: Info.
        public static let commissioningComplete = EventID(rawValue: 0x02)
    }

    // MARK: - Commissioning Error

    /// Error codes returned by General Commissioning commands.
    public enum CommissioningError: UInt8, Sendable, Equatable {
        case ok                          = 0
        case valueOutsideRange           = 1
        case invalidAuthentication       = 2
        case noFailSafe                  = 3
        case busyWithOtherAdmin          = 4
    }

    // MARK: - Regulatory Location Type

    /// Regulatory location type for SetRegulatoryConfig.
    public enum RegulatoryLocationType: UInt8, Sendable, Equatable {
        case indoor         = 0
        case outdoor        = 1
        case indoorOutdoor  = 2
    }

    // MARK: - ArmFailSafe Request

    /// ArmFailSafe command fields.
    ///
    /// ```
    /// Structure {
    ///   0: expiryLengthSeconds (unsigned int)
    ///   1: breadcrumb (unsigned int)
    /// }
    /// ```
    public struct ArmFailSafeRequest: Sendable, Equatable {

        public let expiryLengthSeconds: UInt16
        public let breadcrumb: UInt64

        public init(expiryLengthSeconds: UInt16, breadcrumb: UInt64 = 0) {
            self.expiryLengthSeconds = expiryLengthSeconds
            self.breadcrumb = breadcrumb
        }

        public func toTLVElement() -> TLVElement {
            .structure([
                .init(tag: .contextSpecific(0), value: .unsignedInt(UInt64(expiryLengthSeconds))),
                .init(tag: .contextSpecific(1), value: .unsignedInt(breadcrumb))
            ])
        }

        public static func fromTLVElement(_ element: TLVElement) throws -> ArmFailSafeRequest {
            guard case .structure(let fields) = element else {
                throw GeneralCommissioningError.invalidStructure
            }
            guard let expiry = fields.first(where: { $0.tag == .contextSpecific(0) })?.value.uintValue,
                  let bc = fields.first(where: { $0.tag == .contextSpecific(1) })?.value.uintValue else {
                throw GeneralCommissioningError.missingField
            }
            return ArmFailSafeRequest(expiryLengthSeconds: UInt16(expiry), breadcrumb: bc)
        }
    }

    // MARK: - ArmFailSafe Response

    /// ArmFailSafeResponse command fields.
    ///
    /// ```
    /// Structure {
    ///   0: errorCode (unsigned int — CommissioningError)
    ///   1: debugText (string)
    /// }
    /// ```
    public struct ArmFailSafeResponse: Sendable, Equatable {

        public let errorCode: CommissioningError
        public let debugText: String

        public init(errorCode: CommissioningError, debugText: String = "") {
            self.errorCode = errorCode
            self.debugText = debugText
        }

        public func toTLVElement() -> TLVElement {
            .structure([
                .init(tag: .contextSpecific(0), value: .unsignedInt(UInt64(errorCode.rawValue))),
                .init(tag: .contextSpecific(1), value: .utf8String(debugText))
            ])
        }

        public static func fromTLVElement(_ element: TLVElement) throws -> ArmFailSafeResponse {
            guard case .structure(let fields) = element else {
                throw GeneralCommissioningError.invalidStructure
            }
            guard let ec = fields.first(where: { $0.tag == .contextSpecific(0) })?.value.uintValue,
                  let error = CommissioningError(rawValue: UInt8(ec)),
                  let dt = fields.first(where: { $0.tag == .contextSpecific(1) })?.value.stringValue else {
                throw GeneralCommissioningError.missingField
            }
            return ArmFailSafeResponse(errorCode: error, debugText: dt)
        }
    }

    // MARK: - SetRegulatoryConfig Request

    /// SetRegulatoryConfig command fields.
    ///
    /// ```
    /// Structure {
    ///   0: newRegulatoryConfig (unsigned int — RegulatoryLocationType)
    ///   1: countryCode (string, 2 chars)
    ///   2: breadcrumb (unsigned int)
    /// }
    /// ```
    public struct SetRegulatoryConfigRequest: Sendable, Equatable {

        public let newRegulatoryConfig: RegulatoryLocationType
        public let countryCode: String
        public let breadcrumb: UInt64

        public init(newRegulatoryConfig: RegulatoryLocationType, countryCode: String = "XX", breadcrumb: UInt64 = 0) {
            self.newRegulatoryConfig = newRegulatoryConfig
            self.countryCode = countryCode
            self.breadcrumb = breadcrumb
        }

        public func toTLVElement() -> TLVElement {
            .structure([
                .init(tag: .contextSpecific(0), value: .unsignedInt(UInt64(newRegulatoryConfig.rawValue))),
                .init(tag: .contextSpecific(1), value: .utf8String(countryCode)),
                .init(tag: .contextSpecific(2), value: .unsignedInt(breadcrumb))
            ])
        }

        public static func fromTLVElement(_ element: TLVElement) throws -> SetRegulatoryConfigRequest {
            guard case .structure(let fields) = element else {
                throw GeneralCommissioningError.invalidStructure
            }
            guard let rc = fields.first(where: { $0.tag == .contextSpecific(0) })?.value.uintValue,
                  let regConfig = RegulatoryLocationType(rawValue: UInt8(rc)),
                  let cc = fields.first(where: { $0.tag == .contextSpecific(1) })?.value.stringValue,
                  let bc = fields.first(where: { $0.tag == .contextSpecific(2) })?.value.uintValue else {
                throw GeneralCommissioningError.missingField
            }
            return SetRegulatoryConfigRequest(newRegulatoryConfig: regConfig, countryCode: cc, breadcrumb: bc)
        }
    }

    // MARK: - SetRegulatoryConfig Response

    /// SetRegulatoryConfigResponse command fields.
    ///
    /// ```
    /// Structure {
    ///   0: errorCode (unsigned int — CommissioningError)
    ///   1: debugText (string)
    /// }
    /// ```
    public struct SetRegulatoryConfigResponse: Sendable, Equatable {

        public let errorCode: CommissioningError
        public let debugText: String

        public init(errorCode: CommissioningError, debugText: String = "") {
            self.errorCode = errorCode
            self.debugText = debugText
        }

        public func toTLVElement() -> TLVElement {
            .structure([
                .init(tag: .contextSpecific(0), value: .unsignedInt(UInt64(errorCode.rawValue))),
                .init(tag: .contextSpecific(1), value: .utf8String(debugText))
            ])
        }

        public static func fromTLVElement(_ element: TLVElement) throws -> SetRegulatoryConfigResponse {
            guard case .structure(let fields) = element else {
                throw GeneralCommissioningError.invalidStructure
            }
            guard let ec = fields.first(where: { $0.tag == .contextSpecific(0) })?.value.uintValue,
                  let error = CommissioningError(rawValue: UInt8(ec)),
                  let dt = fields.first(where: { $0.tag == .contextSpecific(1) })?.value.stringValue else {
                throw GeneralCommissioningError.missingField
            }
            return SetRegulatoryConfigResponse(errorCode: error, debugText: dt)
        }
    }

    // MARK: - CommissioningComplete Response

    /// CommissioningCompleteResponse command fields.
    ///
    /// ```
    /// Structure {
    ///   0: errorCode (unsigned int — CommissioningError)
    ///   1: debugText (string)
    /// }
    /// ```
    public struct CommissioningCompleteResponse: Sendable, Equatable {

        public let errorCode: CommissioningError
        public let debugText: String

        public init(errorCode: CommissioningError, debugText: String = "") {
            self.errorCode = errorCode
            self.debugText = debugText
        }

        public func toTLVElement() -> TLVElement {
            .structure([
                .init(tag: .contextSpecific(0), value: .unsignedInt(UInt64(errorCode.rawValue))),
                .init(tag: .contextSpecific(1), value: .utf8String(debugText))
            ])
        }

        public static func fromTLVElement(_ element: TLVElement) throws -> CommissioningCompleteResponse {
            guard case .structure(let fields) = element else {
                throw GeneralCommissioningError.invalidStructure
            }
            guard let ec = fields.first(where: { $0.tag == .contextSpecific(0) })?.value.uintValue,
                  let error = CommissioningError(rawValue: UInt8(ec)),
                  let dt = fields.first(where: { $0.tag == .contextSpecific(1) })?.value.stringValue else {
                throw GeneralCommissioningError.missingField
            }
            return CommissioningCompleteResponse(errorCode: error, debugText: dt)
        }
    }

    // MARK: - Errors

    public enum GeneralCommissioningError: Error, Sendable {
        case invalidStructure
        case missingField
    }
}
