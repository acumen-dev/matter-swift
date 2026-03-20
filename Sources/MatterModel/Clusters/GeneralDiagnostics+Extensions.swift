// GeneralDiagnostics+Extensions.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

extension GeneralDiagnosticsCluster {

    // MARK: - Errors

    public enum GeneralDiagnosticsError: Error {
        case missingField
        case testEventTriggersNotEnabled
    }

    // MARK: - Request Types

    public struct TestEventTriggerRequest: Sendable {
        public let enableKey: Data
        public let eventTrigger: UInt64

        public init(enableKey: Data, eventTrigger: UInt64) {
            self.enableKey = enableKey
            self.eventTrigger = eventTrigger
        }

        public func toTLVElement() -> TLVElement {
            .structure([
                TLVElement.TLVField(tag: .contextSpecific(0), value: .octetString(enableKey)),
                TLVElement.TLVField(tag: .contextSpecific(1), value: .unsignedInt(eventTrigger)),
            ])
        }

        public static func fromTLVElement(_ element: TLVElement) throws -> TestEventTriggerRequest {
            guard case .structure(let fields) = element else {
                throw GeneralDiagnosticsError.missingField
            }
            guard let enableKeyField = fields.first(where: { $0.tag == .contextSpecific(0) }),
                  let enableKey = enableKeyField.value.dataValue else {
                throw GeneralDiagnosticsError.missingField
            }
            guard let triggerField = fields.first(where: { $0.tag == .contextSpecific(1) }),
                  let eventTrigger = triggerField.value.uintValue else {
                throw GeneralDiagnosticsError.missingField
            }
            return TestEventTriggerRequest(enableKey: enableKey, eventTrigger: eventTrigger)
        }
    }

    // MARK: - Network Interface

    public struct NetworkInterface: Sendable {
        public let name: String
        public let isOperational: Bool
        public let offPremiseServicesReachableIPv4: Bool?
        public let offPremiseServicesReachableIPv6: Bool?
        public let hardwareAddress: Data
        public let ipv4Addresses: [Data]
        public let ipv6Addresses: [Data]
        public let type: InterfaceTypeEnum

        public init(
            name: String,
            isOperational: Bool,
            offPremiseServicesReachableIPv4: Bool?,
            offPremiseServicesReachableIPv6: Bool?,
            hardwareAddress: Data,
            ipv4Addresses: [Data],
            ipv6Addresses: [Data],
            type: InterfaceTypeEnum
        ) {
            self.name = name
            self.isOperational = isOperational
            self.offPremiseServicesReachableIPv4 = offPremiseServicesReachableIPv4
            self.offPremiseServicesReachableIPv6 = offPremiseServicesReachableIPv6
            self.hardwareAddress = hardwareAddress
            self.ipv4Addresses = ipv4Addresses
            self.ipv6Addresses = ipv6Addresses
            self.type = type
        }

        public func toTLVElement() -> TLVElement {
            var fields: [TLVElement.TLVField] = [
                TLVElement.TLVField(tag: .contextSpecific(0), value: .utf8String(name)),
                TLVElement.TLVField(tag: .contextSpecific(1), value: .bool(isOperational)),
            ]
            if let v4 = offPremiseServicesReachableIPv4 {
                fields.append(TLVElement.TLVField(tag: .contextSpecific(2), value: .bool(v4)))
            } else {
                fields.append(TLVElement.TLVField(tag: .contextSpecific(2), value: .null))
            }
            if let v6 = offPremiseServicesReachableIPv6 {
                fields.append(TLVElement.TLVField(tag: .contextSpecific(3), value: .bool(v6)))
            } else {
                fields.append(TLVElement.TLVField(tag: .contextSpecific(3), value: .null))
            }
            fields.append(TLVElement.TLVField(tag: .contextSpecific(4), value: .octetString(hardwareAddress)))
            fields.append(TLVElement.TLVField(
                tag: .contextSpecific(5),
                value: .array(ipv4Addresses.map { .octetString($0) })
            ))
            fields.append(TLVElement.TLVField(
                tag: .contextSpecific(6),
                value: .array(ipv6Addresses.map { .octetString($0) })
            ))
            fields.append(TLVElement.TLVField(
                tag: .contextSpecific(7),
                value: .unsignedInt(UInt64(type.rawValue))
            ))
            return .structure(fields)
        }
    }
}
