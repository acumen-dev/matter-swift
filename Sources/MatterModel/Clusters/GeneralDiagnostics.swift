// GeneralDiagnostics.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

/// General Diagnostics cluster (0x0033).
///
/// Provides diagnostics information about the node's general health, including
/// network interfaces, reboot count, uptime, and hardware/software fault lists.
/// Required on root endpoint (endpoint 0) for all Matter devices.
public enum GeneralDiagnosticsCluster {

    // MARK: - Cluster ID

    public static let id = ClusterID(rawValue: 0x0033)

    // MARK: - Attribute IDs

    public enum Attribute {
        public static let networkInterfaces      = AttributeID(rawValue: 0x0000)
        public static let rebootCount            = AttributeID(rawValue: 0x0001)
        public static let upTime                 = AttributeID(rawValue: 0x0002)
        public static let bootReason             = AttributeID(rawValue: 0x0004)
        public static let activeHardwareFaults   = AttributeID(rawValue: 0x0005)
        public static let activeRadioFaults      = AttributeID(rawValue: 0x0006)
        public static let activeNetworkFaults    = AttributeID(rawValue: 0x0007)
        public static let testEventTriggersEnabled = AttributeID(rawValue: 0x0008)
        public static let featureMap             = AttributeID(rawValue: 0xFFFC)
        public static let clusterRevision        = AttributeID(rawValue: 0xFFFD)
    }

    // MARK: - Command IDs

    public enum Command {
        public static let testEventTrigger = CommandID(rawValue: 0x00)
    }

    // MARK: - Event IDs

    public enum Event {
        public static let bootReason = EventID(rawValue: 0x00)
    }

    // MARK: - InterfaceType

    /// Network interface type.
    public enum InterfaceType: UInt8, Sendable, Equatable {
        case unspecified = 0
        case wifi        = 1
        case ethernet    = 2
        case cellular    = 3
        case thread      = 4
    }

    // MARK: - BootReasonEnum

    /// Reason for the last device boot.
    public enum BootReasonEnum: UInt8, Sendable, Equatable {
        case unspecified                = 0
        case powerOnReboot              = 1
        case brownOutReset              = 2
        case softwareWatchdogReset      = 3
        case hardwareWatchdogReset      = 4
        case softwareUpdateCompleted    = 5
        case softwareReset              = 6
    }

    // MARK: - NetworkInterface

    /// A network interface entry in the `networkInterfaces` attribute.
    ///
    /// ```
    /// Structure {
    ///   0: name (utf8string)
    ///   1: isOperational (bool)
    ///   2: offPremiseServicesReachableIPv4 (bool, nullable)
    ///   3: offPremiseServicesReachableIPv6 (bool, nullable)
    ///   4: hardwareAddress (octet string)
    ///   5: ipv4Addresses (array of octet strings)
    ///   6: ipv6Addresses (array of octet strings)
    ///   7: type (unsigned int — InterfaceType)
    /// }
    /// ```
    public struct NetworkInterface: Sendable, Equatable {
        public let name: String
        public let isOperational: Bool
        public let offPremiseServicesReachableIPv4: Bool?
        public let offPremiseServicesReachableIPv6: Bool?
        public let hardwareAddress: Data
        public let ipv4Addresses: [Data]
        public let ipv6Addresses: [Data]
        public let type: InterfaceType

        public init(
            name: String,
            isOperational: Bool,
            offPremiseServicesReachableIPv4: Bool? = nil,
            offPremiseServicesReachableIPv6: Bool? = nil,
            hardwareAddress: Data,
            ipv4Addresses: [Data] = [],
            ipv6Addresses: [Data] = [],
            type: InterfaceType
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
            var fields: [TLVElement.TLVField] = []
            fields.append(.init(tag: .contextSpecific(0), value: .utf8String(name)))
            fields.append(.init(tag: .contextSpecific(1), value: .bool(isOperational)))

            if let v = offPremiseServicesReachableIPv4 {
                fields.append(.init(tag: .contextSpecific(2), value: .bool(v)))
            } else {
                fields.append(.init(tag: .contextSpecific(2), value: .null))
            }

            if let v = offPremiseServicesReachableIPv6 {
                fields.append(.init(tag: .contextSpecific(3), value: .bool(v)))
            } else {
                fields.append(.init(tag: .contextSpecific(3), value: .null))
            }

            fields.append(.init(tag: .contextSpecific(4), value: .octetString(hardwareAddress)))

            let ipv4Array: [TLVElement] = ipv4Addresses.map { .octetString($0) }
            fields.append(.init(tag: .contextSpecific(5), value: .array(ipv4Array)))

            let ipv6Array: [TLVElement] = ipv6Addresses.map { .octetString($0) }
            fields.append(.init(tag: .contextSpecific(6), value: .array(ipv6Array)))

            fields.append(.init(tag: .contextSpecific(7), value: .unsignedInt(UInt64(type.rawValue))))

            return .structure(fields)
        }
    }

    // MARK: - TestEventTriggerRequest

    /// TestEventTrigger command fields.
    ///
    /// ```
    /// Structure {
    ///   0: enableKey (octet string, 16 bytes)
    ///   1: eventTrigger (unsigned int)
    /// }
    /// ```
    public struct TestEventTriggerRequest: Sendable, Equatable {
        public let enableKey: Data
        public let eventTrigger: UInt64

        public init(enableKey: Data, eventTrigger: UInt64) {
            self.enableKey = enableKey
            self.eventTrigger = eventTrigger
        }

        public func toTLVElement() -> TLVElement {
            .structure([
                .init(tag: .contextSpecific(0), value: .octetString(enableKey)),
                .init(tag: .contextSpecific(1), value: .unsignedInt(eventTrigger))
            ])
        }

        public static func fromTLVElement(_ element: TLVElement) throws -> TestEventTriggerRequest {
            guard case .structure(let fields) = element else {
                throw GeneralDiagnosticsError.invalidStructure
            }
            guard let key = fields.first(where: { $0.tag == .contextSpecific(0) })?.value.dataValue else {
                throw GeneralDiagnosticsError.missingField
            }
            guard let trigger = fields.first(where: { $0.tag == .contextSpecific(1) })?.value.uintValue else {
                throw GeneralDiagnosticsError.missingField
            }
            return TestEventTriggerRequest(enableKey: key, eventTrigger: trigger)
        }
    }

    // MARK: - Errors

    public enum GeneralDiagnosticsError: Error, Sendable {
        case invalidStructure
        case missingField
        case testEventTriggersNotEnabled
    }
}
