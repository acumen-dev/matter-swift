// TimeSynchronization.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

/// Time Synchronization cluster (0x0038).
///
/// Provides UTC time synchronization for Matter nodes. Allows a controller to
/// set the UTC time and granularity. Optional but commonly expected by controllers.
public enum TimeSynchronizationCluster {

    // MARK: - Cluster ID

    public static let id = ClusterID(rawValue: 0x0038)

    // MARK: - Attribute IDs

    public enum Attribute {
        public static let utcTime            = AttributeID(rawValue: 0x0000)
        public static let granularity        = AttributeID(rawValue: 0x0001)
        public static let timeSource         = AttributeID(rawValue: 0x0002)
        public static let trustedTimeSource  = AttributeID(rawValue: 0x0003)
        public static let defaultNTP         = AttributeID(rawValue: 0x0004)
        public static let featureMap         = AttributeID(rawValue: 0xFFFC)
        public static let clusterRevision    = AttributeID(rawValue: 0xFFFD)
    }

    // MARK: - Command IDs

    public enum Command {
        public static let setUTCTime = CommandID(rawValue: 0x00)
    }

    // MARK: - Granularity

    /// Time synchronization granularity — how precise the current time is.
    public enum Granularity: UInt8, Sendable, Equatable {
        case noTimeGranularity      = 0
        case minutesGranularity     = 1
        case secondsGranularity     = 2
        case millisecondsGranularity = 3
        case microsecondsGranularity = 4
    }

    // MARK: - TimeSource

    /// Source of the node's time.
    public enum TimeSource: UInt8, Sendable, Equatable {
        case none    = 0
        case unknown = 1
        case admin   = 2
    }

    // MARK: - SetUTCTimeRequest

    /// SetUTCTime command fields.
    ///
    /// ```
    /// Structure {
    ///   0: utcTime (unsigned int, epoch microseconds)
    ///   1: granularity (unsigned int — Granularity)
    ///   2: timeSource (unsigned int — TimeSource, optional)
    /// }
    /// ```
    public struct SetUTCTimeRequest: Sendable, Equatable {
        public let utcTime: UInt64
        public let granularity: Granularity
        public let timeSource: TimeSource?

        public init(utcTime: UInt64, granularity: Granularity, timeSource: TimeSource? = nil) {
            self.utcTime = utcTime
            self.granularity = granularity
            self.timeSource = timeSource
        }

        public func toTLVElement() -> TLVElement {
            var fields: [TLVElement.TLVField] = [
                .init(tag: .contextSpecific(0), value: .unsignedInt(utcTime)),
                .init(tag: .contextSpecific(1), value: .unsignedInt(UInt64(granularity.rawValue)))
            ]
            if let source = timeSource {
                fields.append(.init(tag: .contextSpecific(2), value: .unsignedInt(UInt64(source.rawValue))))
            }
            return .structure(fields)
        }

        public static func fromTLVElement(_ element: TLVElement) throws -> SetUTCTimeRequest {
            guard case .structure(let fields) = element else {
                throw TimeSynchronizationError.invalidStructure
            }
            guard let time = fields.first(where: { $0.tag == .contextSpecific(0) })?.value.uintValue else {
                throw TimeSynchronizationError.missingField
            }
            guard let granVal = fields.first(where: { $0.tag == .contextSpecific(1) })?.value.uintValue,
                  let gran = Granularity(rawValue: UInt8(granVal)) else {
                throw TimeSynchronizationError.missingField
            }
            var source: TimeSource?
            if let sourceVal = fields.first(where: { $0.tag == .contextSpecific(2) })?.value.uintValue {
                source = TimeSource(rawValue: UInt8(sourceVal))
            }
            return SetUTCTimeRequest(utcTime: time, granularity: gran, timeSource: source)
        }
    }

    // MARK: - Errors

    public enum TimeSynchronizationError: Error, Sendable {
        case invalidStructure
        case missingField
        case invalidGranularity
    }
}
