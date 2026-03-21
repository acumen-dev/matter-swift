// TimeSynchronization+Extensions.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

extension TimeSynchronizationCluster {

    // MARK: - Custom Types for Handler

    public enum TimeSynchronizationError: Error {
        case missingField
        case invalidGranularity
    }

    public struct SetUTCTimeRequest: Equatable {
        public let utcTime: UInt64
        public let granularity: GranularityEnum
        public let timeSource: TimeSourceEnum?

        public init(utcTime: UInt64, granularity: GranularityEnum, timeSource: TimeSourceEnum? = nil) {
            self.utcTime = utcTime
            self.granularity = granularity
            self.timeSource = timeSource
        }

        public func toTLVElement() -> TLVElement {
            var fields: [TLVElement.TLVField] = [
                TLVElement.TLVField(tag: .contextSpecific(0), value: .unsignedInt(utcTime)),
                TLVElement.TLVField(tag: .contextSpecific(1), value: .unsignedInt(UInt64(granularity.rawValue))),
            ]
            if let timeSource {
                fields.append(TLVElement.TLVField(tag: .contextSpecific(2), value: .unsignedInt(UInt64(timeSource.rawValue))))
            }
            return .structure(fields)
        }

        public static func fromTLVElement(_ element: TLVElement) throws -> SetUTCTimeRequest {
            guard case .structure(let fields) = element else {
                throw TimeSynchronizationError.missingField
            }
            guard let utcTimeField = fields.first(where: { $0.tag == .contextSpecific(0) }),
                  let utcTime = utcTimeField.value.uintValue else {
                throw TimeSynchronizationError.missingField
            }
            guard let granField = fields.first(where: { $0.tag == .contextSpecific(1) }),
                  let granRaw = granField.value.uintValue,
                  let granularity = GranularityEnum(rawValue: UInt8(granRaw)) else {
                throw TimeSynchronizationError.missingField
            }
            var timeSource: TimeSourceEnum?
            if let tsField = fields.first(where: { $0.tag == .contextSpecific(2) }),
               let tsRaw = tsField.value.uintValue {
                timeSource = TimeSourceEnum(rawValue: UInt8(tsRaw))
            }
            return SetUTCTimeRequest(utcTime: utcTime, granularity: granularity, timeSource: timeSource)
        }
    }
}
