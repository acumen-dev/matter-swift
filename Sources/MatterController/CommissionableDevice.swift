// CommissionableDevice.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterProtocol
import MatterTransport

/// A commissionable (`_matterc._udp`) device that matched a setup code:
/// where to reach it, and what its TXT record advertised.
public struct CommissionableDevice: Sendable, Hashable {
    /// DNS-SD instance name.
    public let instanceName: String
    /// Resolved address to run PASE against.
    public let address: MatterAddress
    /// Full 12-bit discriminator (TXT `D`).
    public let discriminator: UInt16
    /// Vendor ID (TXT `VP` = "vid" or "vid+pid"); nil when not advertised.
    public let vendorID: UInt16?
    /// Product ID (TXT `VP` = "vid+pid"); nil when not advertised.
    public let productID: UInt16?
    /// Commissioning mode (TXT `CM`): 1 basic, 2 enhanced.
    public let commissioningMode: UInt8
    /// MRP timing from TXT `SII`/`SAI`/`SAT`; defaults where absent.
    public let mrp: MRPParameters
    /// The TXT record the device was matched and built from.
    public let txtRecords: [String: String]
}

// MARK: - Matching

extension CommissionableDevice {

    /// The TXT fields a setup code is matched against.
    struct Advertisement: Sendable {
        let discriminator: UInt16
        let commissioningMode: UInt8
        let vendorID: UInt16?
        let productID: UInt16?

        /// Parse and filter `txt` against `code`; nil when it does not match.
        ///
        /// - `D` must parse as `UInt16` and fit in 12 bits before `matches`
        ///   is consulted (`matches` masks with 0xFFF, so 0x1F00 would
        ///   otherwise match 3840).
        /// - `CM` must parse and be non-zero (not in commissioning mode).
        /// - `VP` is filtered only on the IDs the code carries.
        init?(txt: [String: String], matching code: SetupCode) {
            guard let dText = txt["D"], let d = UInt16(dText), d <= 0xFFF,
                  code.discriminator.matches(d) else { return nil }
            guard let cmText = txt["CM"], let cm = UInt8(cmText), cm != 0 else { return nil }

            let (vid, pid) = Self.parseVP(txt["VP"])
            if let wanted = code.vendorID, vid != wanted { return nil }
            if let wanted = code.productID, pid != wanted { return nil }

            self.discriminator = d
            self.commissioningMode = cm
            self.vendorID = vid
            self.productID = pid
        }

        /// `VP` is "vid" or "vid+pid", decimal. An unparseable part is nil.
        private static func parseVP(_ text: String?) -> (UInt16?, UInt16?) {
            guard let text else { return (nil, nil) }
            let parts = text.split(separator: "+", maxSplits: 1, omittingEmptySubsequences: false)
            let vid = parts.first.flatMap { UInt16($0) }
            let pid = parts.count > 1 ? UInt16(parts[1]) : nil
            return (vid, pid)
        }
    }

    init(instanceName: String, address: MatterAddress, advertisement: Advertisement, txtRecords: [String: String]) {
        self.instanceName = instanceName
        self.address = address
        self.discriminator = advertisement.discriminator
        self.vendorID = advertisement.vendorID
        self.productID = advertisement.productID
        self.commissioningMode = advertisement.commissioningMode
        self.mrp = MRPParameters(txtRecords: txtRecords)
        self.txtRecords = txtRecords
    }
}
