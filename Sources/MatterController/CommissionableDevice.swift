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
        /// - `VP` is filtered only on the IDs the code carries, and only where
        ///   advertised: an absent `VP`, an absent `+pid` part, or an empty
        ///   part (`VP=`, `65521+`, `+32768`) is unknown and passes
        ///   (chip-tool's `SetUpCodePairer`); an advertised ID that differs,
        ///   or a non-empty part that does not parse, rejects.
        init?(txt: [String: String], matching code: SetupCode) {
            guard let dText = txt["D"], let d = UInt16(dText), d <= 0xFFF,
                  code.discriminator.matches(d) else { return nil }
            guard let cmText = txt["CM"], let cm = UInt8(cmText), cm != 0 else { return nil }

            let (vidText, pidText) = Self.splitVP(txt["VP"])
            let vid = vidText.flatMap { UInt16($0) }
            let pid = pidText.flatMap { UInt16($0) }
            if let wanted = code.vendorID, vidText != nil, vid != wanted { return nil }
            if let wanted = code.productID, pidText != nil, pid != wanted { return nil }

            self.discriminator = d
            self.commissioningMode = cm
            self.vendorID = vid
            self.productID = pid
        }

        /// `VP` is "vid" or "vid+pid", decimal. A part that is absent or
        /// empty is nil (unknown).
        private static func splitVP(_ text: String?) -> (Substring?, Substring?) {
            guard let text else { return (nil, nil) }
            let parts = text.split(separator: "+", maxSplits: 1, omittingEmptySubsequences: false)
            let present = { (part: Substring?) in part.flatMap { $0.isEmpty ? nil : $0 } }
            return (present(parts.first), present(parts.count > 1 ? parts[1] : nil))
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
