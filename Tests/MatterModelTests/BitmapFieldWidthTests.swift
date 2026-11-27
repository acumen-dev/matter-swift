// BitmapFieldWidthTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
@testable import MatterModel

/// acumen-dev/matter-swift#50 — the Matter XML declares multi-bit bitfields as an
/// inclusive `from`/`to` range (`<bitfield name="Global" from="1" to="0"/>`), while
/// the generator only read `bit`. Every ranged field therefore defaulted to bit 0,
/// so all of a bitmap's fields collapsed onto the same single-bit option.
@Suite("Bitmap field widths")
struct BitmapFieldWidthTests {

    // MARK: - WindowCovering.OperationalStatusBitmap

    /// Spec: global (bits 0–1), lift (2–3), tilt (4–5), each 2 bits.
    @Test("OperationalStatus fields are two-bit masks at their declared offsets")
    func operationalStatusFields() {
        let bitmap = WindowCoveringCluster.OperationalStatusBitmap.self
        #expect(bitmap.global.rawValue == 0b00_0011, "global is bits 0–1, got \(bitmap.global.rawValue)")
        #expect(bitmap.lift.rawValue == 0b00_1100, "lift is bits 2–3, got \(bitmap.lift.rawValue)")
        #expect(bitmap.tilt.rawValue == 0b11_0000, "tilt is bits 4–5, got \(bitmap.tilt.rawValue)")
    }

    /// The three masks must be distinct and disjoint; the bug made them equal.
    @Test("OperationalStatus masks are distinct")
    func operationalStatusMasksAreDistinct() {
        let bitmap = WindowCoveringCluster.OperationalStatusBitmap.self
        let masks = [bitmap.global.rawValue, bitmap.lift.rawValue, bitmap.tilt.rawValue]
        #expect(Set(masks).count == 3, "collapsed to \(masks)")
        for (index, first) in masks.enumerated() {
            for second in masks[(index + 1)...] {
                #expect(first & second == 0, "\(first) overlaps \(second)")
            }
        }
    }

    // MARK: - Thermostat.HVACSystemTypeBitmap

    /// Spec: coolingStage (bits 0–1), heatingStage (2–3), then single bits 4 and 5.
    @Test("HVACSystemType stages are two-bit masks and single bits stay single-bit")
    func hvacSystemTypeFields() {
        let bitmap = ThermostatCluster.HVACSystemTypeBitmap.self
        #expect(bitmap.coolingStage.rawValue == 0b00_0011, "coolingStage is bits 0–1, got \(bitmap.coolingStage.rawValue)")
        #expect(bitmap.heatingStage.rawValue == 0b00_1100, "heatingStage is bits 2–3, got \(bitmap.heatingStage.rawValue)")
        #expect(bitmap.heatingIsHeatPump.rawValue == 0b01_0000, "heatingIsHeatPump is bit 4")
        #expect(bitmap.heatingUsesFuel.rawValue == 0b10_0000, "heatingUsesFuel is bit 5")
    }
}
