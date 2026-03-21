// TLVCodableTests.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Testing
@testable import MatterModel
import MatterTypes

@Suite("TLVCodable Round-Trip Tests")
struct TLVCodableTests {

    // MARK: - OnOff Command Structs

    @Test("OffWithEffectRequest round-trip encoding")
    func offWithEffectRoundTrip() throws {
        let request = OnOffCluster.OffWithEffectRequest(
            effectIdentifier: 1,
            effectVariant: 0
        )
        let element = request.toTLVElement()

        // Verify TLV structure
        #expect(element[contextTag: 0]?.uintValue == 1)
        #expect(element[contextTag: 1]?.uintValue == 0)

        // Round-trip
        let decoded = try OnOffCluster.OffWithEffectRequest.fromTLVElement(element)
        #expect(decoded == request)
    }

    @Test("OnWithTimedOffRequest round-trip encoding")
    func onWithTimedOffRoundTrip() throws {
        let request = OnOffCluster.OnWithTimedOffRequest(
            onOffControl: 1,
            onTime: 300,
            offWaitTime: 600
        )
        let element = request.toTLVElement()

        let decoded = try OnOffCluster.OnWithTimedOffRequest.fromTLVElement(element)
        #expect(decoded == request)
        #expect(decoded.onOffControl == 1)
        #expect(decoded.onTime == 300)
        #expect(decoded.offWaitTime == 600)
    }

    // MARK: - LevelControl Command Structs

    @Test("MoveToLevelRequest round-trip with nullable field")
    func moveToLevelRoundTrip() throws {
        // With non-null transition time
        let request1 = LevelControlCluster.MoveToLevelRequest(
            level: 128,
            transitionTime: 100,
            optionsMask: 0,
            optionsOverride: 0
        )
        let element1 = request1.toTLVElement()
        let decoded1 = try LevelControlCluster.MoveToLevelRequest.fromTLVElement(element1)
        #expect(decoded1 == request1)
        #expect(decoded1.transitionTime == 100)

        // With null transition time
        let request2 = LevelControlCluster.MoveToLevelRequest(
            level: 255,
            transitionTime: nil,
            optionsMask: 1,
            optionsOverride: 1
        )
        let element2 = request2.toTLVElement()
        let decoded2 = try LevelControlCluster.MoveToLevelRequest.fromTLVElement(element2)
        #expect(decoded2 == request2)
        #expect(decoded2.transitionTime == nil)
    }

    // MARK: - Decoding from List (matter.js compatibility)

    @Test("fromTLVElement accepts .list as well as .structure")
    func decodesFromList() throws {
        let listElement = TLVElement.list([
            TLVElement.TLVField(tag: .contextSpecific(0), value: .unsignedInt(0)),
            TLVElement.TLVField(tag: .contextSpecific(1), value: .unsignedInt(1)),
        ])
        let decoded = try OnOffCluster.OffWithEffectRequest.fromTLVElement(listElement)
        #expect(decoded.effectIdentifier == 0)
        #expect(decoded.effectVariant == 1)
    }

    @Test("fromTLVElement rejects non-structure types")
    func rejectsNonStructure() {
        #expect(throws: TLVDecodingError.self) {
            _ = try OnOffCluster.OffWithEffectRequest.fromTLVElement(.unsignedInt(42))
        }
    }

    @Test("fromTLVElement throws for missing required field")
    func throwsForMissingField() {
        let partial = TLVElement.structure([
            TLVElement.TLVField(tag: .contextSpecific(0), value: .unsignedInt(1)),
            // Missing tag 1 (effectVariant)
        ])
        #expect(throws: TLVDecodingError.self) {
            _ = try OnOffCluster.OffWithEffectRequest.fromTLVElement(partial)
        }
    }

    @Test("fromTLVElement ignores extra unknown fields (forward compatibility)")
    func ignoresExtraFields() throws {
        let extended = TLVElement.structure([
            TLVElement.TLVField(tag: .contextSpecific(0), value: .unsignedInt(1)),
            TLVElement.TLVField(tag: .contextSpecific(1), value: .unsignedInt(0)),
            TLVElement.TLVField(tag: .contextSpecific(99), value: .utf8String("future field")),
        ])
        let decoded = try OnOffCluster.OffWithEffectRequest.fromTLVElement(extended)
        #expect(decoded.effectIdentifier == 1)
        #expect(decoded.effectVariant == 0)
    }
}
