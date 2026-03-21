// ClusterSpecTests.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Testing
@testable import MatterModel
import MatterTypes

@Suite("ClusterSpec Tests")
struct ClusterSpecTests {

    @Test("SpecConformance mandatory evaluates to mandatory regardless of features")
    func mandatoryAlways() {
        #expect(SpecConformance.mandatory.isMandatory(featureMap: 0))
        #expect(SpecConformance.mandatory.isMandatory(featureMap: 0xFFFFFFFF))
    }

    @Test("SpecConformance optional never evaluates to mandatory")
    func optionalNever() {
        #expect(!SpecConformance.optional.isMandatory(featureMap: 0))
        #expect(!SpecConformance.optional.isMandatory(featureMap: 0xFFFFFFFF))
    }

    @Test("SpecCondition feature bit mask evaluation")
    func featureBitMask() {
        let bit0 = SpecCondition.feature(1 << 0)
        #expect(bit0.evaluate(featureMap: 0b0001))
        #expect(!bit0.evaluate(featureMap: 0b0010))
        #expect(bit0.evaluate(featureMap: 0b1111))

        let bit3 = SpecCondition.feature(1 << 3)
        #expect(!bit3.evaluate(featureMap: 0b0100))
        #expect(bit3.evaluate(featureMap: 0b1000))
    }

    @Test("SpecCondition NOT inverts correctly")
    func notCondition() {
        let notBit0 = SpecCondition.not(.feature(1 << 0))
        #expect(!notBit0.evaluate(featureMap: 0b0001))
        #expect(notBit0.evaluate(featureMap: 0b0000))
        #expect(notBit0.evaluate(featureMap: 0b1110))
    }

    @Test("SpecCondition OR any-match semantics")
    func orCondition() {
        let cond = SpecCondition.or([.feature(1 << 0), .feature(1 << 2)])
        #expect(cond.evaluate(featureMap: 0b001))  // bit 0
        #expect(cond.evaluate(featureMap: 0b100))  // bit 2
        #expect(cond.evaluate(featureMap: 0b101))  // both
        #expect(!cond.evaluate(featureMap: 0b010)) // neither
    }

    @Test("SpecCondition AND all-match semantics")
    func andCondition() {
        let cond = SpecCondition.and([.feature(1 << 0), .feature(1 << 2)])
        #expect(!cond.evaluate(featureMap: 0b001)) // only bit 0
        #expect(!cond.evaluate(featureMap: 0b100)) // only bit 2
        #expect(cond.evaluate(featureMap: 0b101))  // both
        #expect(!cond.evaluate(featureMap: 0b010)) // neither
    }

    @Test("Generated OnOff spec has correct structure")
    func onOffSpecStructure() {
        let spec = OnOffCluster.spec
        #expect(spec.clusterID == ClusterID(rawValue: 0x0006))
        #expect(spec.revision == 6)

        // OnOff attribute is mandatory
        let onOffAttr = spec.attributes.first { $0.id == AttributeID(rawValue: 0x0000) }
        #expect(onOffAttr != nil)
        #expect(onOffAttr?.name == "OnOff")
        #expect(onOffAttr?.conformance.isMandatory(featureMap: 0) == true)

        // GlobalSceneControl is mandatoryIf(LT, bit 0)
        let gscAttr = spec.attributes.first { $0.id == AttributeID(rawValue: 0x4000) }
        #expect(gscAttr != nil)
        #expect(gscAttr?.conformance.isMandatory(featureMap: 0) == false)
        #expect(gscAttr?.conformance.isMandatory(featureMap: 1 << 0) == true)

        // Off command is mandatory
        let offCmd = spec.commands.first { $0.id == CommandID(rawValue: 0x0000) }
        #expect(offCmd != nil)
        #expect(offCmd?.conformance.isMandatory(featureMap: 0) == true)
    }

    // MARK: - MatterAttributeType Tests

    @Test("MatterAttributeType.isCompatible — bool matches only bool TLV")
    func boolTypeCompatibility() {
        #expect(MatterAttributeType.bool.isCompatible(with: .bool(true)))
        #expect(MatterAttributeType.bool.isCompatible(with: .bool(false)))
        #expect(!MatterAttributeType.bool.isCompatible(with: .unsignedInt(1)))
        #expect(!MatterAttributeType.bool.isCompatible(with: .signedInt(0)))
        #expect(!MatterAttributeType.bool.isCompatible(with: .utf8String("x")))
    }

    @Test("MatterAttributeType.isCompatible — all unsigned widths accept unsignedInt")
    func unsignedIntCompatibility() {
        let unsigned: [MatterAttributeType] = [.uint8, .uint16, .uint24, .uint32, .uint64]
        for t in unsigned {
            #expect(t.isCompatible(with: .unsignedInt(0)))
            #expect(t.isCompatible(with: .unsignedInt(0xFFFF)))
            #expect(!t.isCompatible(with: .signedInt(-1)))
            #expect(!t.isCompatible(with: .bool(false)))
        }
    }

    @Test("MatterAttributeType.isCompatible — all signed widths accept signedInt")
    func signedIntCompatibility() {
        let signed: [MatterAttributeType] = [.int8, .int16, .int32, .int64]
        for t in signed {
            #expect(t.isCompatible(with: .signedInt(-1)))
            #expect(t.isCompatible(with: .signedInt(100)))
            #expect(!t.isCompatible(with: .unsignedInt(1)))
            #expect(!t.isCompatible(with: .bool(true)))
        }
    }

    @Test("MatterAttributeType.isCompatible — string, octstr, single, double, structure, list")
    func otherTypeCompatibility() {
        #expect(MatterAttributeType.string.isCompatible(with: .utf8String("hello")))
        #expect(!MatterAttributeType.string.isCompatible(with: .octetString(Data())))

        #expect(MatterAttributeType.octstr.isCompatible(with: .octetString(Data([0x01]))))
        #expect(!MatterAttributeType.octstr.isCompatible(with: .utf8String("x")))

        #expect(MatterAttributeType.single.isCompatible(with: .float(1.0)))
        #expect(!MatterAttributeType.single.isCompatible(with: .double(1.0)))

        #expect(MatterAttributeType.double.isCompatible(with: .double(1.0)))
        #expect(!MatterAttributeType.double.isCompatible(with: .float(1.0)))

        #expect(MatterAttributeType.structure.isCompatible(with: .structure([])))
        #expect(!MatterAttributeType.structure.isCompatible(with: .array([])))

        #expect(MatterAttributeType.list.isCompatible(with: .array([])))
        #expect(!MatterAttributeType.list.isCompatible(with: .structure([])))
    }

    @Test("MatterAttributeType.unknown is compatible with any TLV element")
    func unknownTypeAlwaysCompatible() {
        #expect(MatterAttributeType.unknown.isCompatible(with: .bool(true)))
        #expect(MatterAttributeType.unknown.isCompatible(with: .unsignedInt(99)))
        #expect(MatterAttributeType.unknown.isCompatible(with: .utf8String("x")))
        #expect(MatterAttributeType.unknown.isCompatible(with: .null))
    }

    @Test("Generated OnOff spec carries type and nullability metadata")
    func onOffSpecTypeMetadata() {
        let spec = OnOffCluster.spec
        let onOffAttr = spec.attributes.first { $0.id == AttributeID(rawValue: 0x0000) }
        #expect(onOffAttr?.type == .bool)
        #expect(onOffAttr?.isNullable == false)

        // StartUpOnOff is nullable and maps to uint8 (StartUpOnOffEnum with values 0-2)
        let startUpOnOff = spec.attributes.first { $0.id == AttributeID(rawValue: 0x4003) }
        #expect(startUpOnOff?.type == .uint8)
        #expect(startUpOnOff?.isNullable == true)

        // OnTime is uint16, non-nullable
        let onTime = spec.attributes.first { $0.id == AttributeID(rawValue: 0x4001) }
        #expect(onTime?.type == .uint16)
        #expect(onTime?.isNullable == false)
    }

    @Test("Generated BasicInformation spec is available via registry")
    func basicInfoViaRegistry() {
        let spec = ClusterSpecRegistry.spec(for: .basicInformation)
        #expect(spec != nil)
        #expect(spec?.clusterID == ClusterID(rawValue: 0x0028))

        // VendorName is mandatory
        let vendorName = spec?.attributes.first { $0.name == "VendorName" }
        #expect(vendorName != nil)
        #expect(vendorName?.conformance.isMandatory(featureMap: 0) == true)

        // ManufacturingDate is optional
        let mfgDate = spec?.attributes.first { $0.name == "ManufacturingDate" }
        #expect(mfgDate != nil)
        #expect(mfgDate?.conformance.isMandatory(featureMap: 0) == false)
    }
}
