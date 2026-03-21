// ClusterValidatorTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
@testable import MatterDevice
@testable import MatterModel
import MatterTypes

@Suite("ClusterValidator Tests")
struct ClusterValidatorTests {

    // MARK: - Test Helpers

    /// A minimal test handler that can be configured with specific attributes and commands.
    struct TestHandler: ClusterHandler {
        let clusterID: ClusterID
        let featureMap: UInt32
        private let attrs: [(AttributeID, TLVElement)]
        private let cmds: [CommandID]

        init(
            clusterID: ClusterID,
            featureMap: UInt32 = 0,
            attributes: [(AttributeID, TLVElement)] = [],
            commands: [CommandID] = []
        ) {
            self.clusterID = clusterID
            self.featureMap = featureMap
            self.attrs = attributes
            self.cmds = commands
        }

        func initialAttributes() -> [(AttributeID, TLVElement)] { attrs }
        func acceptedCommands() -> [CommandID] { cmds }
    }

    // MARK: - Tests

    @Test("Mandatory attribute missing produces error")
    func mandatoryAttributeMissing() {
        // OnOff cluster requires attribute 0x0000 (OnOff) as mandatory
        let handler = TestHandler(
            clusterID: .onOff,
            attributes: []  // Missing mandatory OnOff attribute
        )
        let result = ClusterValidator.validate(handler: handler)
        #expect(!result.isValid)
        #expect(result.errors.contains { $0.contains("OnOff") && $0.contains("0x0000") })
    }

    @Test("All mandatory attributes present produces no error")
    func allMandatoryPresent() {
        // OnOff cluster without LT feature only requires onOff attribute
        let handler = TestHandler(
            clusterID: .onOff,
            attributes: [
                (OnOffCluster.Attribute.onOff, .bool(false)),
            ],
            commands: [
                OnOffCluster.Command.off,
                OnOffCluster.Command.on,
                OnOffCluster.Command.toggle,
            ]
        )
        let result = ClusterValidator.validate(handler: handler)
        #expect(result.isValid)
    }

    @Test("Feature-conditional attribute missing when feature enabled produces error")
    func featureConditionalMissing() {
        // OnOff with LT (Lighting, bit 0) feature requires GlobalSceneControl, OnTime, etc.
        let handler = TestHandler(
            clusterID: .onOff,
            featureMap: 1 << 0,  // LT feature
            attributes: [
                (OnOffCluster.Attribute.onOff, .bool(false)),
                // Missing: globalSceneControl, onTime, offWaitTime, startUpOnOff
            ]
        )
        let result = ClusterValidator.validate(handler: handler)
        #expect(!result.isValid)
        #expect(result.errors.contains { $0.contains("GlobalSceneControl") })
    }

    @Test("Feature-conditional attribute not required when feature disabled")
    func featureConditionalNotRequired() {
        // OnOff WITHOUT LT feature — GlobalSceneControl is not mandatory
        let handler = TestHandler(
            clusterID: .onOff,
            featureMap: 0,  // No features
            attributes: [
                (OnOffCluster.Attribute.onOff, .bool(false)),
            ],
            commands: [
                OnOffCluster.Command.off,
                OnOffCluster.Command.on,
                OnOffCluster.Command.toggle,
            ]
        )
        let result = ClusterValidator.validate(handler: handler)
        #expect(result.isValid)
    }

    @Test("Mandatory command missing produces error")
    func mandatoryCommandMissing() {
        // OnOff cluster requires Off command as mandatory
        let handler = TestHandler(
            clusterID: .onOff,
            attributes: [
                (OnOffCluster.Attribute.onOff, .bool(false)),
            ],
            commands: []  // Missing mandatory Off command
        )
        let result = ClusterValidator.validate(handler: handler)
        #expect(!result.isValid)
        #expect(result.errors.contains { $0.contains("Off") && $0.contains("0x0000") })
    }

    @Test("Unknown cluster ID returns valid (no validation)")
    func unknownCluster() {
        // Vendor-specific cluster — no spec metadata
        let handler = TestHandler(
            clusterID: ClusterID(rawValue: 0xFFFF1234),
            attributes: []
        )
        let result = ClusterValidator.validate(handler: handler)
        #expect(result.isValid)
        #expect(result.errors.isEmpty)
    }

    @Test("SpecConformance.isMandatory evaluates correctly")
    func specConformanceEvaluation() {
        #expect(SpecConformance.mandatory.isMandatory(featureMap: 0))
        #expect(!SpecConformance.optional.isMandatory(featureMap: 0))
        #expect(!SpecConformance.deprecated.isMandatory(featureMap: 0))
        #expect(!SpecConformance.disallowed.isMandatory(featureMap: 0))

        // mandatoryIf with feature bit 0 set
        let condBit0 = SpecConformance.mandatoryIf(.feature(1 << 0))
        #expect(condBit0.isMandatory(featureMap: 0b0001))
        #expect(!condBit0.isMandatory(featureMap: 0b0010))

        // mandatoryIf with NOT condition
        let condNotBit2 = SpecConformance.mandatoryIf(.not(.feature(1 << 2)))
        #expect(condNotBit2.isMandatory(featureMap: 0b0000))
        #expect(!condNotBit2.isMandatory(featureMap: 0b0100))
    }

    @Test("SpecCondition OR/AND evaluation")
    func specConditionLogic() {
        // OR: true if any is true
        let orCond = SpecCondition.or([.feature(1 << 0), .feature(1 << 1)])
        #expect(orCond.evaluate(featureMap: 0b01))
        #expect(orCond.evaluate(featureMap: 0b10))
        #expect(!orCond.evaluate(featureMap: 0b00))

        // AND: true if all are true
        let andCond = SpecCondition.and([.feature(1 << 0), .feature(1 << 1)])
        #expect(andCond.evaluate(featureMap: 0b11))
        #expect(!andCond.evaluate(featureMap: 0b01))
        #expect(!andCond.evaluate(featureMap: 0b10))
    }

    @Test("ClusterSpecRegistry returns spec for known clusters")
    func registryLookup() {
        let onOffSpec = ClusterSpecRegistry.spec(for: .onOff)
        #expect(onOffSpec != nil)
        #expect(onOffSpec?.clusterID == .onOff)
        #expect(onOffSpec?.revision == 6)
        #expect(onOffSpec?.attributes.isEmpty == false)

        let unknownSpec = ClusterSpecRegistry.spec(for: ClusterID(rawValue: 0xFFFF9999))
        #expect(unknownSpec == nil)
    }
}
