// FixedLabelHandlerTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import MatterTypes
import MatterModel
@testable import MatterDevice

@Suite("FixedLabelHandler")
struct FixedLabelHandlerTests {

    // MARK: - Initial Attributes

    @Test("empty init produces empty labelList array")
    func emptyInitProducesEmptyArray() {
        let handler = FixedLabelHandler()
        let attrs = Dictionary(uniqueKeysWithValues: handler.initialAttributes())
        #expect(attrs[FixedLabelCluster.Attribute.labelList] == .array([]))
    }

    @Test("initialAttributes returns correct TLV structures for labels")
    func initialAttributesWithLabels() {
        let handler = FixedLabelHandler(labels: [
            (label: "Room", value: "Kitchen"),
            (label: "Zone", value: "A"),
        ])
        let attrs = Dictionary(uniqueKeysWithValues: handler.initialAttributes())

        guard let labelList = attrs[FixedLabelCluster.Attribute.labelList],
              case .array(let elements) = labelList else {
            Issue.record("labelList missing or wrong type")
            return
        }

        #expect(elements.count == 2)

        // First entry: Room = Kitchen
        guard case .structure(let firstFields) = elements[0] else {
            Issue.record("First element is not a structure")
            return
        }
        let firstLabel = firstFields.first(where: { $0.tag == .contextSpecific(0) })?.value.stringValue
        let firstValue = firstFields.first(where: { $0.tag == .contextSpecific(1) })?.value.stringValue
        #expect(firstLabel == "Room")
        #expect(firstValue == "Kitchen")

        // Second entry: Zone = A
        guard case .structure(let secondFields) = elements[1] else {
            Issue.record("Second element is not a structure")
            return
        }
        let secondLabel = secondFields.first(where: { $0.tag == .contextSpecific(0) })?.value.stringValue
        let secondValue = secondFields.first(where: { $0.tag == .contextSpecific(1) })?.value.stringValue
        #expect(secondLabel == "Zone")
        #expect(secondValue == "A")
    }

    @Test("single label produces single structure")
    func singleLabel() {
        let handler = FixedLabelHandler(labels: [
            (label: "Location", value: "Garage"),
        ])
        let attrs = Dictionary(uniqueKeysWithValues: handler.initialAttributes())

        guard let labelList = attrs[FixedLabelCluster.Attribute.labelList],
              case .array(let elements) = labelList else {
            Issue.record("labelList missing or wrong type")
            return
        }
        #expect(elements.count == 1)
    }

    // MARK: - Write Validation

    @Test("labels are not writable — labelList rejected")
    func labelListNotWritable() {
        let handler = FixedLabelHandler()
        let result = handler.validateWrite(
            attributeID: FixedLabelCluster.Attribute.labelList,
            value: .array([])
        )
        #expect(result == .unsupportedWrite)
    }

    @Test("unknown attribute also rejected")
    func unknownAttributeRejected() {
        let handler = FixedLabelHandler()
        let result = handler.validateWrite(
            attributeID: AttributeID(rawValue: 0x9999),
            value: .unsignedInt(0)
        )
        #expect(result == .unsupportedWrite)
    }

    // MARK: - Fabric Scoping

    @Test("labelList is not fabric-scoped")
    func labelListNotFabricScoped() {
        let handler = FixedLabelHandler()
        #expect(handler.isFabricScoped(attributeID: FixedLabelCluster.Attribute.labelList) == false)
    }

    // MARK: - Cluster ID

    @Test("clusterID is 0x0040")
    func clusterID() {
        let handler = FixedLabelHandler()
        #expect(handler.clusterID == ClusterID(rawValue: 0x0040))
        #expect(handler.clusterID == ClusterID.fixedLabel)
    }
}
