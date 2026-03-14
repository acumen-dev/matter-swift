// BindingHandlerTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import MatterTypes
import MatterModel
@testable import MatterDevice

@Suite("BindingHandler")
struct BindingHandlerTests {

    let endpoint = EndpointID(rawValue: 1)

    private func makeHandler() -> (BindingHandler, AttributeStore) {
        let handler = BindingHandler()
        let store = AttributeStore()
        for (attr, value) in handler.initialAttributes() {
            store.set(endpoint: endpoint, cluster: handler.clusterID, attribute: attr, value: value)
        }
        return (handler, store)
    }

    // MARK: - Initial Attributes

    @Test("initialAttributes has empty binding list")
    func initialBindingList() {
        let handler = BindingHandler()
        let attrs = Dictionary(uniqueKeysWithValues: handler.initialAttributes())
        #expect(attrs[BindingCluster.Attribute.binding] == .array([]))
    }

    // MARK: - Write Validation

    @Test("binding list is writable with array value")
    func bindingListIsWritable() {
        let handler = BindingHandler()
        let result = handler.validateWrite(
            attributeID: BindingCluster.Attribute.binding,
            value: .array([])
        )
        #expect(result == .allowed)
    }

    @Test("binding list write rejected with non-array value")
    func bindingListWriteRejectedWithNonArray() {
        let handler = BindingHandler()
        let result = handler.validateWrite(
            attributeID: BindingCluster.Attribute.binding,
            value: .unsignedInt(0)
        )
        #expect(result != .allowed)
    }

    @Test("unknown attribute is not writable")
    func unknownAttributeNotWritable() {
        let handler = BindingHandler()
        let result = handler.validateWrite(
            attributeID: AttributeID(rawValue: 0x9999),
            value: .array([])
        )
        #expect(result == .unsupportedWrite)
    }

    // MARK: - Fabric Scoping

    @Test("binding list is fabric-scoped")
    func bindingListIsFabricScoped() {
        let handler = BindingHandler()
        #expect(handler.isFabricScoped(attributeID: BindingCluster.Attribute.binding) == true)
    }

    @Test("unknown attribute is not fabric-scoped")
    func unknownAttributeNotFabricScoped() {
        let handler = BindingHandler()
        #expect(handler.isFabricScoped(attributeID: AttributeID(rawValue: 0x9999)) == false)
    }

    // MARK: - Fabric Filtering

    @Test("fabric filtering by tag 0xFE keeps matching entries")
    func fabricFilteringKeepsMatching() {
        let handler = BindingHandler()

        let fabric1Entry = TLVElement.structure([
            TLVElement.TLVField(tag: .contextSpecific(0x00), value: .unsignedInt(1)),   // node
            TLVElement.TLVField(tag: .contextSpecific(0xFE), value: .unsignedInt(1)),   // fabricIndex = 1
        ])
        let fabric2Entry = TLVElement.structure([
            TLVElement.TLVField(tag: .contextSpecific(0x00), value: .unsignedInt(2)),   // node
            TLVElement.TLVField(tag: .contextSpecific(0xFE), value: .unsignedInt(2)),   // fabricIndex = 2
        ])

        let value = TLVElement.array([fabric1Entry, fabric2Entry])
        let filtered = handler.filterFabricScopedAttribute(
            attributeID: BindingCluster.Attribute.binding,
            value: value,
            fabricIndex: FabricIndex(rawValue: 1)
        )

        guard case .array(let elements) = filtered else {
            Issue.record("Expected array result")
            return
        }
        #expect(elements.count == 1)
        #expect(elements[0] == fabric1Entry)
    }

    @Test("fabric filtering removes non-matching entries")
    func fabricFilteringRemovesNonMatching() {
        let handler = BindingHandler()

        let fabric2Entry = TLVElement.structure([
            TLVElement.TLVField(tag: .contextSpecific(0xFE), value: .unsignedInt(2)),
        ])

        let value = TLVElement.array([fabric2Entry])
        let filtered = handler.filterFabricScopedAttribute(
            attributeID: BindingCluster.Attribute.binding,
            value: value,
            fabricIndex: FabricIndex(rawValue: 1)
        )

        guard case .array(let elements) = filtered else {
            Issue.record("Expected array result")
            return
        }
        #expect(elements.isEmpty)
    }

    @Test("fabric filtering on non-scoped attribute returns unchanged value")
    func fabricFilteringNonScopedAttribute() {
        let handler = BindingHandler()
        let value = TLVElement.unsignedInt(42)
        let result = handler.filterFabricScopedAttribute(
            attributeID: AttributeID(rawValue: 0x9999),
            value: value,
            fabricIndex: FabricIndex(rawValue: 1)
        )
        #expect(result == value)
    }

    // MARK: - Cluster ID

    @Test("clusterID is 0x001E")
    func clusterID() {
        let handler = BindingHandler()
        #expect(handler.clusterID == ClusterID(rawValue: 0x001E))
        #expect(handler.clusterID == ClusterID.binding)
    }
}
