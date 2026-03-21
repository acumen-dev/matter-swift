// IdentifyHandlerTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import MatterTypes
import MatterModel
@testable import MatterDevice

@Suite("IdentifyHandler")
struct IdentifyHandlerTests {

    let endpoint = EndpointID(rawValue: 1)

    private func makeHandler() -> (IdentifyHandler, AttributeStore) {
        let handler = IdentifyHandler()
        let store = AttributeStore()
        for (attr, value) in handler.initialAttributes() {
            store.set(endpoint: endpoint, cluster: handler.clusterID, attribute: attr, value: value)
        }
        return (handler, store)
    }

    // MARK: - Initial Attributes

    @Test("initialAttributes has identifyTime = 0")
    func initialIdentifyTime() {
        let handler = IdentifyHandler()
        let attrs = Dictionary(uniqueKeysWithValues: handler.initialAttributes())
        #expect(attrs[IdentifyCluster.Attribute.identifyTime] == .unsignedInt(0))
    }

    @Test("initialAttributes has identifyType = 2 (VisibleIndicator)")
    func initialIdentifyType() {
        let handler = IdentifyHandler()
        let attrs = Dictionary(uniqueKeysWithValues: handler.initialAttributes())
        #expect(attrs[IdentifyCluster.Attribute.identifyType] == .unsignedInt(2))
    }

    // MARK: - Identify Command

    @Test("Identify command sets identifyTime")
    func identifyCommandSetsTime() throws {
        let (handler, store) = makeHandler()

        let fields = TLVElement.structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(15))
        ])
        let result = try handler.handleCommand(
            commandID: IdentifyCluster.Command.identify,
            fields: fields,
            store: store,
            endpointID: endpoint
        )
        #expect(result == nil)
        let stored = store.get(endpoint: endpoint, cluster: handler.clusterID, attribute: IdentifyCluster.Attribute.identifyTime)
        #expect(stored == .unsignedInt(15))
    }

    @Test("Identify command with nil fields sets identifyTime to 0")
    func identifyCommandNilFields() throws {
        let (handler, store) = makeHandler()
        // First set to non-zero
        store.set(endpoint: endpoint, cluster: handler.clusterID, attribute: IdentifyCluster.Attribute.identifyTime, value: .unsignedInt(30))

        _ = try handler.handleCommand(
            commandID: IdentifyCluster.Command.identify,
            fields: nil,
            store: store,
            endpointID: endpoint
        )
        let stored = store.get(endpoint: endpoint, cluster: handler.clusterID, attribute: IdentifyCluster.Attribute.identifyTime)
        #expect(stored == .unsignedInt(0))
    }

    // MARK: - Write Validation

    @Test("identifyTime is writable with unsigned int")
    func identifyTimeIsWritable() {
        let handler = IdentifyHandler()
        let result = handler.validateWrite(
            attributeID: IdentifyCluster.Attribute.identifyTime,
            value: .unsignedInt(60)
        )
        #expect(result == .allowed)
    }

    @Test("identifyTime write rejected with bool value")
    func identifyTimeWriteRejectedWithBool() {
        let handler = IdentifyHandler()
        let result = handler.validateWrite(
            attributeID: IdentifyCluster.Attribute.identifyTime,
            value: .bool(true)
        )
        #expect(result != .allowed)
    }

    @Test("identifyType is not writable")
    func identifyTypeIsNotWritable() {
        let handler = IdentifyHandler()
        let result = handler.validateWrite(
            attributeID: IdentifyCluster.Attribute.identifyType,
            value: .unsignedInt(1)
        )
        #expect(result == .unsupportedWrite)
    }

    @Test("unknown attribute is not writable")
    func unknownAttributeNotWritable() {
        let handler = IdentifyHandler()
        let result = handler.validateWrite(
            attributeID: AttributeID(rawValue: 0x9999),
            value: .unsignedInt(0)
        )
        #expect(result == .unsupportedWrite)
    }

    // MARK: - Cluster ID

    @Test("clusterID is 0x0003")
    func clusterID() {
        let handler = IdentifyHandler()
        #expect(handler.clusterID == ClusterID(rawValue: 0x0003))
        #expect(handler.clusterID == ClusterID.identify)
    }
}
