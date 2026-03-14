// NetworkCommissioningHandlerTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
@testable import MatterDevice
@testable import MatterModel

private let ep0 = EndpointID(rawValue: 0)

private func populateStore(_ store: AttributeStore, handler: some ClusterHandler, endpoint: EndpointID) {
    for (attr, value) in handler.initialAttributes() {
        store.set(endpoint: endpoint, cluster: handler.clusterID, attribute: attr, value: value)
    }
}

@Suite("NetworkCommissioningHandler")
struct NetworkCommissioningHandlerTests {

    @Test("initial attributes include maxNetworks = 1")
    func maxNetworks() {
        let handler = NetworkCommissioningHandler()
        let attrs = handler.initialAttributes()
        let attr = attrs.first { $0.0 == NetworkCommissioningCluster.Attribute.maxNetworks }
        #expect(attr?.1 == .unsignedInt(1))
    }

    @Test("networks array contains single entry with interface name")
    func networksArray() throws {
        let handler = NetworkCommissioningHandler(networkName: "en0", connected: true)
        let attrs = handler.initialAttributes()
        let attr = attrs.first { $0.0 == NetworkCommissioningCluster.Attribute.networks }
        guard case .array(let entries) = attr?.1 else {
            Issue.record("networks attribute is not an array")
            return
        }
        #expect(entries.count == 1)
    }

    @Test("feature map indicates Ethernet feature (0x04)")
    func featureMap() {
        let handler = NetworkCommissioningHandler()
        let attrs = handler.initialAttributes()
        let attr = attrs.first { $0.0 == NetworkCommissioningCluster.Attribute.featureMap }
        #expect(attr?.1 == .unsignedInt(4))
    }

    @Test("interface enabled defaults to true")
    func interfaceEnabled() {
        let handler = NetworkCommissioningHandler()
        let attrs = handler.initialAttributes()
        let attr = attrs.first { $0.0 == NetworkCommissioningCluster.Attribute.interfaceEnabled }
        #expect(attr?.1 == .bool(true))
    }

    @Test("nullable attributes default to null")
    func nullableAttributes() {
        let handler = NetworkCommissioningHandler()
        let attrs = handler.initialAttributes()
        let status = attrs.first { $0.0 == NetworkCommissioningCluster.Attribute.lastNetworkingStatus }
        let id = attrs.first { $0.0 == NetworkCommissioningCluster.Attribute.lastNetworkID }
        let err = attrs.first { $0.0 == NetworkCommissioningCluster.Attribute.lastConnectErrorValue }
        #expect(status?.1 == .null)
        #expect(id?.1 == .null)
        #expect(err?.1 == .null)
    }

    @Test("cluster revision is present")
    func clusterRevision() {
        let handler = NetworkCommissioningHandler()
        let attrs = handler.initialAttributes()
        let attr = attrs.first { $0.0 == NetworkCommissioningCluster.Attribute.clusterRevision }
        #expect(attr?.1 == .unsignedInt(1))
    }

    @Test("interface enabled attribute is writable with bool value")
    func interfaceEnabledWritable() {
        let handler = NetworkCommissioningHandler()
        #expect(handler.validateWrite(
            attributeID: NetworkCommissioningCluster.Attribute.interfaceEnabled,
            value: .bool(false)
        ) == .allowed)
    }

    @Test("maxNetworks attribute is not writable")
    func maxNetworksNotWritable() {
        let handler = NetworkCommissioningHandler()
        #expect(handler.validateWrite(
            attributeID: NetworkCommissioningCluster.Attribute.maxNetworks,
            value: .unsignedInt(2)
        ) == .unsupportedWrite)
    }

    @Test("network entry contains networkID matching interface name")
    func networkEntryNetworkID() throws {
        let handler = NetworkCommissioningHandler(networkName: "eth0", connected: false)
        let attrs = handler.initialAttributes()
        let attr = attrs.first { $0.0 == NetworkCommissioningCluster.Attribute.networks }
        guard case .array(let entries) = attr?.1,
              let first = entries.first else {
            Issue.record("networks attribute is not an array or is empty")
            return
        }
        let networkInfo = try NetworkCommissioningCluster.NetworkInfoStruct.fromTLVElement(first)
        #expect(networkInfo.networkID == Data("eth0".utf8))
        #expect(networkInfo.connected == false)
    }

    @Test("interface enabled rejects non-bool write")
    func interfaceEnabledRejectsNonBool() {
        let handler = NetworkCommissioningHandler()
        #expect(handler.validateWrite(
            attributeID: NetworkCommissioningCluster.Attribute.interfaceEnabled,
            value: .unsignedInt(1)
        ) == .constraintError)
    }

    @Test("NetworkInfoStruct round-trips through TLV")
    func networkInfoTLVRoundTrip() throws {
        let original = NetworkCommissioningCluster.NetworkInfoStruct(
            networkID: Data("en0".utf8),
            connected: true
        )
        let decoded = try NetworkCommissioningCluster.NetworkInfoStruct.fromTLVElement(original.toTLVElement())
        #expect(decoded == original)
    }
}
