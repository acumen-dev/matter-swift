// MetadataClusterHandlerTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import MatterTypes
@testable import MatterDevice
@testable import MatterModel

// MARK: - Helpers

private let testEndpoint = EndpointID(rawValue: 5)
private let testClusterID = ClusterID.onOff

/// Populate the store with a handler's initial attributes.
private func populateStore(_ store: AttributeStore, handler: some ClusterHandler, endpoint: EndpointID) {
    for (attr, value) in handler.initialAttributes() {
        store.set(endpoint: endpoint, cluster: handler.clusterID, attribute: attr, value: value)
    }
}

// MARK: - Tests

@Suite("MetadataClusterHandler")
struct MetadataClusterHandlerTests {

    @Test("Read returns stored attribute value")
    func readReturnsStoredValue() {
        let handler = MetadataClusterHandler(
            clusterID: testClusterID,
            attributes: [
                (OnOffCluster.Attribute.onOff, .bool(false)),
            ]
        )

        let value = handler.getAttribute(OnOffCluster.Attribute.onOff)
        #expect(value == .bool(false))
    }

    @Test("Write updates attribute value via callback")
    func writeUpdatesValue() {
        let handler = MetadataClusterHandler(
            clusterID: testClusterID,
            attributes: [
                (OnOffCluster.Attribute.onOff, .bool(false)),
            ],
            onWrite: { _, _ in true }
        )

        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: testEndpoint)

        let result = handler.validateWrite(
            attributeID: OnOffCluster.Attribute.onOff,
            value: .bool(true)
        )
        #expect(result == .allowed)
    }

    @Test("Write callback rejection returns constraint error")
    func writeCallbackRejection() {
        let handler = MetadataClusterHandler(
            clusterID: testClusterID,
            attributes: [
                (OnOffCluster.Attribute.onOff, .bool(false)),
            ],
            onWrite: { _, _ in false }
        )

        let result = handler.validateWrite(
            attributeID: OnOffCluster.Attribute.onOff,
            value: .bool(true)
        )
        #expect(result == .rejected(status: 0x87))
    }

    @Test("Write without callback rejects as unsupported")
    func writeWithoutCallbackRejects() {
        let handler = MetadataClusterHandler(
            clusterID: testClusterID,
            attributes: [
                (OnOffCluster.Attribute.onOff, .bool(false)),
            ]
        )

        let result = handler.validateWrite(
            attributeID: OnOffCluster.Attribute.onOff,
            value: .bool(true)
        )
        #expect(result == .unsupportedWrite)
    }

    @Test("Command invocation delegates to callback")
    func commandInvocation() async throws {
        let handler = MetadataClusterHandler(
            clusterID: testClusterID,
            acceptedCommands: [OnOffCluster.Command.on],
            onCommand: { commandID, _ in
                if commandID == OnOffCluster.Command.on {
                    return .structure([
                        TLVElement.TLVField(tag: .contextSpecific(0), value: .unsignedInt(0))
                    ])
                }
                return nil
            }
        )

        let store = AttributeStore()
        let result = try handler.handleCommand(
            commandID: OnOffCluster.Command.on,
            fields: nil,
            store: store,
            endpointID: testEndpoint
        )

        #expect(result != nil)
    }

    @Test("Global attributes populated via initialAttributes")
    func globalAttributesPopulated() {
        let handler = MetadataClusterHandler(
            clusterID: testClusterID,
            attributes: [
                (OnOffCluster.Attribute.onOff, .bool(false)),
            ],
            clusterRevision: 4,
            featureMap: 0x01
        )

        // Verify clusterRevision and featureMap are set as nonisolated properties
        #expect(handler.clusterRevision == 4)
        #expect(handler.featureMap == 0x01)

        // Verify the EndpointManager auto-populates global attributes when
        // the handler is registered.
        let store = AttributeStore()
        let endpoints = EndpointManager(store: store)
        let config = EndpointConfig(
            endpointID: testEndpoint,
            deviceTypes: [(.onOffLight, 1)],
            clusterHandlers: [handler]
        )
        endpoints.addEndpoint(config)

        // ClusterRevision (0xFFFD) should be auto-populated
        let revision = store.get(
            endpoint: testEndpoint,
            cluster: testClusterID,
            attribute: .clusterRevision
        )
        #expect(revision == .unsignedInt(4))

        // FeatureMap (0xFFFC) should be auto-populated
        let features = store.get(
            endpoint: testEndpoint,
            cluster: testClusterID,
            attribute: .featureMap
        )
        #expect(features == .unsignedInt(0x01))

        // AttributeList (0xFFFB) should include our attribute + globals
        let attrList = store.get(
            endpoint: testEndpoint,
            cluster: testClusterID,
            attribute: .attributeList
        )
        #expect(attrList != nil)
    }

    @Test("updateAttribute stores new value")
    func updateAttributeWorks() {
        let handler = MetadataClusterHandler(
            clusterID: testClusterID,
            attributes: [
                (OnOffCluster.Attribute.onOff, .bool(false)),
            ]
        )

        handler.updateAttribute(OnOffCluster.Attribute.onOff, value: .bool(true))
        let value = handler.getAttribute(OnOffCluster.Attribute.onOff)
        #expect(value == .bool(true))
    }

    @Test("acceptedCommands and generatedCommands returned correctly")
    func commandListsReturned() {
        let handler = MetadataClusterHandler(
            clusterID: testClusterID,
            acceptedCommands: [OnOffCluster.Command.on, OnOffCluster.Command.off],
            generatedCommands: [CommandID(rawValue: 0x01)]
        )

        let accepted = handler.acceptedCommands()
        #expect(accepted.count == 2)
        #expect(accepted.contains(OnOffCluster.Command.on))
        #expect(accepted.contains(OnOffCluster.Command.off))

        let generated = handler.generatedCommands()
        #expect(generated.count == 1)
    }

    @Test("Spec metadata used for write type validation")
    func specMetadataValidatesWriteType() {
        // OnOff cluster has spec metadata — the onOff attribute is bool type
        let handler = MetadataClusterHandler(
            clusterID: ClusterID.onOff,
            attributes: [
                (OnOffCluster.Attribute.onOff, .bool(false)),
            ],
            onWrite: { _, _ in true }
        )

        // Writing a string to a bool attribute should fail type validation
        let result = handler.validateWrite(
            attributeID: OnOffCluster.Attribute.onOff,
            value: .utf8String("not a bool")
        )
        #expect(result == .constraintError)

        // Writing a bool should pass
        let validResult = handler.validateWrite(
            attributeID: OnOffCluster.Attribute.onOff,
            value: .bool(true)
        )
        #expect(validResult == .allowed)
    }

    @Test("addGenericEndpoint creates endpoint with infrastructure clusters")
    func addGenericEndpointWorks() {
        let bridge = MatterBridge()

        let endpoint = bridge.addGenericEndpoint(
            name: "Test Sensor",
            deviceTypeID: .temperatureSensor,
            clusters: [
                MatterBridge.ClusterConfig(
                    clusterID: .temperatureMeasurement,
                    attributes: [
                        (AttributeID(rawValue: 0x0000), .signedInt(2100)),
                        (AttributeID(rawValue: 0x0001), .signedInt(-2000)),
                        (AttributeID(rawValue: 0x0002), .signedInt(12000)),
                    ]
                )
            ]
        )

        // Verify the endpoint was created
        let epConfig = bridge.endpoints.endpoint(for: endpoint.endpointID)
        #expect(epConfig != nil)

        // Should have: temperatureMeasurement + groups + identify + bridgedDeviceBasicInfo + descriptor
        #expect(epConfig!.clusterHandlers.count == 5)

        // Verify the measured value attribute was stored
        let measuredValue = bridge.store.get(
            endpoint: endpoint.endpointID,
            cluster: .temperatureMeasurement,
            attribute: AttributeID(rawValue: 0x0000)
        )
        #expect(measuredValue == .signedInt(2100))
    }
}
