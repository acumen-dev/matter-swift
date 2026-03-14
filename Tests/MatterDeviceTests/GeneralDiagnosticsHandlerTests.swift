// GeneralDiagnosticsHandlerTests.swift
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

@Suite("GeneralDiagnosticsHandler")
struct GeneralDiagnosticsHandlerTests {

    @Test("initial attributes include rebootCount = 0")
    func rebootCount() {
        let handler = GeneralDiagnosticsHandler()
        let attrs = handler.initialAttributes()
        let attr = attrs.first { $0.0 == GeneralDiagnosticsCluster.Attribute.rebootCount }
        #expect(attr?.1 == .unsignedInt(0))
    }

    @Test("initial attributes include empty fault lists")
    func emptyFaultLists() {
        let handler = GeneralDiagnosticsHandler()
        let attrs = handler.initialAttributes()
        let hw = attrs.first { $0.0 == GeneralDiagnosticsCluster.Attribute.activeHardwareFaults }
        let radio = attrs.first { $0.0 == GeneralDiagnosticsCluster.Attribute.activeRadioFaults }
        let net = attrs.first { $0.0 == GeneralDiagnosticsCluster.Attribute.activeNetworkFaults }
        #expect(hw?.1 == .array([]))
        #expect(radio?.1 == .array([]))
        #expect(net?.1 == .array([]))
    }

    @Test("initial testEventTriggersEnabled is false")
    func testEventTriggersDisabledByDefault() {
        let handler = GeneralDiagnosticsHandler()
        let attrs = handler.initialAttributes()
        let attr = attrs.first { $0.0 == GeneralDiagnosticsCluster.Attribute.testEventTriggersEnabled }
        #expect(attr?.1 == .bool(false))
    }

    @Test("networkInterfaces contains one entry")
    func networkInterfaceCount() {
        let handler = GeneralDiagnosticsHandler(networkInterfaceName: "en0")
        let attrs = handler.initialAttributes()
        let attr = attrs.first { $0.0 == GeneralDiagnosticsCluster.Attribute.networkInterfaces }
        guard case .array(let entries) = attr?.1 else {
            Issue.record("networkInterfaces is not an array")
            return
        }
        #expect(entries.count == 1)
    }

    @Test("bootReason defaults to powerOnReboot")
    func bootReasonDefault() {
        let handler = GeneralDiagnosticsHandler()
        let attrs = handler.initialAttributes()
        let attr = attrs.first { $0.0 == GeneralDiagnosticsCluster.Attribute.bootReason }
        #expect(attr?.1 == .unsignedInt(UInt64(GeneralDiagnosticsCluster.BootReasonEnum.powerOnReboot.rawValue)))
    }

    @Test("TestEventTrigger fails when triggers disabled")
    func testEventTriggerDisabled() throws {
        let handler = GeneralDiagnosticsHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        let request = GeneralDiagnosticsCluster.TestEventTriggerRequest(
            enableKey: Data(repeating: 0xAB, count: 16),
            eventTrigger: 0x0001
        )

        #expect(throws: GeneralDiagnosticsCluster.GeneralDiagnosticsError.testEventTriggersNotEnabled) {
            _ = try handler.handleCommand(
                commandID: GeneralDiagnosticsCluster.Command.testEventTrigger,
                fields: request.toTLVElement(),
                store: store,
                endpointID: ep0
            )
        }
    }

    @Test("TestEventTrigger succeeds when triggers enabled")
    func testEventTriggerEnabled() throws {
        let handler = GeneralDiagnosticsHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        // Enable test event triggers
        store.set(
            endpoint: ep0,
            cluster: handler.clusterID,
            attribute: GeneralDiagnosticsCluster.Attribute.testEventTriggersEnabled,
            value: .bool(true)
        )

        let request = GeneralDiagnosticsCluster.TestEventTriggerRequest(
            enableKey: Data(repeating: 0xAB, count: 16),
            eventTrigger: 0x0001
        )

        let result = try handler.handleCommand(
            commandID: GeneralDiagnosticsCluster.Command.testEventTrigger,
            fields: request.toTLVElement(),
            store: store,
            endpointID: ep0
        )
        #expect(result == nil)
    }

    @Test("bootReasonEvent produces critical priority event")
    func bootReasonEvent() {
        let handler = GeneralDiagnosticsHandler()
        let event = handler.bootReasonEvent(reason: .powerOnReboot)
        #expect(event.eventID == GeneralDiagnosticsCluster.Event.bootReason)
        #expect(event.priority == .critical)
    }

    @Test("all attributes are not writable (read-only cluster)")
    func allAttributesReadOnly() {
        let handler = GeneralDiagnosticsHandler()
        #expect(handler.validateWrite(
            attributeID: GeneralDiagnosticsCluster.Attribute.rebootCount,
            value: .unsignedInt(5)
        ) == .unsupportedWrite)
        #expect(handler.validateWrite(
            attributeID: GeneralDiagnosticsCluster.Attribute.upTime,
            value: .unsignedInt(1000)
        ) == .unsupportedWrite)
    }
}
