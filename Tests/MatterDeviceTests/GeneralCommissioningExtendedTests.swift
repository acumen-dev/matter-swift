// GeneralCommissioningExtendedTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterModel
@testable import MatterDevice

@Suite("GeneralCommissioningExtended")
struct GeneralCommissioningExtendedTests {

    let endpoint = EndpointID(rawValue: 0)

    private func makeHandler() -> (GeneralCommissioningHandler, AttributeStore) {
        let state = CommissioningState()
        let handler = GeneralCommissioningHandler(commissioningState: state)
        let store = AttributeStore()
        for (attr, value) in handler.initialAttributes() {
            store.set(endpoint: endpoint, cluster: handler.clusterID, attribute: attr, value: value)
        }
        return (handler, store)
    }

    private func armFailSafe(_ handler: GeneralCommissioningHandler, store: AttributeStore) throws {
        let armFields = GeneralCommissioningCluster.ArmFailSafeRequest(
            expiryLengthSeconds: 900,
            breadcrumb: 0
        ).toTLVElement()
        _ = try handler.handleCommand(
            commandID: GeneralCommissioningCluster.Command.armFailSafe,
            fields: armFields,
            store: store,
            endpointID: endpoint
        )
    }

    // MARK: - LocationCapability Validation

    @Test("SetRegulatoryConfig accepts Indoor when capability is IndoorOutdoor")
    func setRegulatoryConfigIndoorAllowed() throws {
        let (handler, store) = makeHandler()
        try armFailSafe(handler, store: store)

        // Capability is IndoorOutdoor (2) by default
        let request = GeneralCommissioningCluster.SetRegulatoryConfigRequest(
            newRegulatoryConfig: .indoor,
            countryCode: "US",
            breadcrumb: 1
        ).toTLVElement()

        let result = try handler.handleCommand(
            commandID: GeneralCommissioningCluster.Command.setRegulatoryConfig,
            fields: request,
            store: store,
            endpointID: endpoint
        )

        let response = try GeneralCommissioningCluster.SetRegulatoryConfigResponse.fromTLVElement(result!)
        #expect(response.errorCode == .ok)
    }

    @Test("SetRegulatoryConfig accepts Outdoor when capability is IndoorOutdoor")
    func setRegulatoryConfigOutdoorAllowed() throws {
        let (handler, store) = makeHandler()
        try armFailSafe(handler, store: store)

        let request = GeneralCommissioningCluster.SetRegulatoryConfigRequest(
            newRegulatoryConfig: .outdoor,
            countryCode: "US",
            breadcrumb: 1
        ).toTLVElement()

        let result = try handler.handleCommand(
            commandID: GeneralCommissioningCluster.Command.setRegulatoryConfig,
            fields: request,
            store: store,
            endpointID: endpoint
        )

        let response = try GeneralCommissioningCluster.SetRegulatoryConfigResponse.fromTLVElement(result!)
        #expect(response.errorCode == .ok)
    }

    @Test("SetRegulatoryConfig rejects Outdoor when capability is Indoor-only")
    func setRegulatoryConfigOutdoorRejectedForIndoorCapability() throws {
        let (handler, store) = makeHandler()
        try armFailSafe(handler, store: store)

        // Set capability to Indoor-only (0)
        store.set(
            endpoint: endpoint,
            cluster: handler.clusterID,
            attribute: GeneralCommissioningCluster.Attribute.locationCapability,
            value: .unsignedInt(0) // indoor = 0
        )

        let request = GeneralCommissioningCluster.SetRegulatoryConfigRequest(
            newRegulatoryConfig: .outdoor,
            countryCode: "US",
            breadcrumb: 1
        ).toTLVElement()

        let result = try handler.handleCommand(
            commandID: GeneralCommissioningCluster.Command.setRegulatoryConfig,
            fields: request,
            store: store,
            endpointID: endpoint
        )

        let response = try GeneralCommissioningCluster.SetRegulatoryConfigResponse.fromTLVElement(result!)
        #expect(response.errorCode == .valueOutsideRange)
    }

    @Test("SetRegulatoryConfig rejects Indoor when capability is Outdoor-only")
    func setRegulatoryConfigIndoorRejectedForOutdoorCapability() throws {
        let (handler, store) = makeHandler()
        try armFailSafe(handler, store: store)

        // Set capability to Outdoor-only (1)
        store.set(
            endpoint: endpoint,
            cluster: handler.clusterID,
            attribute: GeneralCommissioningCluster.Attribute.locationCapability,
            value: .unsignedInt(1) // outdoor = 1
        )

        let request = GeneralCommissioningCluster.SetRegulatoryConfigRequest(
            newRegulatoryConfig: .indoor,
            countryCode: "US",
            breadcrumb: 1
        ).toTLVElement()

        let result = try handler.handleCommand(
            commandID: GeneralCommissioningCluster.Command.setRegulatoryConfig,
            fields: request,
            store: store,
            endpointID: endpoint
        )

        let response = try GeneralCommissioningCluster.SetRegulatoryConfigResponse.fromTLVElement(result!)
        #expect(response.errorCode == .valueOutsideRange)
    }

    @Test("SetRegulatoryConfig accepts Indoor when capability is Indoor-only")
    func setRegulatoryConfigIndoorAllowedForIndoorCapability() throws {
        let (handler, store) = makeHandler()
        try armFailSafe(handler, store: store)

        // Set capability to Indoor-only (0)
        store.set(
            endpoint: endpoint,
            cluster: handler.clusterID,
            attribute: GeneralCommissioningCluster.Attribute.locationCapability,
            value: .unsignedInt(0)
        )

        let request = GeneralCommissioningCluster.SetRegulatoryConfigRequest(
            newRegulatoryConfig: .indoor,
            countryCode: "US",
            breadcrumb: 1
        ).toTLVElement()

        let result = try handler.handleCommand(
            commandID: GeneralCommissioningCluster.Command.setRegulatoryConfig,
            fields: request,
            store: store,
            endpointID: endpoint
        )

        let response = try GeneralCommissioningCluster.SetRegulatoryConfigResponse.fromTLVElement(result!)
        #expect(response.errorCode == .ok)
    }

    // MARK: - CommissioningComplete Event

    @Test("generatedEvents returns commissioningComplete event for CommissioningComplete command")
    func generatedEventsCommissioningComplete() {
        let (handler, store) = makeHandler()
        let events = handler.generatedEvents(
            commandID: GeneralCommissioningCluster.Command.commissioningComplete,
            endpointID: endpoint,
            store: store
        )
        #expect(events.count == 1)
        #expect(events[0].eventID == GeneralCommissioningCluster.Event.commissioningComplete)
        #expect(events[0].priority == .info)
    }

    @Test("generatedEvents returns empty for other commands")
    func generatedEventsOtherCommands() {
        let (handler, store) = makeHandler()
        let events = handler.generatedEvents(
            commandID: GeneralCommissioningCluster.Command.armFailSafe,
            endpointID: endpoint,
            store: store
        )
        #expect(events.isEmpty)
    }
}
