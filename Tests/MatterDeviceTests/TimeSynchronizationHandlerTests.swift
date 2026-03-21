// TimeSynchronizationHandlerTests.swift
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

@Suite("TimeSynchronizationHandler")
struct TimeSynchronizationHandlerTests {

    @Test("initial utcTime is null (no time set)")
    func initialUTCTimeNull() {
        let handler = TimeSynchronizationHandler()
        let attrs = handler.initialAttributes()
        let attr = attrs.first { $0.0 == TimeSynchronizationCluster.Attribute.utcTime }
        #expect(attr?.1 == .null)
    }

    @Test("initial granularity is noTimeGranularity")
    func initialGranularity() {
        let handler = TimeSynchronizationHandler()
        let attrs = handler.initialAttributes()
        let attr = attrs.first { $0.0 == TimeSynchronizationCluster.Attribute.granularity }
        #expect(attr?.1 == .unsignedInt(0))
    }

    @Test("initial timeSource is none")
    func initialTimeSource() {
        let handler = TimeSynchronizationHandler()
        let attrs = handler.initialAttributes()
        let attr = attrs.first { $0.0 == TimeSynchronizationCluster.Attribute.timeSource }
        #expect(attr?.1 == .unsignedInt(0))
    }

    @Test("SetUTCTime writes utcTime and granularity")
    func setUTCTime() throws {
        let handler = TimeSynchronizationHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        let testTime: UInt64 = 1_000_000_000
        let request = TimeSynchronizationCluster.SetUTCTimeRequest(
            utcTime: testTime,
            granularity: .secondsGranularity
        )

        let result = try handler.handleCommand(
            commandID: TimeSynchronizationCluster.Command.setUTCTime,
            fields: request.toTLVElement(),
            store: store,
            endpointID: ep0
        )
        #expect(result == nil)

        let utcAttr = store.get(endpoint: ep0, cluster: handler.clusterID, attribute: TimeSynchronizationCluster.Attribute.utcTime)
        #expect(utcAttr?.uintValue == testTime)

        let granAttr = store.get(endpoint: ep0, cluster: handler.clusterID, attribute: TimeSynchronizationCluster.Attribute.granularity)
        #expect(granAttr?.uintValue == UInt64(TimeSynchronizationCluster.GranularityEnum.secondsGranularity.rawValue))
    }

    @Test("SetUTCTime with optional timeSource writes timeSource attribute")
    func setUTCTimeWithSource() throws {
        let handler = TimeSynchronizationHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        let request = TimeSynchronizationCluster.SetUTCTimeRequest(
            utcTime: 2_000_000_000,
            granularity: .millisecondsGranularity,
            timeSource: .admin
        )

        _ = try handler.handleCommand(
            commandID: TimeSynchronizationCluster.Command.setUTCTime,
            fields: request.toTLVElement(),
            store: store,
            endpointID: ep0
        )

        let sourceAttr = store.get(endpoint: ep0, cluster: handler.clusterID, attribute: TimeSynchronizationCluster.Attribute.timeSource)
        #expect(sourceAttr?.uintValue == UInt64(TimeSynchronizationCluster.TimeSourceEnum.admin.rawValue))
    }

    @Test("featureMap is zero (no special features)")
    func featureMap() {
        let handler = TimeSynchronizationHandler()
        let attrs = handler.initialAttributes()
        let attr = attrs.first { $0.0 == AttributeID.featureMap }
        #expect(attr?.1 == .unsignedInt(0))
    }

    @Test("clusterRevision is present")
    func clusterRevision() {
        let handler = TimeSynchronizationHandler()
        let attrs = handler.initialAttributes()
        let attr = attrs.first { $0.0 == AttributeID.clusterRevision }
        #expect(attr?.1 != nil)
    }

    @Test("trustedTimeSource and defaultNTP default to null")
    func optionalAttributesNull() {
        let handler = TimeSynchronizationHandler()
        let attrs = handler.initialAttributes()
        let trustedTS = attrs.first { $0.0 == TimeSynchronizationCluster.Attribute.trustedTimeSource }
        let defaultNTP = attrs.first { $0.0 == TimeSynchronizationCluster.Attribute.defaultNTP }
        #expect(trustedTS?.1 == .null)
        #expect(defaultNTP?.1 == .null)
    }

    @Test("SetUTCTimeRequest round-trips through TLV")
    func setUTCTimeRoundTrip() throws {
        let original = TimeSynchronizationCluster.SetUTCTimeRequest(
            utcTime: 12345678,
            granularity: .microsecondsGranularity,
            timeSource: .admin
        )
        let decoded = try TimeSynchronizationCluster.SetUTCTimeRequest.fromTLVElement(original.toTLVElement())
        #expect(decoded == original)
    }
}
