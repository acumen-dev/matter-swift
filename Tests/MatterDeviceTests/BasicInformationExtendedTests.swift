// BasicInformationExtendedTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import MatterTypes
import MatterModel
@testable import MatterDevice

@Suite("BasicInformationExtended")
struct BasicInformationExtendedTests {

    // MARK: - New Attribute Tests

    @Test("manufacturingDate attribute included when non-empty")
    func manufacturingDateIncluded() {
        let handler = BasicInformationHandler(manufacturingDate: "2026-01-15")
        let attrs = Dictionary(uniqueKeysWithValues: handler.initialAttributes())
        #expect(attrs[BasicInformationCluster.Attribute.manufacturingDate] == .utf8String("2026-01-15"))
    }

    @Test("manufacturingDate attribute not included when empty")
    func manufacturingDateExcludedWhenEmpty() {
        let handler = BasicInformationHandler()
        let attrs = Dictionary(uniqueKeysWithValues: handler.initialAttributes())
        #expect(attrs[BasicInformationCluster.Attribute.manufacturingDate] == nil)
    }

    @Test("partNumber attribute included when non-empty")
    func partNumberIncluded() {
        let handler = BasicInformationHandler(partNumber: "PN-12345")
        let attrs = Dictionary(uniqueKeysWithValues: handler.initialAttributes())
        #expect(attrs[BasicInformationCluster.Attribute.partNumber] == .utf8String("PN-12345"))
    }

    @Test("productURL attribute included when non-empty")
    func productURLIncluded() {
        let handler = BasicInformationHandler(productURL: "https://example.com/product")
        let attrs = Dictionary(uniqueKeysWithValues: handler.initialAttributes())
        #expect(attrs[BasicInformationCluster.Attribute.productURL] == .utf8String("https://example.com/product"))
    }

    @Test("productLabel attribute included when non-empty")
    func productLabelIncluded() {
        let handler = BasicInformationHandler(productLabel: "Smart Bridge Gen2")
        let attrs = Dictionary(uniqueKeysWithValues: handler.initialAttributes())
        #expect(attrs[BasicInformationCluster.Attribute.productLabel] == .utf8String("Smart Bridge Gen2"))
    }

    @Test("all optional attributes excluded when empty")
    func optionalAttributesExcludedWhenEmpty() {
        let handler = BasicInformationHandler()
        let attrs = Dictionary(uniqueKeysWithValues: handler.initialAttributes())
        #expect(attrs[BasicInformationCluster.Attribute.manufacturingDate] == nil)
        #expect(attrs[BasicInformationCluster.Attribute.partNumber] == nil)
        #expect(attrs[BasicInformationCluster.Attribute.productURL] == nil)
        #expect(attrs[BasicInformationCluster.Attribute.productLabel] == nil)
    }

    @Test("all optional attributes included when non-empty")
    func allOptionalAttributesIncluded() {
        let handler = BasicInformationHandler(
            manufacturingDate: "2026-01-15",
            partNumber: "PN-001",
            productURL: "https://example.com",
            productLabel: "Test Product"
        )
        let attrs = Dictionary(uniqueKeysWithValues: handler.initialAttributes())
        #expect(attrs[BasicInformationCluster.Attribute.manufacturingDate] != nil)
        #expect(attrs[BasicInformationCluster.Attribute.partNumber] != nil)
        #expect(attrs[BasicInformationCluster.Attribute.productURL] != nil)
        #expect(attrs[BasicInformationCluster.Attribute.productLabel] != nil)
    }

    // MARK: - Existing Attributes Still Present

    @Test("existing required attributes still present")
    func existingAttributesStillPresent() {
        let handler = BasicInformationHandler(
            vendorName: "TestVendor",
            vendorID: 0xFFF1,
            productName: "TestProduct",
            productID: 0x8001,
            softwareVersion: 2,
            serialNumber: "SN-001"
        )
        let attrs = Dictionary(uniqueKeysWithValues: handler.initialAttributes())
        #expect(attrs[BasicInformationCluster.Attribute.vendorName] == .utf8String("TestVendor"))
        #expect(attrs[BasicInformationCluster.Attribute.productName] == .utf8String("TestProduct"))
        #expect(attrs[BasicInformationCluster.Attribute.softwareVersion] == .unsignedInt(2))
        #expect(attrs[BasicInformationCluster.Attribute.serialNumber] == .utf8String("SN-001"))
    }

    // MARK: - Event Factory Tests

    @Test("startUpEvent has correct eventID and priority")
    func startUpEventCorrect() {
        let handler = BasicInformationHandler(softwareVersion: 5)
        let event = handler.startUpEvent(softwareVersion: 5)
        #expect(event.eventID == BasicInformationCluster.Event.startUp)
        #expect(event.priority == .critical)
        #expect(event.isUrgent == false)
    }

    @Test("startUpEvent payload contains softwareVersion")
    func startUpEventPayload() {
        let handler = BasicInformationHandler()
        let event = handler.startUpEvent(softwareVersion: 42)
        guard case .structure(let fields) = event.data,
              let versionField = fields.first(where: { $0.tag == .contextSpecific(0) }) else {
            Issue.record("Expected structure data with context tag 0")
            return
        }
        #expect(versionField.value == .unsignedInt(42))
    }

    @Test("shutDownEvent has correct eventID and priority")
    func shutDownEventCorrect() {
        let handler = BasicInformationHandler()
        let event = handler.shutDownEvent()
        #expect(event.eventID == BasicInformationCluster.Event.shutDown)
        #expect(event.priority == .critical)
        #expect(event.data == nil)
    }

    @Test("leaveEvent has correct eventID and priority")
    func leaveEventCorrect() {
        let handler = BasicInformationHandler()
        let event = handler.leaveEvent(fabricIndex: 2)
        #expect(event.eventID == BasicInformationCluster.Event.leave)
        #expect(event.priority == .info)
    }

    @Test("leaveEvent payload contains fabricIndex")
    func leaveEventPayload() {
        let handler = BasicInformationHandler()
        let event = handler.leaveEvent(fabricIndex: 3)
        guard case .structure(let fields) = event.data,
              let fabricField = fields.first(where: { $0.tag == .contextSpecific(0) }) else {
            Issue.record("Expected structure data with context tag 0")
            return
        }
        #expect(fabricField.value == .unsignedInt(3))
    }
}
