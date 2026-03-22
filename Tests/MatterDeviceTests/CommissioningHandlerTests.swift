// CommissioningHandlerTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
@testable import MatterDevice
@testable import MatterModel
@testable import MatterCrypto

// MARK: - Helpers

private func populateStore(_ store: AttributeStore, handler: some ClusterHandler, endpoint: EndpointID) {
    for (attr, value) in handler.initialAttributes() {
        store.set(endpoint: endpoint, cluster: handler.clusterID, attribute: attr, value: value)
    }
}

private let ep0 = EndpointID(rawValue: 0)

// MARK: - BasicInformationHandler Tests

@Suite("BasicInformationHandler")
struct BasicInformationHandlerTests {

    @Test("Initial attributes include vendor name, product name, and capability minima")
    func initialAttributes() {
        let handler = BasicInformationHandler(
            vendorName: "TestVendor",
            vendorID: 0x1234,
            productName: "TestProduct",
            productID: 0x5678
        )
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        let vendorName = store.get(endpoint: ep0, cluster: .basicInformation, attribute: BasicInformationCluster.Attribute.vendorName)
        #expect(vendorName?.stringValue == "TestVendor")

        let productName = store.get(endpoint: ep0, cluster: .basicInformation, attribute: BasicInformationCluster.Attribute.productName)
        #expect(productName?.stringValue == "TestProduct")

        let vendorID = store.get(endpoint: ep0, cluster: .basicInformation, attribute: BasicInformationCluster.Attribute.vendorID)
        #expect(vendorID?.uintValue == 0x1234)

        let productID = store.get(endpoint: ep0, cluster: .basicInformation, attribute: BasicInformationCluster.Attribute.productID)
        #expect(productID?.uintValue == 0x5678)

        // Capability minima should be a structure
        let capMinima = store.get(endpoint: ep0, cluster: .basicInformation, attribute: BasicInformationCluster.Attribute.capabilityMinima)
        #expect(capMinima != nil)
    }

    @Test("NodeLabel is writable, vendorName is read-only")
    func writeValidation() {
        let handler = BasicInformationHandler()

        #expect(handler.validateWrite(attributeID: BasicInformationCluster.Attribute.nodeLabel, value: .utf8String("Test")) == .allowed)
        #expect(handler.validateWrite(attributeID: BasicInformationCluster.Attribute.vendorName, value: .utf8String("X")) == .unsupportedWrite)
    }

    @Test("NodeLabel write rejects strings over 32 chars")
    func nodeLabelConstraint() {
        let handler = BasicInformationHandler()
        let longString = String(repeating: "A", count: 33)
        #expect(handler.validateWrite(attributeID: BasicInformationCluster.Attribute.nodeLabel, value: .utf8String(longString)) == .constraintError)
    }
}

// MARK: - GeneralCommissioningHandler Tests

@Suite("GeneralCommissioningHandler")
struct GeneralCommissioningHandlerTests {

    @Test("ArmFailSafe arms the fail-safe timer")
    func armFailSafe() throws {
        let state = CommissioningState()
        let handler = GeneralCommissioningHandler(commissioningState: state)
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        let request = GeneralCommissioningCluster.ArmFailSafeRequest(expiryLengthSeconds: 60, breadcrumb: 42)
        let response = try handler.handleCommand(
            commandID: GeneralCommissioningCluster.Command.armFailSafe,
            fields: request.toTLVElement(),
            store: store,
            endpointID: ep0
        )

        #expect(state.isFailSafeArmed)
        #expect(state.failSafeExpiry != nil)

        // Check response is OK
        let parsed = try GeneralCommissioningCluster.ArmFailSafeResponse.fromTLVElement(response!)
        #expect(parsed.errorCode == .ok)

        // Check breadcrumb updated
        let breadcrumb = store.get(endpoint: ep0, cluster: GeneralCommissioningCluster.id, attribute: GeneralCommissioningCluster.Attribute.breadcrumb)
        #expect(breadcrumb?.uintValue == 42)
    }

    @Test("ArmFailSafe with 0 seconds disarms")
    func disarmFailSafe() throws {
        let state = CommissioningState()
        state.armFailSafe(expiresAt: Date().addingTimeInterval(60))
        #expect(state.isFailSafeArmed)

        let handler = GeneralCommissioningHandler(commissioningState: state)
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        let request = GeneralCommissioningCluster.ArmFailSafeRequest(expiryLengthSeconds: 0)
        _ = try handler.handleCommand(
            commandID: GeneralCommissioningCluster.Command.armFailSafe,
            fields: request.toTLVElement(),
            store: store,
            endpointID: ep0
        )

        #expect(!state.isFailSafeArmed)
    }

    @Test("SetRegulatoryConfig requires fail-safe to be armed")
    func setRegulatoryConfigRequiresFailSafe() throws {
        let state = CommissioningState()
        let handler = GeneralCommissioningHandler(commissioningState: state)
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        let request = GeneralCommissioningCluster.SetRegulatoryConfigRequest(
            newRegulatoryConfig: .indoorOutdoor
        )
        let response = try handler.handleCommand(
            commandID: GeneralCommissioningCluster.Command.setRegulatoryConfig,
            fields: request.toTLVElement(),
            store: store,
            endpointID: ep0
        )

        let parsed = try GeneralCommissioningCluster.SetRegulatoryConfigResponse.fromTLVElement(response!)
        #expect(parsed.errorCode == .noFailSafe)
    }

    @Test("SetRegulatoryConfig succeeds when fail-safe is armed")
    func setRegulatoryConfigSuccess() throws {
        let state = CommissioningState()
        state.armFailSafe(expiresAt: Date().addingTimeInterval(60))

        let handler = GeneralCommissioningHandler(commissioningState: state)
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        let request = GeneralCommissioningCluster.SetRegulatoryConfigRequest(
            newRegulatoryConfig: .indoorOutdoor,
            countryCode: "AU",
            breadcrumb: 99
        )
        let response = try handler.handleCommand(
            commandID: GeneralCommissioningCluster.Command.setRegulatoryConfig,
            fields: request.toTLVElement(),
            store: store,
            endpointID: ep0
        )

        let parsed = try GeneralCommissioningCluster.SetRegulatoryConfigResponse.fromTLVElement(response!)
        #expect(parsed.errorCode == .ok)

        let regConfig = store.get(endpoint: ep0, cluster: GeneralCommissioningCluster.id, attribute: GeneralCommissioningCluster.Attribute.regulatoryConfig)
        #expect(regConfig?.uintValue == 2) // IndoorOutdoor
    }

    @Test("CommissioningComplete commits staged state")
    func commissioningComplete() throws {
        let state = CommissioningState()
        state.armFailSafe(expiresAt: Date().addingTimeInterval(60))

        let handler = GeneralCommissioningHandler(commissioningState: state)
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        let response = try handler.handleCommand(
            commandID: GeneralCommissioningCluster.Command.commissioningComplete,
            fields: nil,
            store: store,
            endpointID: ep0
        )

        let parsed = try GeneralCommissioningCluster.CommissioningCompleteResponse.fromTLVElement(response!)
        #expect(parsed.errorCode == .ok)
        #expect(!state.isFailSafeArmed)
    }

    @Test("CommissioningComplete requires fail-safe to be armed")
    func commissioningCompleteRequiresFailSafe() throws {
        let state = CommissioningState()
        let handler = GeneralCommissioningHandler(commissioningState: state)
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        let response = try handler.handleCommand(
            commandID: GeneralCommissioningCluster.Command.commissioningComplete,
            fields: nil,
            store: store,
            endpointID: ep0
        )

        let parsed = try GeneralCommissioningCluster.CommissioningCompleteResponse.fromTLVElement(response!)
        #expect(parsed.errorCode == .noFailSafe)
    }
}

// MARK: - OperationalCredentialsHandler Tests

@Suite("OperationalCredentialsHandler")
struct OperationalCredentialsHandlerTests {

    @Test("CSRRequest generates operational key and returns CSR response")
    func csrRequest() throws {
        let state = CommissioningState()
        state.armFailSafe(expiresAt: Date().addingTimeInterval(60))

        let handler = OperationalCredentialsHandler(commissioningState: state)
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        var nonce = Data(count: 32)
        nonce.withUnsafeMutableBytes { buf in
            var rng = SystemRandomNumberGenerator()
            buf.storeBytes(of: rng.next(), toByteOffset: 0,  as: UInt64.self)
            buf.storeBytes(of: rng.next(), toByteOffset: 8,  as: UInt64.self)
            buf.storeBytes(of: rng.next(), toByteOffset: 16, as: UInt64.self)
            buf.storeBytes(of: rng.next(), toByteOffset: 24, as: UInt64.self)
        }

        let request = OperationalCredentialsCluster.CSRRequest(csrNonce: nonce)
        let response = try handler.handleCommand(
            commandID: OperationalCredentialsCluster.Command.csrRequest,
            fields: request.toTLVElement(),
            store: store,
            endpointID: ep0
        )

        #expect(response != nil)
        let csrResp = try OperationalCredentialsCluster.CSRResponse.fromTLVElement(response!)
        #expect(!csrResp.nocsrElements.isEmpty)
        #expect(!csrResp.attestationSignature.isEmpty)

        // Operational key should be stored in state
        #expect(state.operationalKey != nil)
        #expect(state.csrNonce == nonce)
    }

    @Test("CSRRequest fails without fail-safe")
    func csrRequestNoFailSafe() throws {
        let state = CommissioningState()
        let handler = OperationalCredentialsHandler(commissioningState: state)
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        var nonce = Data(count: 32)
        nonce.withUnsafeMutableBytes { buf in
            var rng = SystemRandomNumberGenerator()
            buf.storeBytes(of: rng.next(), toByteOffset: 0,  as: UInt64.self)
            buf.storeBytes(of: rng.next(), toByteOffset: 8,  as: UInt64.self)
            buf.storeBytes(of: rng.next(), toByteOffset: 16, as: UInt64.self)
            buf.storeBytes(of: rng.next(), toByteOffset: 24, as: UInt64.self)
        }

        let request = OperationalCredentialsCluster.CSRRequest(csrNonce: nonce)
        let response = try handler.handleCommand(
            commandID: OperationalCredentialsCluster.Command.csrRequest,
            fields: request.toTLVElement(),
            store: store,
            endpointID: ep0
        )

        // Should return NOCResponse with error
        let nocResp = try OperationalCredentialsCluster.NOCResponse.fromTLVElement(response!)
        #expect(nocResp.statusCode == .missingCSR)
    }

    @Test("AddNOC stages credentials in commissioning state")
    func addNOC() throws {
        let state = CommissioningState()
        state.armFailSafe(expiresAt: Date().addingTimeInterval(60))

        let handler = OperationalCredentialsHandler(commissioningState: state)
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        let addNOC = OperationalCredentialsCluster.AddNOCCommand(
            nocValue: Data([0x01, 0x02, 0x03]),
            ipkValue: Data(repeating: 0xAB, count: 16),
            caseAdminSubject: 12345,
            adminVendorId: 0xFFF1
        )

        let response = try handler.handleCommand(
            commandID: OperationalCredentialsCluster.Command.addNOC,
            fields: addNOC.toTLVElement(),
            store: store,
            endpointID: ep0
        )

        let nocResp = try OperationalCredentialsCluster.NOCResponse.fromTLVElement(response!)
        #expect(nocResp.statusCode == .ok)

        #expect(state.stagedNOC == Data([0x01, 0x02, 0x03]))
        #expect(state.stagedIPK == Data(repeating: 0xAB, count: 16))
        #expect(state.stagedCaseAdminSubject == 12345)
    }

    @Test("AddNOC with non-empty ICAC stages ICAC")
    func addNOCWithICAC() throws {
        let state = CommissioningState()
        state.armFailSafe(expiresAt: Date().addingTimeInterval(60))

        let handler = OperationalCredentialsHandler(commissioningState: state)
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        let icacBytes = Data([0x15, 0x01, 0x02, 0x03, 0x18]) // fake non-empty ICAC
        let addNOC = OperationalCredentialsCluster.AddNOCCommand(
            nocValue: Data([0x01, 0x02, 0x03]),
            icacValue: icacBytes,
            ipkValue: Data(repeating: 0xAB, count: 16),
            caseAdminSubject: 12345,
            adminVendorId: 0xFFF1
        )

        _ = try handler.handleCommand(
            commandID: OperationalCredentialsCluster.Command.addNOC,
            fields: addNOC.toTLVElement(),
            store: store,
            endpointID: ep0
        )

        #expect(state.stagedICAC == icacBytes)
    }

    @Test("AddNOC with zero-length ICAC field treats ICAC as absent")
    func addNOCWithEmptyICAC() throws {
        // Apple Home sends tag 1 as a 0-byte octet string when no ICAC is used
        // (direct RCAC→NOC chain). This must be treated as absent, not as a
        // 0-byte certificate — attempting to parse 0 bytes throws unexpectedEndOfData.
        let state = CommissioningState()
        state.armFailSafe(expiresAt: Date().addingTimeInterval(60))

        let handler = OperationalCredentialsHandler(commissioningState: state)
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        // Construct the AddNOC TLV manually so we can include an explicit empty ICAC field
        let fields: TLVElement = .structure([
            .init(tag: .contextSpecific(0), value: .octetString(Data([0x01, 0x02, 0x03]))), // noc
            .init(tag: .contextSpecific(1), value: .octetString(Data())),                   // icac = empty
            .init(tag: .contextSpecific(2), value: .octetString(Data(repeating: 0, count: 16))), // ipk
            .init(tag: .contextSpecific(3), value: .unsignedInt(12345)),                    // caseAdminSubject
            .init(tag: .contextSpecific(4), value: .unsignedInt(0xFFF1)),                   // adminVendorId
        ])

        _ = try handler.handleCommand(
            commandID: OperationalCredentialsCluster.Command.addNOC,
            fields: fields,
            store: store,
            endpointID: ep0
        )

        // A 0-byte ICAC field MUST be treated as absent, not stored as empty Data
        #expect(state.stagedICAC == nil, "empty ICAC field must be treated as absent")
    }

    @Test("AddTrustedRootCert stages RCAC")
    func addTrustedRootCert() throws {
        let state = CommissioningState()
        state.armFailSafe(expiresAt: Date().addingTimeInterval(60))

        let handler = OperationalCredentialsHandler(commissioningState: state)
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        let rcacData = Data([0xAA, 0xBB, 0xCC])
        let fields: TLVElement = .structure([
            .init(tag: .contextSpecific(0), value: .octetString(rcacData))
        ])

        _ = try handler.handleCommand(
            commandID: OperationalCredentialsCluster.Command.addTrustedRootCert,
            fields: fields,
            store: store,
            endpointID: ep0
        )

        #expect(state.stagedRCAC == rcacData)
    }

    // MARK: - RemoveFabric

    @Test("RemoveFabric removes existing fabric and updates attributes")
    func removeFabric() throws {
        let state = CommissioningState()
        state.armFailSafe(expiresAt: Date().addingTimeInterval(60))

        // Commit a fabric
        let (testFabric, _) = try FabricInfo.generateTestFabric()
        _ = state.generateOperationalKey(csrNonce: Data(repeating: 0x01, count: 32))
        state.stagedRCAC = testFabric.rcac.tlvEncode()
        state.stagedNOC = testFabric.noc.tlvEncode()
        state.stagedIPK = Data(repeating: 0, count: 16)
        state.stagedCaseAdminSubject = 100
        state.stagedAdminVendorId = 0xFFF1
        state.commitCommissioning()

        let fabricIndex = state.fabrics.keys.first!
        #expect(state.fabrics.count == 1)

        let handler = OperationalCredentialsHandler(commissioningState: state)
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        let fields: TLVElement = .structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(UInt64(fabricIndex.rawValue)))
        ])

        let response = try handler.handleCommand(
            commandID: OperationalCredentialsCluster.Command.removeFabric,
            fields: fields,
            store: store,
            endpointID: ep0
        )

        let nocResp = try OperationalCredentialsCluster.NOCResponse.fromTLVElement(response!)
        #expect(nocResp.statusCode == .ok)
        #expect(nocResp.fabricIndex == fabricIndex)
        #expect(state.fabrics.isEmpty)

        // commissionedFabrics attribute should be 0
        let commissioned = store.get(endpoint: ep0, cluster: .operationalCredentials, attribute: OperationalCredentialsCluster.Attribute.commissionedFabrics)
        #expect(commissioned?.uintValue == 0)
    }

    @Test("RemoveFabric returns error for invalid index")
    func removeFabricInvalid() throws {
        let state = CommissioningState()
        let handler = OperationalCredentialsHandler(commissioningState: state)
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        let fields: TLVElement = .structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(99))
        ])

        let response = try handler.handleCommand(
            commandID: OperationalCredentialsCluster.Command.removeFabric,
            fields: fields,
            store: store,
            endpointID: ep0
        )

        let nocResp = try OperationalCredentialsCluster.NOCResponse.fromTLVElement(response!)
        #expect(nocResp.statusCode == .invalidFabricIndex)
    }

    // MARK: - UpdateFabricLabel

    @Test("UpdateFabricLabel sets label on existing fabric")
    func updateFabricLabel() throws {
        let state = CommissioningState()
        state.armFailSafe(expiresAt: Date().addingTimeInterval(60))

        // Commit a fabric
        let (testFabric, _) = try FabricInfo.generateTestFabric()
        _ = state.generateOperationalKey(csrNonce: Data(repeating: 0x01, count: 32))
        state.stagedRCAC = testFabric.rcac.tlvEncode()
        state.stagedNOC = testFabric.noc.tlvEncode()
        state.stagedIPK = Data(repeating: 0, count: 16)
        state.stagedCaseAdminSubject = 100
        state.stagedAdminVendorId = 0xFFF1
        state.commitCommissioning()

        let fabricIndex = state.fabrics.keys.first!
        state.invokingFabricIndex = fabricIndex

        let handler = OperationalCredentialsHandler(commissioningState: state)
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        let fields: TLVElement = .structure([
            .init(tag: .contextSpecific(0), value: .utf8String("Living Room"))
        ])

        let response = try handler.handleCommand(
            commandID: OperationalCredentialsCluster.Command.updateFabricLabel,
            fields: fields,
            store: store,
            endpointID: ep0
        )

        let nocResp = try OperationalCredentialsCluster.NOCResponse.fromTLVElement(response!)
        #expect(nocResp.statusCode == .ok)
        #expect(state.fabrics[fabricIndex]?.label == "Living Room")
    }

    @Test("UpdateFabricLabel rejects duplicate label")
    func updateFabricLabelConflict() throws {
        let state = CommissioningState()

        // Commit two fabrics
        for i in 1...2 {
            state.armFailSafe(expiresAt: Date().addingTimeInterval(60))
            let (testFabric, _) = try FabricInfo.generateTestFabric()
            _ = state.generateOperationalKey(csrNonce: Data(repeating: UInt8(i), count: 32))
            state.stagedRCAC = testFabric.rcac.tlvEncode()
            state.stagedNOC = testFabric.noc.tlvEncode()
            state.stagedIPK = Data(repeating: 0, count: 16)
            state.stagedCaseAdminSubject = UInt64(100 + i)
            state.stagedAdminVendorId = 0xFFF1
            state.commitCommissioning()
        }

        #expect(state.fabrics.count == 2)
        let indices = state.fabrics.keys.sorted { $0.rawValue < $1.rawValue }
        let fabric1 = indices[0]
        let fabric2 = indices[1]

        // Label fabric1
        state.invokingFabricIndex = fabric1
        state.fabrics[fabric1]?.label = "Office"

        // Try to label fabric2 with the same label
        state.invokingFabricIndex = fabric2
        let handler = OperationalCredentialsHandler(commissioningState: state)
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        let fields: TLVElement = .structure([
            .init(tag: .contextSpecific(0), value: .utf8String("Office"))
        ])

        let response = try handler.handleCommand(
            commandID: OperationalCredentialsCluster.Command.updateFabricLabel,
            fields: fields,
            store: store,
            endpointID: ep0
        )

        let nocResp = try OperationalCredentialsCluster.NOCResponse.fromTLVElement(response!)
        #expect(nocResp.statusCode == .labelConflict)
    }
}

// MARK: - AccessControlHandler Tests

@Suite("AccessControlHandler")
struct AccessControlHandlerTests {

    @Test("ACL attribute is writable")
    func aclWritable() {
        let state = CommissioningState()
        let handler = AccessControlHandler(commissioningState: state)
        #expect(handler.validateWrite(attributeID: AccessControlCluster.Attribute.acl, value: .array([])) == .allowed)
    }

    @Test("Non-ACL attributes are read-only")
    func readOnlyAttributes() {
        let state = CommissioningState()
        let handler = AccessControlHandler(commissioningState: state)
        #expect(handler.validateWrite(attributeID: AccessControlCluster.Attribute.subjectsPerAccessControlEntry, value: .unsignedInt(5)) == .unsupportedWrite)
    }
}

// MARK: - AdminCommissioningHandler Tests

@Suite("AdminCommissioningHandler")
struct AdminCommissioningHandlerTests {

    @Test("Initial window status reflects commissioning state")
    func initialWindowStatus() {
        let state = CommissioningState()
        let handler = AdminCommissioningHandler(commissioningState: state)
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        // Default state is not open
        let status = store.get(endpoint: ep0, cluster: .adminCommissioning, attribute: AdminCommissioningHandler.Attribute.windowStatus)
        #expect(status?.uintValue == 0) // Not open
    }

    @Test("OpenBasicCommissioningWindow opens the window with timeout")
    func openBasicWindow() throws {
        let state = CommissioningState()
        let handler = AdminCommissioningHandler(commissioningState: state)
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        let fields: TLVElement = .structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(300))  // 300 seconds
        ])

        _ = try handler.handleCommand(
            commandID: AdminCommissioningHandler.Command.openBasicCommissioningWindow,
            fields: fields,
            store: store,
            endpointID: ep0
        )

        #expect(state.windowStatus == .basicWindowOpen)
        #expect(state.windowExpiry != nil)

        let status = store.get(endpoint: ep0, cluster: .adminCommissioning, attribute: AdminCommissioningHandler.Attribute.windowStatus)
        #expect(status?.uintValue == 2) // BasicWindowOpen
    }

    @Test("OpenBasicCommissioningWindow clamps timeout to 180-900 range")
    func openBasicWindowClampsTimeout() throws {
        let state = CommissioningState()
        let handler = AdminCommissioningHandler(commissioningState: state)
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        // Try to set timeout to 10 seconds (below minimum 180)
        let fields: TLVElement = .structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(10))
        ])

        _ = try handler.handleCommand(
            commandID: AdminCommissioningHandler.Command.openBasicCommissioningWindow,
            fields: fields,
            store: store,
            endpointID: ep0
        )

        // Window should be open with timeout clamped to at least 180s
        #expect(state.windowStatus == .basicWindowOpen)
        #expect(state.windowExpiry != nil)
        let remaining = state.windowExpiry!.timeIntervalSinceNow
        #expect(remaining > 170)  // Should be ~180s
    }

    @Test("OpenBasicCommissioningWindow rejects when window already open")
    func openBasicWindowRejectsWhenOpen() throws {
        let state = CommissioningState()
        state.openBasicWindow(timeout: 300)

        let handler = AdminCommissioningHandler(commissioningState: state)
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        let fields: TLVElement = .structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(300))
        ])

        let result = try handler.handleCommand(
            commandID: AdminCommissioningHandler.Command.openBasicCommissioningWindow,
            fields: fields,
            store: store,
            endpointID: ep0
        )

        // Returns nil (busy) — window should still be in its original state
        #expect(result == nil)
        #expect(state.windowStatus == .basicWindowOpen)
    }

    @Test("RevokeCommissioning closes the window")
    func revokeCommissioning() throws {
        let state = CommissioningState()
        state.openBasicWindow(timeout: 300)

        let handler = AdminCommissioningHandler(commissioningState: state)
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        _ = try handler.handleCommand(
            commandID: AdminCommissioningHandler.Command.revokeCommissioning,
            fields: nil,
            store: store,
            endpointID: ep0
        )

        #expect(state.windowStatus == .notOpen)
        #expect(state.windowExpiry == nil)

        let status = store.get(endpoint: ep0, cluster: .adminCommissioning, attribute: AdminCommissioningHandler.Attribute.windowStatus)
        #expect(status?.uintValue == 0) // Not open
    }

    @Test("OpenBasicCommissioningWindow sets admin attributes")
    func openWindowSetsAdminAttributes() throws {
        let state = CommissioningState()
        let handler = AdminCommissioningHandler(commissioningState: state)
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        // Set admin context before opening
        state.openBasicWindow(
            timeout: 300,
            fabricIndex: FabricIndex(rawValue: 2),
            vendorId: 0x1234
        )
        handler.updateWindowAttributes(store: store, endpointID: ep0)

        let fabricIndex = store.get(endpoint: ep0, cluster: .adminCommissioning, attribute: AdminCommissioningHandler.Attribute.adminFabricIndex)
        #expect(fabricIndex?.uintValue == 2)

        let vendorId = store.get(endpoint: ep0, cluster: .adminCommissioning, attribute: AdminCommissioningHandler.Attribute.adminVendorId)
        #expect(vendorId?.uintValue == 0x1234)
    }
}

// MARK: - CommissioningState Tests

@Suite("CommissioningState")
struct CommissioningStateTests {

    @Test("Fail-safe arm and disarm")
    func failSafeLifecycle() {
        let state = CommissioningState()
        #expect(!state.isFailSafeArmed)

        state.armFailSafe(expiresAt: Date().addingTimeInterval(60))
        #expect(state.isFailSafeArmed)
        #expect(state.failSafeExpiry != nil)

        state.disarmFailSafe()
        #expect(!state.isFailSafeArmed)
        #expect(state.failSafeExpiry == nil)
    }

    @Test("Fail-safe expiry check")
    func failSafeExpiry() {
        let state = CommissioningState()
        state.armFailSafe(expiresAt: Date().addingTimeInterval(-1)) // Already expired

        let expired = state.checkFailSafeExpiry()
        #expect(expired)
        #expect(!state.isFailSafeArmed)
    }

    @Test("GenerateOperationalKey stores key and nonce")
    func generateOperationalKey() {
        let state = CommissioningState()
        let nonce = Data(repeating: 0x42, count: 32)

        let key = state.generateOperationalKey(csrNonce: nonce)
        #expect(state.operationalKey != nil)
        #expect(state.csrNonce == nonce)
        #expect(key.publicKey.x963Representation.count == 65)
    }

    @Test("Commit commissioning with staged credentials creates fabric")
    func commitWithCredentials() throws {
        let state = CommissioningState()
        state.armFailSafe(expiresAt: Date().addingTimeInterval(60))

        // Generate an operational key
        let nonce = Data(repeating: 0x01, count: 32)
        _ = state.generateOperationalKey(csrNonce: nonce)

        // Generate test certificates
        let (testFabric, _) = try FabricInfo.generateTestFabric()
        state.stagedRCAC = testFabric.rcac.tlvEncode()
        state.stagedNOC = testFabric.noc.tlvEncode()
        state.stagedIPK = Data(repeating: 0, count: 16)
        state.stagedCaseAdminSubject = 12345
        state.stagedAdminVendorId = 0xFFF1

        var committedFabric: CommittedFabric?
        state.onCommissioningComplete = { fabric in
            committedFabric = fabric
        }

        state.commitCommissioning()

        #expect(!state.isFailSafeArmed)
        #expect(state.fabrics.count == 1)
        #expect(committedFabric != nil)
        #expect(committedFabric?.fabricIndex.rawValue == 1)
    }

    @Test("Disarm clears staged state")
    func disarmClearsStagedState() {
        let state = CommissioningState()
        state.armFailSafe(expiresAt: Date().addingTimeInterval(60))
        state.stagedRCAC = Data([0x01])
        state.stagedNOC = Data([0x02])
        state.stagedIPK = Data([0x03])

        state.disarmFailSafe()

        #expect(state.stagedRCAC == nil)
        #expect(state.stagedNOC == nil)
        #expect(state.stagedIPK == nil)
    }

    // MARK: - Window State

    @Test("Open basic window sets state and expiry")
    func openBasicWindow() {
        let state = CommissioningState()
        let baseDate = Date(timeIntervalSinceReferenceDate: 0)

        state.openBasicWindow(timeout: 300, fabricIndex: FabricIndex(rawValue: 1), vendorId: 0x1234, now: baseDate)

        #expect(state.windowStatus == .basicWindowOpen)
        #expect(state.isWindowOpen)
        #expect(state.windowExpiry == baseDate.addingTimeInterval(300))
        #expect(state.windowAdminFabricIndex == FabricIndex(rawValue: 1))
        #expect(state.windowAdminVendorId == 0x1234)
    }

    @Test("Close window clears all window state")
    func closeWindow() {
        let state = CommissioningState()
        state.openBasicWindow(timeout: 300, fabricIndex: FabricIndex(rawValue: 1), vendorId: 0x1234)

        state.closeWindow()

        #expect(state.windowStatus == .notOpen)
        #expect(!state.isWindowOpen)
        #expect(state.windowExpiry == nil)
        #expect(state.windowAdminFabricIndex == nil)
        #expect(state.windowAdminVendorId == nil)
    }

    @Test("Window expiry check closes expired window")
    func windowExpiry() {
        let state = CommissioningState()
        let baseDate = Date(timeIntervalSinceReferenceDate: 0)
        state.openBasicWindow(timeout: 300, now: baseDate)

        // Not expired yet
        let notExpired = state.checkWindowExpiry(now: baseDate.addingTimeInterval(200))
        #expect(!notExpired)
        #expect(state.isWindowOpen)

        // Expired
        let expired = state.checkWindowExpiry(now: baseDate.addingTimeInterval(301))
        #expect(expired)
        #expect(!state.isWindowOpen)
    }

    @Test("Window expiry returns false when no window open")
    func windowExpiryNoWindow() {
        let state = CommissioningState()
        let expired = state.checkWindowExpiry()
        #expect(!expired)
    }

    @Test("onWindowOpened and onWindowClosed callbacks fire")
    func windowCallbacks() {
        let state = CommissioningState()
        var openedCount = 0
        var closedCount = 0

        state.onWindowOpened = { openedCount += 1 }
        state.onWindowClosed = { closedCount += 1 }

        state.openBasicWindow(timeout: 300)
        #expect(openedCount == 1)
        #expect(closedCount == 0)

        state.closeWindow()
        #expect(openedCount == 1)
        #expect(closedCount == 1)
    }

    // MARK: - Fabric Removal

    @Test("Remove fabric succeeds for existing fabric")
    func removeFabricSucceeds() throws {
        let state = CommissioningState()
        state.armFailSafe(expiresAt: Date().addingTimeInterval(60))

        // Stage and commit a fabric
        let (testFabric, _) = try FabricInfo.generateTestFabric()
        _ = state.generateOperationalKey(csrNonce: Data(repeating: 0x01, count: 32))
        state.stagedRCAC = testFabric.rcac.tlvEncode()
        state.stagedNOC = testFabric.noc.tlvEncode()
        state.stagedIPK = Data(repeating: 0, count: 16)
        state.stagedCaseAdminSubject = 100
        state.stagedAdminVendorId = 0xFFF1
        state.commitCommissioning()

        #expect(state.fabrics.count == 1)
        let fabricIndex = state.fabrics.keys.first!

        var removedIndex: FabricIndex?
        state.onFabricRemoved = { idx in removedIndex = idx }

        let removed = state.removeFabric(fabricIndex)
        #expect(removed)
        #expect(state.fabrics.isEmpty)
        #expect(removedIndex == fabricIndex)
    }

    @Test("Remove fabric fails for non-existent index")
    func removeFabricFails() {
        let state = CommissioningState()
        let removed = state.removeFabric(FabricIndex(rawValue: 99))
        #expect(!removed)
    }

    @Test("Remove fabric clears ACLs for that fabric")
    func removeFabricClearsACLs() throws {
        let state = CommissioningState()
        state.armFailSafe(expiresAt: Date().addingTimeInterval(60))

        let (testFabric, _) = try FabricInfo.generateTestFabric()
        _ = state.generateOperationalKey(csrNonce: Data(repeating: 0x01, count: 32))
        state.stagedRCAC = testFabric.rcac.tlvEncode()
        state.stagedNOC = testFabric.noc.tlvEncode()
        state.stagedIPK = Data(repeating: 0, count: 16)
        state.stagedACLs = [
            AccessControlCluster.AccessControlEntry(
                privilege: .administer,
                authMode: .case,
                subjects: [100],
                targets: nil,
                fabricIndex: FabricIndex(rawValue: 1)
            )
        ]
        state.commitCommissioning()

        let fabricIndex = state.fabrics.keys.first!
        #expect(state.committedACLs[fabricIndex]?.count == 1)

        _ = state.removeFabric(fabricIndex)
        #expect(state.committedACLs[fabricIndex] == nil)
    }
}

// MARK: - MatterBridge Root Endpoint Tests

@Suite("MatterBridge Root Endpoint")
struct MatterBridgeRootEndpointTests {

    @Test("Root endpoint includes all commissioning clusters")
    func rootEndpointClusters() {
        let bridge = MatterBridge()

        let ep0 = EndpointID(rawValue: 0)
        let store = bridge.store

        // BasicInformation attributes should exist
        let vendorName = store.get(endpoint: ep0, cluster: .basicInformation, attribute: BasicInformationCluster.Attribute.vendorName)
        #expect(vendorName?.stringValue == "MatterSwift")

        // GeneralCommissioning attributes should exist
        let breadcrumb = store.get(endpoint: ep0, cluster: .generalCommissioning, attribute: GeneralCommissioningCluster.Attribute.breadcrumb)
        #expect(breadcrumb?.uintValue == 0)

        // OperationalCredentials attributes should exist
        let supportedFabrics = store.get(endpoint: ep0, cluster: .operationalCredentials, attribute: OperationalCredentialsCluster.Attribute.supportedFabrics)
        #expect(supportedFabrics?.uintValue == 5)

        // AccessControl attributes should exist
        let subjectsPerACE = store.get(endpoint: ep0, cluster: .accessControl, attribute: AccessControlCluster.Attribute.subjectsPerAccessControlEntry)
        #expect(subjectsPerACE?.uintValue == 4)

        // AdminCommissioning attributes should exist
        let windowStatus = store.get(endpoint: ep0, cluster: .adminCommissioning, attribute: AdminCommissioningHandler.Attribute.windowStatus)
        #expect(windowStatus?.uintValue == 0)  // notOpen — device starts with window closed
    }

    @Test("Bridge passes config to BasicInformation handler")
    func bridgeConfigPropagation() {
        let bridge = MatterBridge(config: .init(
            vendorName: "TestVendor",
            productName: "Hub",
            vendorId: 0x1234,
            productId: 0x5678
        ))

        let ep0 = EndpointID(rawValue: 0)
        let vendorName = bridge.store.get(endpoint: ep0, cluster: .basicInformation, attribute: BasicInformationCluster.Attribute.vendorName)
        #expect(vendorName?.stringValue == "TestVendor")

        let productName = bridge.store.get(endpoint: ep0, cluster: .basicInformation, attribute: BasicInformationCluster.Attribute.productName)
        #expect(productName?.stringValue == "Hub")
    }
}
