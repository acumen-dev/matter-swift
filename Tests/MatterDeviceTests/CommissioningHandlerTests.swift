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
        nonce.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }

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
        nonce.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }

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

    @Test("Initial window status is BasicWindowOpen")
    func initialWindowStatus() {
        let handler = AdminCommissioningHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        let status = store.get(endpoint: ep0, cluster: .adminCommissioning, attribute: AdminCommissioningHandler.Attribute.windowStatus)
        #expect(status?.uintValue == 2) // BasicWindowOpen
    }

    @Test("RevokeCommissioning closes the window")
    func revokeCommissioning() throws {
        let handler = AdminCommissioningHandler()
        let store = AttributeStore()
        populateStore(store, handler: handler, endpoint: ep0)

        _ = try handler.handleCommand(
            commandID: AdminCommissioningHandler.Command.revokeCommissioning,
            fields: nil,
            store: store,
            endpointID: ep0
        )

        let status = store.get(endpoint: ep0, cluster: .adminCommissioning, attribute: AdminCommissioningHandler.Attribute.windowStatus)
        #expect(status?.uintValue == 0) // Not open
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
        #expect(vendorName?.stringValue == "SwiftMatter")

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
        #expect(windowStatus?.uintValue == 2)
    }

    @Test("Bridge passes config to BasicInformation handler")
    func bridgeConfigPropagation() {
        let bridge = MatterBridge(config: .init(
            vendorName: "Acumen",
            productName: "Hub",
            vendorId: 0x1234,
            productId: 0x5678
        ))

        let ep0 = EndpointID(rawValue: 0)
        let vendorName = bridge.store.get(endpoint: ep0, cluster: .basicInformation, attribute: BasicInformationCluster.Attribute.vendorName)
        #expect(vendorName?.stringValue == "Acumen")

        let productName = bridge.store.get(endpoint: ep0, cluster: .basicInformation, attribute: BasicInformationCluster.Attribute.productName)
        #expect(productName?.stringValue == "Hub")
    }
}
