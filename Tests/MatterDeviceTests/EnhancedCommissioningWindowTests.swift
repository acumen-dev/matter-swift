// EnhancedCommissioningWindowTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterModel
import MatterCrypto
@testable import MatterDevice

@Suite("Enhanced Commissioning Window")
struct EnhancedCommissioningWindowTests {

    // MARK: - Helpers

    private let ep0 = EndpointID(rawValue: 0)

    /// Build a 97-byte PAKEPasscodeVerifier (W0[32] || L[65]).
    private func makeVerifierBytes() -> Data {
        let w0 = Data(repeating: 0xAA, count: 32)
        let L = Data(repeating: 0xBB, count: 65)
        return w0 + L
    }

    /// Build the TLV fields for an OpenCommissioningWindow command.
    private func makeOpenCommissioningWindowFields(
        timeout: UInt64 = 300,
        verifierData: Data? = nil,
        discriminator: UInt64 = 0x0ABC,
        iterations: UInt64 = 1000,
        salt: Data? = nil
    ) -> TLVElement {
        let vData = verifierData ?? makeVerifierBytes()
        let saltData = salt ?? Data(repeating: 0x42, count: 32)
        return .structure([
            .init(tag: .contextSpecific(0), value: .unsignedInt(timeout)),
            .init(tag: .contextSpecific(1), value: .octetString(vData)),
            .init(tag: .contextSpecific(2), value: .unsignedInt(discriminator)),
            .init(tag: .contextSpecific(3), value: .unsignedInt(iterations)),
            .init(tag: .contextSpecific(4), value: .octetString(saltData)),
        ])
    }

    // MARK: - Test 1: OpenCommissioningWindow stores injected verifier

    @Test("OpenCommissioningWindow stores injected PAKE verifier in CommissioningState")
    func openCommissioningWindowStoresVerifier() throws {
        let state = CommissioningState()
        let handler = AdminCommissioningHandler(commissioningState: state)
        let store = AttributeStore()
        for (attr, value) in handler.initialAttributes() {
            store.set(endpoint: ep0, cluster: handler.clusterID, attribute: attr, value: value)
        }

        let verifierBytes = makeVerifierBytes()
        let discriminator: UInt64 = 0x0DEF
        let iterations: UInt64 = 2000
        let saltData = Data(repeating: 0x7F, count: 16)

        let fields = makeOpenCommissioningWindowFields(
            timeout: 300,
            verifierData: verifierBytes,
            discriminator: discriminator,
            iterations: iterations,
            salt: saltData
        )

        _ = try handler.handleCommand(
            commandID: AdminCommissioningHandler.Command.openCommissioningWindow,
            fields: fields,
            store: store,
            endpointID: ep0
        )

        // Window should now be open in enhanced mode
        #expect(state.windowStatus == .enhancedWindowOpen)
        #expect(state.isWindowOpen)
        #expect(state.windowExpiry != nil)

        // Injected verifier should be stored
        let injected = state.injectedPAKEVerifier
        #expect(injected != nil)
        #expect(injected?.w0 == Data(verifierBytes[0..<32]))
        #expect(injected?.L == Data(verifierBytes[32..<97]))
        #expect(injected?.discriminator == UInt16(discriminator & 0x0FFF))
        #expect(injected?.iterations == UInt32(iterations))
        #expect(injected?.salt == saltData)

        // WindowStatus attribute should be EnhancedWindowOpen (1)
        let statusAttr = store.get(
            endpoint: ep0,
            cluster: handler.clusterID,
            attribute: AdminCommissioningHandler.Attribute.windowStatus
        )
        #expect(statusAttr?.uintValue == 1)
    }

    // MARK: - Test 2: RevokeCommissioning clears injected verifier

    @Test("RevokeCommissioning clears the injected PAKE verifier")
    func revokeCommissioningClearsInjectedVerifier() throws {
        let state = CommissioningState()
        let handler = AdminCommissioningHandler(commissioningState: state)
        let store = AttributeStore()
        for (attr, value) in handler.initialAttributes() {
            store.set(endpoint: ep0, cluster: handler.clusterID, attribute: attr, value: value)
        }

        // Open enhanced window
        let fields = makeOpenCommissioningWindowFields()
        _ = try handler.handleCommand(
            commandID: AdminCommissioningHandler.Command.openCommissioningWindow,
            fields: fields,
            store: store,
            endpointID: ep0
        )
        #expect(state.injectedPAKEVerifier != nil)
        #expect(state.windowStatus == .enhancedWindowOpen)

        // Revoke
        _ = try handler.handleCommand(
            commandID: AdminCommissioningHandler.Command.revokeCommissioning,
            fields: nil,
            store: store,
            endpointID: ep0
        )

        // Injected verifier should be cleared
        #expect(state.injectedPAKEVerifier == nil)
        #expect(state.windowStatus == .notOpen)
        #expect(!state.isWindowOpen)

        let statusAttr = store.get(
            endpoint: ep0,
            cluster: handler.clusterID,
            attribute: AdminCommissioningHandler.Attribute.windowStatus
        )
        #expect(statusAttr?.uintValue == 0)
    }

    // MARK: - Test 3: Window expiry clears injected verifier

    @Test("Commissioning window expiry clears the injected PAKE verifier")
    func windowExpiryClearsInjectedVerifier() throws {
        let state = CommissioningState()

        // Open enhanced window directly via CommissioningState
        let injectedVerifier = InjectedPAKEVerifier(
            w0: Data(repeating: 0xAA, count: 32),
            L: Data(repeating: 0xBB, count: 65),
            discriminator: 0x0123,
            iterations: 1000,
            salt: Data(repeating: 0x42, count: 32)
        )

        let baseDate = Date(timeIntervalSinceReferenceDate: 0)
        state.openEnhancedWindow(
            timeout: 300,
            verifier: injectedVerifier,
            now: baseDate
        )

        #expect(state.windowStatus == .enhancedWindowOpen)
        #expect(state.injectedPAKEVerifier != nil)

        // Not expired yet
        let notExpired = state.checkWindowExpiry(now: baseDate.addingTimeInterval(200))
        #expect(!notExpired)
        #expect(state.injectedPAKEVerifier != nil)
        #expect(state.isWindowOpen)

        // Now expire it
        let expired = state.checkWindowExpiry(now: baseDate.addingTimeInterval(301))
        #expect(expired)
        #expect(state.injectedPAKEVerifier == nil)
        #expect(!state.isWindowOpen)
        #expect(state.windowStatus == .notOpen)
    }

    // MARK: - Additional: spake2pVerifier() helper works

    @Test("InjectedPAKEVerifier builds correct Spake2pVerifier")
    func injectedVerifierBuildsSpake2pVerifier() {
        let w0 = Data(repeating: 0x11, count: 32)
        let L = Data(repeating: 0x22, count: 65)
        let verifier = InjectedPAKEVerifier(
            w0: w0,
            L: L,
            discriminator: 100,
            iterations: 5000,
            salt: Data(repeating: 0x33, count: 16)
        )
        let spake2pVerifier = verifier.spake2pVerifier()
        #expect(spake2pVerifier.w0 == w0)
        #expect(spake2pVerifier.L == L)
    }

    // MARK: - Reject if window already open

    @Test("OpenCommissioningWindow rejects when window already open")
    func openCommissioningWindowRejectsWhenAlreadyOpen() throws {
        let state = CommissioningState()
        state.openBasicWindow(timeout: 300)

        let handler = AdminCommissioningHandler(commissioningState: state)
        let store = AttributeStore()
        for (attr, value) in handler.initialAttributes() {
            store.set(endpoint: ep0, cluster: handler.clusterID, attribute: attr, value: value)
        }

        let fields = makeOpenCommissioningWindowFields()
        let result = try handler.handleCommand(
            commandID: AdminCommissioningHandler.Command.openCommissioningWindow,
            fields: fields,
            store: store,
            endpointID: ep0
        )

        // Returns nil (busy), window stays as basic
        #expect(result == nil)
        #expect(state.windowStatus == .basicWindowOpen)
        #expect(state.injectedPAKEVerifier == nil)
    }
}
