// AttestationCommissioningTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import Crypto
import MatterTypes
import MatterModel
import MatterCrypto
import MatterTransport
@testable import MatterController
import MatterDevice
import MatterTestSupport

/// Commissioning verifies the device's attestation before anything is committed on it:
/// a device that fails is left untouched (fail-safe disarmed, no fabric, no node ID used),
/// and a retry may approve exactly that DAC. Controller ↔ MatterDeviceServer over an
/// in-memory link.
@Suite("Commissioning verifies device attestation", .serialized, .timeLimit(.minutes(5)))
struct AttestationCommissioningTests {

    /// Not the device server's defaults (0xFFF1/0x8000) nor the controller's own vendor
    /// (`VendorID.test`, 0xFFF1), so the recorded identifiers can only have come from the DAC.
    static let vendorID: UInt16 = 0xFFF2
    static let productID: UInt16 = 0x8001

    /// A device whose Basic Information, commissionable TXT and attestation credentials all
    /// name `vendorID`/`productID`.
    struct Rig {
        let link: FaultInjectingLink
        let bridge: MatterBridge
        let server: MatterDeviceServer
        let controller: MatterController
        let store: InMemoryControllerStore

        var state: CommissioningState { bridge.commissioningState }

        func stop() async {
            await controller.stop()
            await server.stop()
        }
    }

    static func makeRig(
        seed: UInt64,
        credentials: DeviceAttestationCredentials,
        trustStore: AttestationTrustStore
    ) async throws -> Rig {
        let link = FaultInjectingLink(seed: seed)
        let bridge = MatterBridge(config: .init(vendorId: vendorID, productId: productID))
        _ = bridge.addDimmableLight(name: "Attested Light", onOffChanged: { _ in })
        bridge.commissioningState.attestationCredentials = credentials
        let server = MatterDeviceServer(
            bridge: bridge,
            transport: link.b,
            discovery: FaultyLinkDiscovery(),
            config: .init(
                discriminator: 3840, passcode: passcode, port: 5540,
                vendorId: vendorID, productId: productID,
                salt: Data(repeating: 0xAB, count: 32), iterations: 1000
            )
        )
        try await server.start()
        let store = InMemoryControllerStore()
        let controller = try makeController(on: link, maxRetransmissions: 10, store: store, trustStore: trustStore)
        return Rig(link: link, bridge: bridge, server: server, controller: controller, store: store)
    }

    static func credentials() throws -> DeviceAttestationCredentials {
        try DeviceAttestationCredentials.testCredentials(vendorID: vendorID, productID: productID)
    }

    /// Runs `body`, then stops the rig whether or not it threw.
    static func withRig(
        seed: UInt64,
        credentials: DeviceAttestationCredentials,
        trustStore: AttestationTrustStore,
        _ body: (Rig) async throws -> Void
    ) async throws {
        let rig = try await makeRig(seed: seed, credentials: credentials, trustStore: trustStore)
        do {
            try await body(rig)
        } catch {
            await rig.stop()
            throw error
        }
        await rig.stop()
    }

    /// Commissions and expects `attestationFailed`; returns the failure.
    static func expectAttestationFailure(
        _ rig: Rig, approving: Data? = nil, sourceLocation: SourceLocation = #_sourceLocation
    ) async throws -> AttestationFailure {
        do {
            _ = try await rig.controller.commission(
                address: rig.link.b.address, setupCode: passcode, mrp: fast, approvingUnverifiedDevice: approving)
        } catch ControllerError.attestationFailed(let failure) {
            return failure
        }
        Issue.record("commission should have failed attestation", sourceLocation: sourceLocation)
        throw Unexpected()
    }

    struct Unexpected: Error {}

    /// The device was left as it was found: the fail-safe disarmed by the controller (not by
    /// its own expiry), no fabric, nothing staged, no session, no node ID consumed, nothing
    /// registered.
    static func expectUntouched(
        _ rig: Rig, nextNodeID expected: UInt64, armedAfter start: Date,
        sourceLocation: SourceLocation = #_sourceLocation
    ) async throws {
        let disarmed = try await CommissioningFailureTests.disarmedBeforeExpiry(rig.state, armedAfter: start)
        #expect(disarmed, "the device's fail-safe must be disarmed without waiting for its expiry",
                sourceLocation: sourceLocation)
        #expect(rig.state.fabrics.isEmpty, "no fabric may be added", sourceLocation: sourceLocation)
        #expect(rig.state.stagedNOC == nil && rig.state.stagedRCAC == nil, sourceLocation: sourceLocation)
        #expect(await rig.controller.messenger.registeredSessionIDs.isEmpty, sourceLocation: sourceLocation)
        #expect(await rig.controller.nextNodeID == expected, "a failed commissioning must not consume a node ID",
                sourceLocation: sourceLocation)
        #expect(await rig.controller.allDevices().isEmpty, sourceLocation: sourceLocation)
    }

    // MARK: - (a) Trusted

    @Test("A device whose chain the trust store holds is commissioned and recorded as verified, with the DAC's VID/PID")
    func trustedDeviceVerifies() async throws {
        let creds = try Self.credentials()
        try await Self.withRig(seed: 91, credentials: creds, trustStore: try TestAttestation.trustStore(for: creds)) { rig in
            // The device's Basic Information agrees with its CD (Ruling 35).
            #expect(rig.bridge.store.get(endpoint: .root, cluster: BasicInformationCluster.id,
                                         attribute: BasicInformationCluster.Attribute.vendorID)?.uintValue == UInt64(Self.vendorID))
            #expect(rig.bridge.store.get(endpoint: .root, cluster: BasicInformationCluster.id,
                                         attribute: BasicInformationCluster.Attribute.productID)?.uintValue == UInt64(Self.productID))

            let device = try await rig.controller.commission(address: rig.link.b.address, setupCode: passcode, mrp: fast)

            guard case .verified(let paaSubject, let vid, let pid) = device.attestation else {
                Issue.record("expected a verified attestation record, got \(String(describing: device.attestation))")
                return
            }
            #expect(vid == Self.vendorID && pid == Self.productID)
            #expect(paaSubject.contains("Matter Test PAA"))
            #expect(device.vendorID == VendorID(rawValue: Self.vendorID))
            #expect(device.productID == ProductID(rawValue: Self.productID))
            #expect(await rig.controller.device(for: device.nodeID) == device)

            let stored = try #require(try await rig.store.load()?.devices.first { $0.nodeID == device.nodeID.rawValue })
            #expect(stored.attestation == .verified(paaSubject: paaSubject, vendorID: Self.vendorID, productID: Self.productID))
            #expect(stored.vendorID == Self.vendorID && stored.productID == Self.productID)
        }
    }

    // MARK: - (b) Untrusted

    @Test("A device whose PAA is not trusted fails attestation, untouched: disarmed, no fabric, no node ID")
    func untrustedRootFails() async throws {
        let creds = try Self.credentials()
        try await Self.withRig(seed: 92, credentials: creds, trustStore: try AttestationTrustStore.bundledProduction()) { rig in
            let expectedNodeID = await rig.controller.nextNodeID
            let start = Date()
            let failure = try await Self.expectAttestationFailure(rig)
            #expect(failure.reason == .untrustedRoot)
            #expect(failure.dacFingerprint == Data(SHA256.hash(data: creds.dacCertificate)))
            try await Self.expectUntouched(rig, nextNodeID: expectedNodeID, armedAfter: start)
        }
    }

    // MARK: - (c) Approved retry

    @Test("A retry approving the failed DAC's fingerprint commissions it, recorded as overridden")
    func approvedRetrySucceeds() async throws {
        let creds = try Self.credentials()
        try await Self.withRig(seed: 93, credentials: creds, trustStore: try AttestationTrustStore.bundledProduction()) { rig in
            let expectedNodeID = await rig.controller.nextNodeID
            let start = Date()
            let failure = try await Self.expectAttestationFailure(rig)
            try await Self.expectUntouched(rig, nextNodeID: expectedNodeID, armedAfter: start)
            let fingerprint = try #require(failure.dacFingerprint)

            await rig.server.openCommissioningWindow(timeout: 180)
            let before = Date()
            let device = try await rig.controller.commission(
                address: rig.link.b.address, setupCode: passcode, mrp: fast, approvingUnverifiedDevice: fingerprint)
            let after = Date()

            guard case .overridden(let approvedFingerprint, let reason, let approvedAt) = device.attestation else {
                Issue.record("expected an overridden attestation record, got \(String(describing: device.attestation))")
                return
            }
            #expect(approvedFingerprint == fingerprint)
            #expect(reason == .untrustedRoot)
            #expect(approvedAt >= before && approvedAt <= after)
            #expect(device.nodeID.rawValue == expectedNodeID)
            #expect(device.vendorID == VendorID(rawValue: Self.vendorID))
            #expect(device.productID == ProductID(rawValue: Self.productID))
            #expect(!rig.state.fabrics.isEmpty)

            let stored = try #require(try await rig.store.load()?.devices.first { $0.nodeID == device.nodeID.rawValue })
            #expect(stored.attestation == .overridden(
                dacFingerprint: fingerprint, reason: AttestationFailureReason.untrustedRoot.rawValue, approvedAt: approvedAt))
        }
    }

    // MARK: - (d) Approval of another DAC

    @Test("A retry approving a different fingerprint still fails attestation")
    func otherFingerprintFails() async throws {
        let creds = try Self.credentials()
        try await Self.withRig(seed: 94, credentials: creds, trustStore: try AttestationTrustStore.bundledProduction()) { rig in
            let expectedNodeID = await rig.controller.nextNodeID
            let first = try await Self.expectAttestationFailure(rig)
            try await pollUntil { !rig.state.isFailSafeArmed }
            var other = try #require(first.dacFingerprint)
            other[other.startIndex] ^= 0x01

            await rig.server.openCommissioningWindow(timeout: 180)
            let start = Date()
            let second = try await Self.expectAttestationFailure(rig, approving: other)
            #expect(second == first)
            try await Self.expectUntouched(rig, nextNodeID: expectedNodeID, armedAfter: start)
        }
    }

    // MARK: - (e) CSR not signed by the DAC

    /// The device holds a key that is not its DAC's: the AttestationResponse and the
    /// CSRResponse are both signed with it. Attestation fails; approving that DAC does not skip
    /// the CSR's attestation signature check, which fails against the DAC key.
    @Test("A device that cannot sign with its DAC key fails at the CSR, even when its DAC is approved")
    func csrSignedByAnotherKeyFails() async throws {
        let genuine = try Self.credentials()
        let impostor = DeviceAttestationCredentials(
            dacCertificate: genuine.dacCertificate,
            dacPrivateKey: P256.Signing.PrivateKey(),
            paiCertificate: genuine.paiCertificate,
            paaCertificate: genuine.paaCertificate,
            certificationDeclaration: genuine.certificationDeclaration,
            cdSigningCertificate: genuine.cdSigningCertificate
        )
        try await Self.withRig(seed: 95, credentials: impostor, trustStore: try TestAttestation.trustStore(for: genuine)) { rig in
            let expectedNodeID = await rig.controller.nextNodeID
            let failure = try await Self.expectAttestationFailure(rig)
            #expect(failure.reason == .attestationSignatureInvalid)
            try await pollUntil { !rig.state.isFailSafeArmed }
            let fingerprint = try #require(failure.dacFingerprint)

            await rig.server.openCommissioningWindow(timeout: 180)
            let start = Date()
            await #expect(throws: ControllerError.commissioningFailed("CSR attestation signature invalid")) {
                _ = try await rig.controller.commission(
                    address: rig.link.b.address, setupCode: passcode, mrp: fast, approvingUnverifiedDevice: fingerprint)
            }
            try await Self.expectUntouched(rig, nextNodeID: expectedNodeID, armedAfter: start)
        }
    }

    // MARK: - Malformed

    @Test("A malformed attestation cannot be approved, even by the DAC's own fingerprint")
    func malformedCannotBeApproved() async throws {
        let genuine = try Self.credentials()
        // The PAI is not a certificate: the verifier fails `.malformed`, with the DAC's fingerprint.
        let broken = DeviceAttestationCredentials(
            dacCertificate: genuine.dacCertificate,
            dacPrivateKey: genuine.dacPrivateKey,
            paiCertificate: Data([0x30, 0x00]),
            paaCertificate: genuine.paaCertificate,
            certificationDeclaration: genuine.certificationDeclaration,
            cdSigningCertificate: genuine.cdSigningCertificate
        )
        let fingerprint = Data(SHA256.hash(data: genuine.dacCertificate))
        try await Self.withRig(seed: 96, credentials: broken, trustStore: try TestAttestation.trustStore(for: genuine)) { rig in
            let expectedNodeID = await rig.controller.nextNodeID
            let start = Date()
            let failure = try await Self.expectAttestationFailure(rig, approving: fingerprint)
            #expect(failure.reason == .malformed)
            #expect(failure.dacFingerprint == fingerprint)
            try await Self.expectUntouched(rig, nextNodeID: expectedNodeID, armedAfter: start)
        }
    }

    // MARK: - Basic Information read failure (Ruling 35)

    @Test("A Basic Information VendorID that cannot be read fails commissioning, untouched")
    func basicInformationReadFailure() async throws {
        let creds = try Self.credentials()
        try await Self.withRig(seed: 97, credentials: creds, trustStore: try TestAttestation.trustStore(for: creds)) { rig in
            // Not an unsigned integer: the controller cannot read a VendorID from it.
            rig.bridge.store.set(endpoint: .root, cluster: BasicInformationCluster.id,
                                 attribute: BasicInformationCluster.Attribute.vendorID, value: .utf8String("not a vendor"))
            let expectedNodeID = await rig.controller.nextNodeID
            let start = Date()
            do {
                _ = try await rig.controller.commission(address: rig.link.b.address, setupCode: passcode, mrp: fast)
                Issue.record("commission should have failed reading Basic Information")
            } catch ControllerError.commissioningFailed(let message) {
                #expect(message.hasPrefix("Basic Information VendorID"), "got \(message)")
            }
            try await Self.expectUntouched(rig, nextNodeID: expectedNodeID, armedAfter: start)
        }
    }
}
