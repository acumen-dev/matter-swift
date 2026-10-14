// ChipDeviceAttestationTests.swift
// Copyright 2026 Monagle Pty Ltd
//
// Device attestation against connectedhomeip's chip-all-clusters-app, which presents a
// development DAC/PAI under the "Matter Test PAA" (measured by ChipAttestationMeasurementTests):
// untrusted by the production roots, verified by TestAttestation.chipDevelopmentTrustStore().
// Skips silently when the app has not been built (make ref-setup-app).

#if canImport(Network)
import Testing
import Foundation
import Crypto
import MatterTypes
import MatterModel
import MatterCrypto
import MatterProtocol
import MatterTransport
import MatterTestSupport
@testable import MatterController

// MARK: - ChipDeviceAttestationTests

@Suite("CHIP device attestation through commissioning", .serialized)
struct ChipDeviceAttestationTests {

    static let passcode: UInt32 = 20202021
    /// What the app's DAC carries (measured).
    static let appVendorID: UInt16 = 0xFFF1
    static let appProductID: UInt16 = 0x8001
    static let endpoint = EndpointID(rawValue: 1)

    private struct Failure: Error, CustomStringConvertible {
        let description: String
    }

    // MARK: - (a) Production roots, then approval

    @Test("Against the production roots the app fails attestation; approving its fingerprint commissions it as overridden", .timeLimit(.minutes(5)))
    func productionRootsRejectThenApprove() async throws {
        guard ChipAppRunner.findBinary() != nil else { return }
        try await withChipApp(trustStore: try AttestationTrustStore.bundledProduction()) { app, controller in
            let address = MatterAddress(host: "127.0.0.1", port: app.port)

            let failure: AttestationFailure
            do {
                _ = try await controller.commission(address: address, setupCode: Self.passcode, mrp: nil)
                throw Failure(description: "commission should have failed attestation")
            } catch ControllerError.attestationFailed(let caught) {
                failure = caught
            }
            #expect(failure.reason == .untrustedRoot)
            #expect(failure.dacPublicKey != nil)
            #expect(failure.dacVendorID == Self.appVendorID && failure.dacProductID == Self.appProductID)
            let fingerprint = try #require(failure.dacFingerprint)

            // The app re-listens for PASE synchronously while handling ArmFailSafe(0), and the
            // controller awaits that disarm response before throwing, so the app is commissionable
            // again by the time the failure arrives and the retry needs no wait.
            let device = try await controller.commission(
                address: address, setupCode: Self.passcode, mrp: nil, approvingUnverifiedDevice: fingerprint)

            guard case .overridden(let approved, let reason, _) = device.attestation else {
                throw Failure(description: "expected an overridden attestation record, got \(String(describing: device.attestation))")
            }
            #expect(approved == fingerprint && reason == .untrustedRoot)
            // From Basic Information (the app's DAC names the same pair; Basic Information is the source).
            #expect(device.vendorID == VendorID(rawValue: Self.appVendorID))
            #expect(device.productID == ProductID(rawValue: Self.appProductID))

            let value = try await controller.readAttribute(
                nodeID: device.nodeID, endpointID: Self.endpoint, clusterID: .onOff,
                attributeID: OnOffCluster.Attribute.onOff)
            #expect(value.boolValue != nil, "OnOff reads as a bool over the CASE session: \(value)")
        }
    }

    // MARK: - (b) Development roots

    @Test("Against the CHIP development roots the app commissions as verified, with its VID/PID", .timeLimit(.minutes(5)))
    func developmentRootsVerify() async throws {
        guard ChipAppRunner.findBinary() != nil else { return }
        try await withChipApp(trustStore: try TestAttestation.chipDevelopmentTrustStore()) { app, controller in
            let device = try await controller.commission(
                address: MatterAddress(host: "127.0.0.1", port: app.port), setupCode: Self.passcode, mrp: nil)
            guard case .verified(let paaSubject, let vendorID, let productID) = device.attestation else {
                throw Failure(description: "expected a verified attestation record, got \(String(describing: device.attestation))")
            }
            #expect(vendorID == Self.appVendorID && productID == Self.appProductID)
            #expect(paaSubject.contains("Matter Test PAA"), "PAA subject: \(paaSubject)")
            #expect(device.vendorID == VendorID(rawValue: Self.appVendorID))
            #expect(device.productID == ProductID(rawValue: Self.appProductID))
        }
    }

    // MARK: - Helpers

    /// Start the app (fresh KVS, free port) and a controller trusting `trustStore`, run `body`,
    /// then stop the controller, the transport and the app on every path. A failure is recorded
    /// with the app's log.
    private func withChipApp(
        trustStore: AttestationTrustStore,
        _ body: (_ app: ChipAppRunner, _ controller: MatterController) async throws -> Void
    ) async throws {
        let kvs = FileManager.default.temporaryDirectory.appendingPathComponent("chip-kvs-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: kvs) }

        let port = freeUDPPort()
        try #require(port != 0, "a free port for the app")
        let app = try await ChipAppRunner.start(passcode: Self.passcode, port: port, kvsPath: kvs)
        let transport = LoopbackTransport()
        let controller: MatterController
        do {
            try await transport.bind(port: 0)
            controller = try MatterController(
                transport: transport,
                discovery: StubDiscovery(),
                configuration: .init(
                    fabricID: FabricID(rawValue: 1), rootKey: P256.Signing.PrivateKey(), mrp: .default,
                    attestationTrustStore: trustStore))
        } catch {
            await transport.close()
            await app.stop()
            throw error
        }

        var failure: (any Error)?
        do {
            try await body(app, controller)
        } catch {
            failure = error
        }
        await controller.stop()
        await transport.close()
        await app.stop()
        if let failure {
            Issue.record("\(failure)\n--- app log ---\n\(app.log)")
        }
    }
}
#endif
