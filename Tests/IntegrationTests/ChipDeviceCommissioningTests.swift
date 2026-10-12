// ChipDeviceCommissioningTests.swift
// Copyright 2026 Monagle Pty Ltd
//
// Commissions connectedhomeip's chip-all-clusters-app with our controller:
// the first time the controller meets a real CHIP SDK device.
// Skips silently when the app has not been built (make ref-setup-app).

#if canImport(Network)
import Testing
import Foundation
import Crypto
import MatterTypes
import MatterModel
import MatterTransport
import MatterController

// MARK: - ChipDeviceCommissioningTests

@Suite("CHIP device commissioning", .serialized)
struct ChipDeviceCommissioningTests {

    @Test("Our controller commissions chip-all-clusters-app", .timeLimit(.minutes(3)))
    func commissionChipApp() async throws {
        guard ChipAppRunner.findBinary() != nil else { return }   // skip when not built
        let kvs = FileManager.default.temporaryDirectory.appendingPathComponent("chip-kvs-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: kvs) }

        let app = try await ChipAppRunner.start(passcode: 20202021, port: freeUDPPort(), kvsPath: kvs)
        let transport = LoopbackTransport()
        try await transport.bind(port: 0)
        let controller = try MatterController(
            transport: transport,
            discovery: StubDiscovery(),
            configuration: .init(
                fabricID: FabricID(rawValue: 1),
                rootKey: P256.Signing.PrivateKey()
            )
        )

        // The device's OnOff on endpoint 1, read over the session
        // commissioning left behind: proof the CASE session is live.
        let result: Result<(CommissionedDevice, TLVElement), any Error>
        do {
            let device = try await controller.commission(
                address: MatterAddress(host: "127.0.0.1", port: app.port),
                setupCode: 20202021,
                mrp: nil
            )
            let onOff = try await controller.readAttribute(
                nodeID: device.nodeID,
                endpointID: EndpointID(rawValue: 1),
                clusterID: .onOff,
                attributeID: OnOffCluster.Attribute.onOff
            )
            result = .success((device, onOff))
        } catch {
            result = .failure(error)
        }

        await controller.stop()
        await transport.close()
        await app.stop()

        switch result {
        case .success(let (device, onOff)):
            #expect(device.nodeID.rawValue > 0)
            let registered = await controller.device(for: device.nodeID)
            #expect(registered?.nodeID == device.nodeID, "commissioned device is not registered")
            #expect(onOff.boolValue != nil, "OnOff read over the commissioning CASE session")
            #expect(app.log.contains("Commissioning completed successfully"), "the device committed the fabric")
            // One CASE handshake: CommissioningComplete's, reused for the read.
            #expect(app.log.components(separatedBy: "Received Sigma1 msg").count - 1 == 1)
        case .failure(let error):
            Issue.record("commissioning chip-all-clusters-app failed: \(error)\n--- app log ---\n\(app.log)")
        }
    }
}
#endif
