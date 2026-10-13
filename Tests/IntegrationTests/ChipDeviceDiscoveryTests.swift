// ChipDeviceDiscoveryTests.swift
// Copyright 2026 Monagle Pty Ltd
//
// Our controller finds connectedhomeip's chip-all-clusters-app over real
// mDNS: commissions it from the setup codes the app prints, and follows it
// when it restarts on a new port.
// Skips silently when the app has not been built (make ref-setup-app).
//
// Each test starts the app with a random discriminator (never 3840) so it
// does not match another commissionable device on the network.

#if canImport(Network)
import Testing
import Foundation
import Crypto
import MatterTypes
import MatterModel
import MatterProtocol
import MatterTransport
import MatterApple
@testable import MatterController
import MatterTestSupport

// MARK: - ChipDeviceDiscoveryTests

@Suite("CHIP device discovery", .serialized)
struct ChipDeviceDiscoveryTests {

    /// Hang guard per awaited outcome. Not a timing assertion.
    static let hangGuard: Duration = .seconds(30)
    static let passcode: UInt32 = 20202021
    /// chip-all-clusters-app's light (OnOff) endpoint.
    static let endpoint = EndpointID(rawValue: 1)
    /// Bounds the CASE attempt at the dead port in the move test.
    static let controllerMRP = MRPConfig(maxRetransmissions: 2)
    static let discoveryTimeout: Duration = .seconds(30)

    /// Short discriminators (the top four bits, all a manual code carries)
    /// of the commissionable devices other suites advertise over real mDNS,
    /// with the same passcode, possibly while these tests run: 840
    /// (ChipToolIntegrationTests) → 3, 1234 (AppleDiscoveryTests) → 4, and
    /// 3840 (the CHIP default; device-server and loopback tests) → 15.
    /// Measured: a manual code whose short discriminator was 3 found
    /// ChipToolIntegrationTests' device first, as the spec allows.
    static let shortDiscriminatorsInUse: Set<UInt16> = [3, 4, 15]

    /// Short discriminators this process's apps have used. An app that has
    /// just stopped can still be browsed for a moment (measured: the next
    /// test's manual code found the previous app's record and ran PASE
    /// against its closed port), so each app gets a short form of its own.
    static let usedShortDiscriminators = LockedValue<Set<UInt16>>([])

    /// A random discriminator in 1...4094 whose short form no other suite's
    /// device shares and no earlier app in this process used; never 3840.
    static func randomDiscriminator() -> UInt16 {
        usedShortDiscriminators.withLock { used in
            let available = Set<UInt16>(0...15).subtracting(shortDiscriminatorsInUse)
            if used.isSuperset(of: available) { used.removeAll() }
            var value: UInt16
            repeat {
                value = .random(in: 1...4094)
            } while shortDiscriminatorsInUse.contains(value >> 8) || used.contains(value >> 8)
            used.insert(value >> 8)
            return value
        }
    }

    struct HangGuardExpired: Error, CustomStringConvertible {
        let what: String
        var description: String { "hang guard expired: \(what)" }
    }

    // MARK: - Step 1: manual code

    @Test("Commissions the app from its printed manual pairing code, found over mDNS", .timeLimit(.minutes(3)))
    func commissionFromManualCode() async throws {
        guard ChipAppRunner.findBinary() != nil else { return }   // skip when not built
        try await withChipApp { app, controller in
            let code = try #require(app.manualPairingCode, "the app printed a manual pairing code")
            try await commissionAndRead(code, app: app, controller: controller)
        }
    }

    // MARK: - Step 2: QR code

    @Test("Commissions the app from its printed QR code, found over mDNS", .timeLimit(.minutes(3)))
    func commissionFromQRCode() async throws {
        guard ChipAppRunner.findBinary() != nil else { return }
        try await withChipApp { app, controller in
            let code = try #require(app.qrCode, "the app printed a QR code")
            try await commissionAndRead(code, app: app, controller: controller)
        }
    }

    // MARK: - Step 3: the device moves

    /// Distinct from anything the app advertises, close enough to its timing
    /// that the commissioning flow is unaffected. Replaced by the operational
    /// TXT when the address refresh moves the node.
    static let overrideMRP = MRPParameters(
        sessionIdleInterval: .milliseconds(510),
        sessionActiveInterval: .milliseconds(310),
        sessionActiveThreshold: .milliseconds(4010)
    )

    @Test("After the app restarts on a new port, CASE re-resolves it and the read succeeds", .timeLimit(.minutes(5)))
    func followsDeviceToNewPort() async throws {
        guard ChipAppRunner.findBinary() != nil else { return }
        try await withChipApp { app, controller in
            let code = try #require(app.manualPairingCode, "the app printed a manual pairing code")
            let device = try await Self.guarded("commissioning", Self.discoveryTimeout + Self.hangGuard) {
                try await controller.commission(setupCode: code, mrp: Self.overrideMRP)
            }
            #expect(await controller.device(for: device.nodeID)?.mrpParameters == Self.overrideMRP)
            _ = try await readOnOff(device.nodeID, with: controller)
            #expect(await controller.device(for: device.nodeID)?.operationalAddress?.port == app.port)

            // Same KVS, new port: the fabric survives; `_matter._tcp` names the new port.
            await app.stop()
            var newPort = freeUDPPort()
            while newPort == app.port { newPort = freeUDPPort() }
            let restarted = try await ChipAppRunner.start(
                discriminator: app.discriminator, passcode: Self.passcode, port: newPort, kvsPath: app.kvsPath
            )
            do {
                await controller.invalidateSession(for: device.nodeID)

                // CASE to the old port exhausts its retransmissions, the
                // re-resolve (bounded by addressRefreshTimeout, itself well
                // inside discoveryTimeout) finds the new port, and CASE plus
                // the read run there.
                let deadPort = MRPConfig(
                    peer: Self.overrideMRP, maxRetransmissions: Self.controllerMRP.maxRetransmissions
                ).exhaustionHorizon(peerActive: false)
                let bound = deadPort + Self.discoveryTimeout + Self.hangGuard
                _ = try await Self.guarded("read after the move", bound) {
                    try await readOnOff(device.nodeID, with: controller)
                }

                let moved = try #require(await controller.device(for: device.nodeID))
                #expect(moved.operationalAddress?.port == restarted.port, "the registry follows the device to its new port")
                #expect(moved.mrpParameters != Self.overrideMRP, "the refresh replaced the override")
                let operational = try await Self.guarded("operational resolve", Self.discoveryTimeout + Self.hangGuard) {
                    try await controller.discoverDevice(nodeID: device.nodeID)
                }
                #expect(operational.address.port == restarted.port)
                // Measured: v1.4.0.0's operational TXT is `T` only, so the
                // timing it yields is the defaults; non-empty, so it replaces.
                let advertised = try #require(operational.mrp, "the app's operational TXT is not empty")
                #expect(moved.mrpParameters == advertised, "MRP timing came from the operational TXT")
                #expect(
                    restarted.log.components(separatedBy: "Received Sigma1 msg").count - 1 == 1,
                    "one CASE handshake, against the restarted app"
                )
            } catch {
                await restarted.stop()
                throw ChipDiscoveryFailure(error: error, context: "--- restarted app log ---\n\(restarted.log)")
            }
            await restarted.stop()
        }
    }

    // MARK: - Helpers

    /// Find the app by `code` over mDNS, check what it advertised, commission
    /// it there and read OnOff over the session commissioning left.
    private func commissionAndRead(_ code: String, app: ChipAppRunner, controller: MatterController) async throws {
        let parsed = try SetupCode(parsing: code)
        let found = try await Self.guarded("findCommissionable", Self.discoveryTimeout + Self.hangGuard) {
            try await controller.findCommissionable(parsed)
        }
        // The address came from discovery; the port is the app's.
        #expect(found.address.port == app.port, "the discovered port is the app's")
        try #require(Self.isNumericHost(found.address.host), "the resolved host is an IP literal, not a name")
        #expect(found.discriminator == app.discriminator)
        #expect(found.commissioningMode == 1, "basic commissioning window")
        // Measured: v1.4.0.0's commissionable TXT carries no SII/SAI/SAT,
        // so its MRP timing is the defaults; recorded as advertised.

        let device = try await Self.guarded("commission", Self.discoveryTimeout + Self.hangGuard) {
            try await controller.commission(setupCode: code)
        }
        _ = try await readOnOff(device.nodeID, with: controller)
        let registered = try #require(await controller.device(for: device.nodeID))
        #expect(registered.mrpParameters == found.mrp, "the stored MRP timing is the advertised one")
        #expect(registered.operationalAddress?.port == app.port)
        #expect(app.log.contains("Commissioning completed successfully"), "the device committed the fabric")
    }

    /// Whether `host` is an IPv4 or IPv6 literal (brackets allowed).
    static func isNumericHost(_ host: String) -> Bool {
        var literal = host
        if literal.hasPrefix("["), literal.hasSuffix("]") { literal = String(literal.dropFirst().dropLast()) }
        var v4 = in_addr()
        var v6 = in6_addr()
        return inet_pton(AF_INET, literal, &v4) == 1 || inet_pton(AF_INET6, literal, &v6) == 1
    }

    /// Start the app (random discriminator, fresh KVS, free port) and a
    /// controller with real mDNS over a real UDP socket, run `body`, then
    /// stop the controller, the transport and the app on every path. A
    /// failure is recorded with the app's log.
    private func withChipApp(
        _ body: (_ app: ChipAppRunner, _ controller: MatterController) async throws -> Void
    ) async throws {
        let kvs = FileManager.default.temporaryDirectory.appendingPathComponent("chip-kvs-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: kvs) }

        let app = try await ChipAppRunner.start(
            discriminator: Self.randomDiscriminator(), passcode: Self.passcode, port: freeUDPPort(), kvsPath: kvs
        )
        // Discovery finds the app at a LAN address of this host, not loopback.
        let transport = LoopbackTransport(bindAddress: INADDR_ANY)
        let controller: MatterController
        do {
            try await transport.bind(port: 0)
            controller = try MatterController(
                transport: transport,
                discovery: AppleDiscovery(),
                configuration: .init(
                    fabricID: FabricID(rawValue: 1),
                    rootKey: P256.Signing.PrivateKey(),
                    mrp: Self.controllerMRP,
                    discoveryTimeout: Self.discoveryTimeout
                )
            )
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

    private func readOnOff(_ nodeID: NodeID, with controller: MatterController) async throws -> Bool {
        let value = try await controller.readAttribute(
            nodeID: nodeID, endpointID: Self.endpoint, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff
        )
        guard let on = value.boolValue else { throw ChipDiscoveryFailure(error: nil, context: "OnOff is not a bool: \(value)") }
        return on
    }

    /// `operation`, or `HangGuardExpired` once `bound` passes.
    private static func guarded<T: Sendable>(
        _ what: String,
        _ bound: Duration,
        _ operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask { try await operation() }
            group.addTask {
                try await Task.sleep(for: bound)
                throw HangGuardExpired(what: what)
            }
            defer { group.cancelAll() }
            return try await group.next()!
        }
    }
}

// MARK: - ChipDiscoveryFailure

private struct ChipDiscoveryFailure: Error, CustomStringConvertible {
    let error: (any Error)?
    let context: String
    var description: String {
        if let error { return "\(error)\n\(context)" }
        return context
    }
}
#endif
