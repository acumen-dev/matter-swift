// ChipDeviceCommissioningTests.swift
// Copyright 2026 Monagle Pty Ltd
//
// Our controller against connectedhomeip's chip-all-clusters-app: commissions
// it, controls it, subscribes to it, survives its restart, and commissions it
// as a second admin beside chip-tool.
// Skips silently when the app has not been built (make ref-setup-app).

#if canImport(Network)
import Testing
import Foundation
import Crypto
import MatterTypes
import MatterModel
import MatterProtocol
import MatterTransport
@testable import MatterController

// MARK: - ChipDeviceCommissioningTests

@Suite("CHIP device commissioning", .serialized)
struct ChipDeviceCommissioningTests {

    /// Hang guard per awaited outcome. Not a timing assertion.
    static let hangGuard: Duration = .seconds(30)
    static let passcode: UInt32 = 20202021
    /// chip-all-clusters-app's light (OnOff) and UnitTesting endpoint.
    static let endpoint = EndpointID(rawValue: 1)
    /// OperationalCredentials.Fabrics.
    static let fabricsAttribute = AttributeID(rawValue: 0x0001)
    /// The controller's MRP configuration (spec defaults), named so the
    /// restart test can derive its liveness wait from it.
    static let controllerMRP = MRPConfig.default

    @Test("Our controller commissions chip-all-clusters-app", .timeLimit(.minutes(3)))
    func commissionChipApp() async throws {
        guard ChipAppRunner.findBinary() != nil else { return }   // skip when not built
        try await withChipApp { app, controller in
            let device = try await commission(app, with: controller)
            // The device's OnOff on endpoint 1, read over the session
            // commissioning left behind: proof the CASE session is live.
            _ = try await readOnOff(device.nodeID, with: controller)   // throws unless OnOff is a bool
            #expect(device.nodeID.rawValue > 0)
            let registered = await controller.device(for: device.nodeID)
            #expect(registered?.nodeID == device.nodeID, "commissioned device is not registered")
            #expect(app.log.contains("Commissioning completed successfully"), "the device committed the fabric")
            // One CASE handshake: CommissioningComplete's, reused for the read.
            #expect(app.log.components(separatedBy: "Received Sigma1 msg").count - 1 == 1)
        }
    }

    // MARK: - Control

    @Test("Our controller toggles the app's light and reads the new value", .timeLimit(.minutes(3)))
    func control() async throws {
        guard ChipAppRunner.findBinary() != nil else { return }
        try await withChipApp { app, controller in
            let device = try await commission(app, with: controller)
            let before = try await readOnOff(device.nodeID, with: controller)
            try await toggle(device.nodeID, with: controller)
            let after = try await readOnOff(device.nodeID, with: controller)
            #expect(after == !before, "Toggle flips OnOff")
        }
    }

    // MARK: - Subscribe

    @Test("A subscription to the app's OnOff primes with the value and reports a toggle", .timeLimit(.minutes(3)))
    func subscribe() async throws {
        guard ChipAppRunner.findBinary() != nil else { return }
        try await withChipApp { app, controller in
            let device = try await commission(app, with: controller)
            let current = try await readOnOff(device.nodeID, with: controller)
            let subscription = try await controller.subscribe(nodeID: device.nodeID, Self.onOffSubscription)
            let events = EventQueue(subscription.events)

            _ = try await events.next("established") { if case .established = $0 { true } else { false } }
            let primed = try await events.nextOnOff("priming report")
            #expect(primed == current, "the priming report states the current value")

            try await toggle(device.nodeID, with: controller)
            let reported = try await events.nextOnOff("toggle report")
            #expect(reported == !current, "the toggle is reported")
            await subscription.cancel()
        }
    }

    // MARK: - Device restart

    @Test("A subscription survives a restart of the app: lost, re-established, reporting again", .timeLimit(.minutes(5)))
    func surviveRestart() async throws {
        guard ChipAppRunner.findBinary() != nil else { return }
        try await withChipApp { app, controller in
            let device = try await commission(app, with: controller)
            let subscription = try await controller.subscribe(nodeID: device.nodeID, Self.onOffSubscription)
            let events = EventQueue(subscription.events)
            let first = try await events.next("established") { if case .established = $0 { true } else { false } }
            guard case .established(_, let maxInterval) = first else {
                Issue.record("expected .established, got \(first)")
                return
            }
            _ = try await events.nextOnOff("priming report")

            // The subscription is declared lost one granted max interval plus
            // the controller's MRP exhaustion horizon after the last report;
            // the hang guard is on top of that.
            let peer = await controller.device(for: device.nodeID)?.mrpParameters ?? .default
            let exhaustion = MRPConfig(
                peer: peer,
                maxRetransmissions: Self.controllerMRP.maxRetransmissions
            ).exhaustionHorizon(peerActive: false)
            let liveness = Duration.seconds(Int(maxInterval)) + exhaustion
            // Re-established after the first re-subscribe backoff, at worst one
            // attempt that exhausts its retransmissions against a device still
            // starting, and the second backoff; the hang guard is on top.
            let reestablish = ControllerSubscription.backoff(attempt: 0) + exhaustion
                + ControllerSubscription.backoff(attempt: 1)

            // Same port and KVS file: the device comes back with its fabric,
            // at the address the controller has on record.
            await app.stop()
            let restarted = try await ChipAppRunner.start(passcode: Self.passcode, port: app.port, kvsPath: app.kvsPath)
            do {
                _ = try await events.next(".lost", within: liveness + Self.hangGuard) { if case .lost = $0 { true } else { false } }
                _ = try await events.next("re-established", within: reestablish + Self.hangGuard) {
                    if case .established = $0 { true } else { false }
                }
                let primed = try await events.nextOnOff("priming report after the restart")
                try await toggle(device.nodeID, with: controller)
                let reported = try await events.nextOnOff("toggle report after the restart")
                #expect(reported == !primed, "a toggle after the restart is reported")
                #expect(restarted.log.contains("Received Sigma1 msg"), "the re-subscribe established a new CASE session")
                await subscription.cancel()
            } catch {
                await restarted.stop()
                throw ChipFailure(error: error, context: "events: \(await events.seen)\n--- restarted app log ---\n\(restarted.log)")
            }
            await restarted.stop()
        }
    }

    // MARK: - Second admin

    @Test("Our controller commissions the app as a second admin beside chip-tool", .timeLimit(.minutes(5)))
    func secondAdmin() async throws {
        guard ChipAppRunner.findBinary() != nil, let chipTool = ChipToolRunner.findBinary() else { return }
        let stateDir = try ChipToolRunner.createStateDirectory()
        defer { ChipToolRunner.cleanupStateDirectory(stateDir) }
        let chipToolNode: UInt64 = 1

        try await withChipApp { app, controller in
            let paired = try await Self.chipTool {
                try chipTool.pairWithIP(
                    nodeID: chipToolNode, passcode: Self.passcode,
                    host: "127.0.0.1", port: app.port, stateDir: stateDir
                )
            }
            try Self.require(paired, "chip-tool pairing")

            // Basic commissioning window (option 0): the original passcode,
            // so iteration and discriminator are ignored.
            let window = try await Self.chipTool {
                try chipTool.run([
                    "pairing", "open-commissioning-window",
                    "\(chipToolNode)", "0", "300", "1000", "3840",
                    "--storage-directory", stateDir.path,
                ])
            }
            try Self.require(window, "chip-tool open-commissioning-window")

            let device = try await commission(app, with: controller)
            let before = try await readOnOff(device.nodeID, with: controller)

            let theirs = try await Self.chipTool {
                try chipTool.toggleOnOff(nodeID: chipToolNode, endpointID: 1, stateDir: stateDir)
            }
            try Self.require(theirs, "chip-tool toggle")
            #expect(try await readOnOff(device.nodeID, with: controller) == !before, "chip-tool's toggle took effect")

            try await toggle(device.nodeID, with: controller)
            #expect(try await readOnOff(device.nodeID, with: controller) == before, "our toggle took effect")

            let fabrics = try await controller.readAttribute(
                nodeID: device.nodeID,
                endpointID: .root,
                clusterID: .operationalCredentials,
                attributeID: Self.fabricsAttribute,
                isFabricFiltered: false
            )
            #expect(fabrics.arrayElements?.count == 2, "two fabrics on the device: \(fabrics)")
            let ownOnly = try await controller.readAttribute(
                nodeID: device.nodeID,
                endpointID: .root,
                clusterID: .operationalCredentials,
                attributeID: Self.fabricsAttribute
            )
            #expect(ownOnly.arrayElements?.count == 1, "a fabric-filtered read holds only our fabric: \(ownOnly)")
        }
    }

    // MARK: - Timed invoke

    /// UnitTesting cluster (test vendor 0xFFF1) and its TimedInvokeRequest
    /// command, which the spec marks as requiring a timed interaction.
    static let unitTesting = ClusterID(rawValue: 0xFFF1_FC05)
    static let timedInvokeRequest = CommandID(rawValue: 0x12)

    @Test("The app has no DoorLock; its timed-only UnitTesting command needs, and succeeds with, a timed invoke", .timeLimit(.minutes(3)))
    func timedInvoke() async throws {
        guard ChipAppRunner.findBinary() != nil else { return }
        try await withChipApp { app, controller in
            let device = try await commission(app, with: controller)

            // Measured: chip-all-clusters-app v1.4.0.0 has no DoorLock on any
            // endpoint, so LockDoor on endpoint 1 is UnsupportedCluster.
            await #expect(throws: IMError.invalidStatus("Command error: status \(IMStatusCode.unsupportedCluster.rawValue)")) {
                _ = try await controller.invokeCommand(
                    nodeID: device.nodeID, endpointID: Self.endpoint, clusterID: .doorLock,
                    commandID: DoorLockCluster.Command.lockDoor,
                    timedTimeout: .seconds(30)
                )
            }

            // Measured: the app refuses the untimed invoke in the command's
            // status IB (an InvokeResponse), not with a StatusResponse.
            await #expect(throws: IMError.invalidStatus("Command error: status \(IMStatusCode.needsTimedInteraction.rawValue)")) {
                _ = try await controller.invokeCommand(
                    nodeID: device.nodeID, endpointID: Self.endpoint, clusterID: Self.unitTesting,
                    commandID: Self.timedInvokeRequest
                )
            }
            _ = try await controller.invokeCommand(
                nodeID: device.nodeID, endpointID: Self.endpoint, clusterID: Self.unitTesting,
                commandID: Self.timedInvokeRequest,
                timedTimeout: .seconds(30)
            )
        }
    }

    // MARK: - Helpers

    static let onOffSubscription = SubscriptionRequest(
        attributePaths: [AttributePath(endpointID: endpoint, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff)],
        minInterval: 1,
        maxInterval: 10
    )

    /// Start the app (fresh KVS, free port) and a controller on a loopback
    /// transport, run `body`, then stop the controller, the transport and the
    /// app on every path. A failure is recorded with the app's log.
    private func withChipApp(
        _ body: (_ app: ChipAppRunner, _ controller: MatterController) async throws -> Void
    ) async throws {
        let kvs = FileManager.default.temporaryDirectory.appendingPathComponent("chip-kvs-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: kvs) }

        let app = try await ChipAppRunner.start(passcode: Self.passcode, port: freeUDPPort(), kvsPath: kvs)
        let transport = LoopbackTransport()
        let controller: MatterController
        do {
            try await transport.bind(port: 0)
            controller = try MatterController(
                transport: transport,
                discovery: StubDiscovery(),
                configuration: .init(fabricID: FabricID(rawValue: 1), rootKey: P256.Signing.PrivateKey(), mrp: Self.controllerMRP)
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

    private func commission(_ app: ChipAppRunner, with controller: MatterController) async throws -> CommissionedDevice {
        try await controller.commission(
            address: MatterAddress(host: "127.0.0.1", port: app.port),
            setupCode: Self.passcode,
            mrp: nil
        )
    }

    private func readOnOff(_ nodeID: NodeID, with controller: MatterController) async throws -> Bool {
        let value = try await controller.readAttribute(
            nodeID: nodeID, endpointID: Self.endpoint, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff
        )
        guard let on = value.boolValue else { throw ChipFailure(error: nil, context: "OnOff is not a bool: \(value)") }
        return on
    }

    private func toggle(_ nodeID: NodeID, with controller: MatterController) async throws {
        _ = try await controller.invokeCommand(
            nodeID: nodeID, endpointID: Self.endpoint, clusterID: .onOff, commandID: OnOffCluster.Command.toggle
        )
    }

    /// Run chip-tool off the cooperative pool (it blocks until the process exits).
    private static func chipTool(
        _ run: @escaping @Sendable () throws -> ChipToolRunner.RunResult
    ) async throws -> ChipToolRunner.RunResult {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global().async {
                continuation.resume(with: Result { try run() })
            }
        }
    }

    private static func require(_ result: ChipToolRunner.RunResult, _ what: String) throws {
        guard result.succeeded else {
            throw ChipFailure(
                error: nil,
                context: "\(what) failed (exit \(result.exitCode))\n--- chip-tool stdout (tail) ---\n\(result.stdout.suffix(6000))\n--- stderr ---\n\(result.stderr.suffix(2000))"
            )
        }
    }
}

// MARK: - ChipFailure

private struct ChipFailure: Error, CustomStringConvertible {
    let error: (any Error)?
    let context: String
    var description: String {
        if let error { return "\(error)\n\(context)" }
        return context
    }
}

// MARK: - EventQueue

/// A subscription's events, pulled one outcome at a time under the hang guard.
private actor EventQueue {
    private var buffered: [SubscriptionEvent] = []
    private var finished = false
    private var waiter: CheckedContinuation<SubscriptionEvent?, Never>?
    private var generation = 0
    private var pump: Task<Void, Never>?
    /// Every event pulled so far, for diagnosis.
    private(set) var seen: [String] = []

    init(_ events: AsyncStream<SubscriptionEvent>) {
        Task { await self.start(events) }
    }

    private func start(_ events: AsyncStream<SubscriptionEvent>) {
        pump = Task { [weak self] in
            for await event in events { await self?.push(event) }
            await self?.finish()
        }
    }

    deinit { pump?.cancel() }

    private func push(_ event: SubscriptionEvent) {
        if let waiter {
            self.waiter = nil
            waiter.resume(returning: event)
        } else {
            buffered.append(event)
        }
    }

    private func finish() {
        finished = true
        waiter?.resume(returning: nil)
        waiter = nil
    }

    private func expire(_ token: Int) {
        guard token == generation, let waiter else { return }
        self.waiter = nil
        waiter.resume(returning: nil)
    }

    /// The next event, or `nil` once the stream finishes or `deadline` passes.
    private func next(before deadline: ContinuousClock.Instant) async -> SubscriptionEvent? {
        if !buffered.isEmpty { return buffered.removeFirst() }
        if finished { return nil }
        precondition(waiter == nil, "EventQueue has one consumer at a time")
        generation += 1
        let token = generation
        let timer = Task { [weak self] in
            guard (try? await Task.sleep(until: deadline, clock: .continuous)) != nil else { return }
            await self?.expire(token)
        }
        defer { timer.cancel() }
        return await withCheckedContinuation { waiter = $0 }
    }

    /// The first event matching `predicate` within `within` (default: the
    /// hang guard). Throws if none arrives in time, or if the stream finishes.
    func next(
        _ what: String,
        within: Duration = ChipDeviceCommissioningTests.hangGuard,
        where predicate: (SubscriptionEvent) -> Bool
    ) async throws -> SubscriptionEvent {
        let deadline = ContinuousClock.now.advanced(by: within)
        while let event = await next(before: deadline) {
            seen.append(Self.describe(event))
            if predicate(event) { return event }
        }
        if finished {
            throw ChipFailure(error: nil, context: "events finished before \(what); events: \(seen)")
        }
        throw ChipFailure(error: nil, context: "no \(what) within \(within); events: \(seen)")
    }

    /// The next report carrying an OnOff value, within the hang guard.
    func nextOnOff(_ what: String) async throws -> Bool {
        let event = try await next(what) { Self.onOff(in: $0) != nil }
        return Self.onOff(in: event)!
    }

    private static func onOff(in event: SubscriptionEvent) -> Bool? {
        guard case .report(let report) = event else { return nil }
        return report.attributes.compactMap { $0.attributeData?.data.boolValue }.last
    }

    private static func describe(_ event: SubscriptionEvent) -> String {
        switch event {
        case .established(let id, let maxInterval): "established(\(id.rawValue), max \(maxInterval) s)"
        case .lost(let reason): "lost(\(reason))"
        case .report(let report):
            "report(\(report.attributes.compactMap { $0.attributeData?.data.boolValue }), events \(report.events.count))"
        }
    }
}
#endif
