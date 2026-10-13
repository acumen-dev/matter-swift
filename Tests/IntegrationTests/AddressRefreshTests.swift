// AddressRefreshTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterModel
import MatterProtocol
import MatterTransport
@testable import MatterController
import MatterDevice
import MatterTestSupport

/// A commissioned node whose address went stale: when CASE gets no answer,
/// the controller re-resolves `_matter._tcp` once and retries at a new
/// address. The device advertises through one `InMemoryDiscovery`; the link
/// models an address nobody answers on by dropping what is sent to it.
@Suite("AddressRefresh", .serialized, .timeLimit(.minutes(3)))
struct AddressRefreshTests {

    /// An address on the link's private range that no endpoint answers on.
    static let stale = MatterAddress(host: "10.0.0.3", port: 5540)

    /// The device server's operational TXT.
    static let advertisedMRP = MRPParameters(txtRecords: ["SII": "5000", "SAI": "300", "T": "0"])

    static let retransmissions = 4

    /// On top of every protocol-derived bound; never a latency budget.
    static let hangGuard = Duration.seconds(10)

    /// How long a suspended operational resolve waits for its cancellation
    /// before completing anyway (so a missed deadline shows as a result).
    static let suspendGuard = Duration.seconds(30)

    struct HangGuard: Error {}

    /// Commissionable records resolve to the device; operational ones to `operational`.
    private static func makeDiscovery(
        _ link: FaultInjectingLink,
        operational: LockedValue<MatterAddress>
    ) -> InMemoryDiscovery {
        InMemoryDiscovery { record in
            record.serviceType == .operational ? operational.value : link.b.address
        }
    }

    /// The device's operational instance name, once it has advertised it
    /// (the server advertises from a task after the fabric commits).
    private static func operationalName(_ discovery: any ServiceDiscovery) async throws -> String {
        try await operationalRecord(discovery).name
    }

    private static func operationalRecord(_ discovery: any ServiceDiscovery) async throws -> ServiceRecord {
        try await withThrowingTaskGroup(of: ServiceRecord.self) { group in
            group.addTask {
                for await record in discovery.browse(serviceType: .operational) { return record }
                throw CancellationError()
            }
            group.addTask {
                try await Task.sleep(for: hangGuard)
                throw HangGuard()
            }
            defer { group.cancelAll() }
            return try await group.next()!
        }
    }

    /// Poll until `condition` holds or `bound` passes.
    private static func waitUntil(within bound: Duration, _ condition: @Sendable () async -> Bool) async throws -> Bool {
        let deadline = ContinuousClock.now + bound
        while ContinuousClock.now < deadline {
            if await condition() { return true }
            try await Task.sleep(for: .milliseconds(20))
        }
        return await condition()
    }

    private static func readOnOff(_ controller: MatterController, _ device: CommissionedDevice, _ light: BridgedEndpoint) async throws -> TLVElement {
        try await controller.readAttribute(
            nodeID: device.nodeID, endpointID: light.endpointID,
            clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff
        )
    }

    /// Commission, wait for the operational advert, drop the CASE session and
    /// record `stale` as the node's address; everything sent to it is lost.
    private static func commissionThenGoStale(
        _ controller: MatterController,
        _ link: FaultInjectingLink,
        _ discovery: any ServiceDiscovery
    ) async throws -> (CommissionedDevice, String) {
        let device = try await controller.commission(address: link.b.address, setupCode: passcode, mrp: fast)
        let name = try await operationalName(discovery)
        await controller.invalidateSession(for: device.nodeID)
        await controller.updateOperationalAddress(stale, mrp: nil, for: device.nodeID)
        link.setAddressedInterceptor { _, side, destination in
            side == .a && destination == stale ? .drop : .deliver(after: .zero)
        }
        return (device, name)
    }

    // MARK: - (a) moved

    @Test("CASE to a stale address re-resolves once, persists the new address and TXT timing, and succeeds there")
    func refreshesAndRetries() async throws {
        let link = FaultInjectingLink(seed: 61)
        let operational = LockedValue(link.b.address)
        let discovery = Self.makeDiscovery(link, operational: operational)
        let (server, light) = try await startServer(on: link, toggles: LockedValue(0), discovery: discovery)
        let store = InMemoryControllerStore()
        let controller = try makeController(on: link, maxRetransmissions: Self.retransmissions, discovery: discovery, store: store)

        do {
            let (device, name) = try await Self.commissionThenGoStale(controller, link, discovery)
            try #require(await controller.device(for: device.nodeID)?.mrpParameters == fast)

            let value = try await Self.readOnOff(controller, device, light)
            #expect(value.boolValue == false)

            let current = await controller.device(for: device.nodeID)
            #expect(current?.operationalAddress == link.b.address)
            #expect(current?.mrpParameters == Self.advertisedMRP)
            let stored = try #require(await store.load()?.devices.first { $0.nodeID == device.nodeID.rawValue })
            #expect(stored.operationalHost == link.b.address.host)
            #expect(stored.operationalPort == link.b.address.port)
            #expect(DeviceRegistry.mrpParameters(from: stored) == Self.advertisedMRP)
            #expect(discovery.resolveCount(name: name, serviceType: .operational) == 1)
        } catch {
            await controller.stop(); await server.stop()
            throw error
        }
        await controller.stop(); await server.stop()
    }

    // MARK: - (a') moved, no TXT

    @Test("A re-resolve with an empty TXT moves the node but keeps its stored MRP timing")
    func emptyTXTKeepsTiming() async throws {
        let link = FaultInjectingLink(seed: 66)
        let operational = LockedValue(link.b.address)
        let discovery = Self.makeDiscovery(link, operational: operational)
        let (server, light) = try await startServer(on: link, toggles: LockedValue(0), discovery: discovery)
        let store = InMemoryControllerStore()
        let controller = try makeController(on: link, maxRetransmissions: Self.retransmissions, discovery: discovery, store: store)

        do {
            let (device, _) = try await Self.commissionThenGoStale(controller, link, discovery)
            // Same name and type: replaces the device's record, now without TXT.
            let advertised = try await Self.operationalRecord(discovery)
            try await discovery.advertise(service: ServiceRecord(
                name: advertised.name, serviceType: .operational, host: advertised.host,
                port: advertised.port, txtRecords: [:], subtypes: advertised.subtypes))
            try #require(try await Self.operationalRecord(discovery).txtRecords.isEmpty)

            let value = try await Self.readOnOff(controller, device, light)
            #expect(value.boolValue == false)

            let current = await controller.device(for: device.nodeID)
            #expect(current?.operationalAddress == link.b.address)
            #expect(current?.mrpParameters == fast)
            let stored = try #require(await store.load()?.devices.first { $0.nodeID == device.nodeID.rawValue })
            #expect(stored.operationalHost == link.b.address.host)
            #expect(DeviceRegistry.mrpParameters(from: stored) == fast)
        } catch {
            await controller.stop(); await server.stop()
            throw error
        }
        await controller.stop(); await server.stop()
    }

    // MARK: - Resolve deadlines

    @Test("discoverDevice gives up at its timeout when the resolve never completes")
    func discoverDeviceDeadline() async throws {
        let link = FaultInjectingLink(seed: 67)
        let discovery = SuspendingOperationalDiscovery(
            inner: InMemoryDiscovery { _ in link.b.address }, hangGuard: Self.suspendGuard
        )
        let controller = try makeController(on: link, maxRetransmissions: Self.retransmissions, discovery: discovery)
        await #expect {
            _ = try await controller.discoverDevice(nodeID: NodeID(rawValue: 2), timeout: .milliseconds(200))
        } throws: { error in
            if case ControllerError.discoveryFailed = error { return true }
            return false
        }
        #expect(discovery.resolveCancelled)
        await controller.stop()
    }

    @Test("A refresh whose resolve never completes gives up at addressRefreshTimeout with the original error")
    func refreshDeadline() async throws {
        let link = FaultInjectingLink(seed: 68)
        let operational = LockedValue(link.b.address)
        let discovery = SuspendingOperationalDiscovery(
            inner: Self.makeDiscovery(link, operational: operational), hangGuard: Self.suspendGuard
        )
        let (server, light) = try await startServer(on: link, toggles: LockedValue(0), discovery: discovery)
        let controller = try MatterController(
            transport: link.a,
            discovery: discovery,
            configuration: .init(
                fabricID: FabricID(rawValue: 1),
                mrp: MRPConfig(maxRetransmissions: Self.retransmissions),
                addressRefreshTimeout: .milliseconds(200)
            )
        )

        do {
            let (device, _) = try await Self.commissionThenGoStale(controller, link, discovery)
            // Had the deadline been missed, the resolve would complete after
            // the suspend guard, and the retry at the device's address succeed.
            await #expect(throws: ControllerError.peerUnreachable(device.nodeID)) {
                _ = try await Self.readOnOff(controller, device, light)
            }
            #expect(discovery.resolveCancelled)
            #expect(await controller.device(for: device.nodeID)?.operationalAddress == Self.stale)
        } catch {
            await controller.stop(); await server.stop()
            throw error
        }
        await controller.stop(); await server.stop()
    }

    // MARK: - (b) no record

    @Test("With no operational record, the original peerUnreachable is thrown after one resolve attempt")
    func noRecordRethrowsOriginal() async throws {
        let link = FaultInjectingLink(seed: 62)
        let operational = LockedValue(link.b.address)
        let discovery = Self.makeDiscovery(link, operational: operational)
        let (server, light) = try await startServer(on: link, toggles: LockedValue(0), discovery: discovery)
        let controller = try makeController(on: link, maxRetransmissions: Self.retransmissions, discovery: discovery)

        do {
            let (device, name) = try await Self.commissionThenGoStale(controller, link, discovery)
            await discovery.stopAdvertising(name: name)

            await #expect(throws: ControllerError.peerUnreachable(device.nodeID)) {
                _ = try await Self.readOnOff(controller, device, light)
            }
            #expect(discovery.resolveCount(name: name, serviceType: .operational) == 1)
            #expect(await controller.device(for: device.nodeID)?.operationalAddress == Self.stale)
            #expect(await controller.device(for: device.nodeID)?.mrpParameters == fast)
        } catch {
            await controller.stop(); await server.stop()
            throw error
        }
        await controller.stop(); await server.stop()
    }

    // MARK: - (c) same address

    @Test("When the record resolves to the address tried, the original error is thrown and Sigma1 is sent there once")
    func sameAddressDoesNotRetry() async throws {
        let link = FaultInjectingLink(seed: 63)
        let operational = LockedValue(Self.stale)
        let discovery = Self.makeDiscovery(link, operational: operational)
        let (server, light) = try await startServer(on: link, toggles: LockedValue(0), discovery: discovery)
        let controller = try makeController(on: link, maxRetransmissions: Self.retransmissions, discovery: discovery)

        do {
            let (device, name) = try await Self.commissionThenGoStale(controller, link, discovery)

            await #expect(throws: ControllerError.peerUnreachable(device.nodeID)) {
                _ = try await Self.readOnOff(controller, device, light)
            }
            #expect(discovery.resolveCount(name: name, serviceType: .operational) == 1)

            let toStale = link.sent(from: .a, to: Self.stale)
            let headers = try toStale.map { try MessageHeader.decode(from: $0).header }
            #expect(headers.allSatisfy { $0.sessionID == 0 }, "only unsecured (handshake) frames went to the stale address")
            #expect(FaultyLinkTests.sigma1Exchanges(in: toStale).count == 1, "one Sigma1 exchange, not a retry")
            #expect(toStale.count == 1 + Self.retransmissions, "1 transmission + MRP retransmissions")
        } catch {
            await controller.stop(); await server.stop()
            throw error
        }
        await controller.stop(); await server.stop()
    }

    // MARK: - (d) the device answered

    @Test("A device that answers Sigma1 with a failure StatusReport is never re-resolved")
    func answeredFailureDoesNotResolve() async throws {
        let link = FaultInjectingLink(seed: 64)
        let operational = LockedValue(link.b.address)
        let discovery = Self.makeDiscovery(link, operational: operational)
        let (server, light) = try await startServer(on: link, toggles: LockedValue(0), discovery: discovery)
        let controller = try makeController(on: link, maxRetransmissions: Self.retransmissions, discovery: discovery)

        do {
            let device = try await controller.commission(address: link.b.address, setupCode: passcode, mrp: fast)
            let name = try await Self.operationalName(discovery)
            await controller.invalidateSession(for: device.nodeID)

            // Sigma1 never reaches the device; the "device" refuses it with a
            // CASE failure (NoSharedTrustRoots), once.
            let answered = LockedValue(false)
            let refusal = StatusReportMessage(
                generalStatus: .failure,
                protocolID: UInt32(MatterProtocolID.secureChannel.rawValue),
                protocolStatus: 0x0001
            ).encode()
            let endpointA = link.a.address
            let deviceSide = link.b
            link.setAddressedInterceptor { data, side, _ in
                guard side == .a,
                      let frame = try? ScriptedPeer.decodeUnsecured(data),
                      frame.exchangeHeader.protocolID == MatterProtocolID.secureChannel.rawValue,
                      frame.exchangeHeader.protocolOpcode == SecureChannelOpcode.caseSigma1.rawValue
                else { return .deliver(after: .zero) }
                let first = answered.withLock { answered in
                    defer { answered = true }
                    return !answered
                }
                if first {
                    let reply = ScriptedPeer.unsecuredReply(
                        to: frame, protocolID: .secureChannel,
                        opcode: SecureChannelOpcode.statusReport.rawValue,
                        payload: refusal, counter: 0x4D_0001
                    )
                    Task { try? await deviceSide.send(reply, to: endpointA) }
                }
                return .drop
            }

            await #expect {
                _ = try await Self.readOnOff(controller, device, light)
            } throws: { error in
                if case ControllerError.caseSessionFailed = error { return true }
                return false
            }
            #expect(answered.value)
            #expect(discovery.resolveCount(name: name, serviceType: .operational) == 0)
            #expect(await controller.device(for: device.nodeID)?.operationalAddress == link.b.address)
        } catch {
            await controller.stop(); await server.stop()
            throw error
        }
        await controller.stop(); await server.stop()
    }

    // MARK: - (e) a subscription follows the device

    @Test("A subscription whose device moved re-establishes at the new address on its own, and reports")
    func subscriptionFollowsMove() async throws {
        let link = FaultInjectingLink(seed: 65)
        let operational = LockedValue(link.b.address)
        let discovery = Self.makeDiscovery(link, operational: operational)
        let endpoint = MovableEndpoint(link.b)
        let (server, light) = try await startServer(
            on: link, toggles: LockedValue(0), discovery: discovery, transport: endpoint
        )
        let controller = try makeController(on: link, maxRetransmissions: Self.retransmissions, discovery: discovery)

        do {
            let device = try await controller.commission(address: link.b.address, setupCode: passcode, mrp: fast)
            let name = try await Self.operationalName(discovery)
            let path = AttributePath(endpointID: light.endpointID, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff)
            let subscription = try await controller.subscribe(
                nodeID: device.nodeID,
                SubscriptionRequest(attributePaths: [path], minInterval: 0, maxInterval: 2)
            )
            let established = LockedValue<[UInt16]>([])
            let lost = LockedValue(0)
            let values = LockedValue<[Bool]>([])
            let reader = Task {
                for await event in subscription.events {
                    switch event {
                    case .established(_, let maxInterval): established.withLock { $0.append(maxInterval) }
                    case .lost: lost.withLock { $0 += 1 }
                    case .report(let report):
                        for attribute in report.attributes {
                            if let value = attribute.attributeData?.data.boolValue { values.withLock { $0.append(value) } }
                        }
                    }
                }
            }
            #expect(try await Self.waitUntil(within: Self.hangGuard) { established.value.count == 1 && !values.value.isEmpty })
            let maxInterval = try #require(established.value.first)

            // The device moves: it sends from the new address, its old one
            // goes dead both ways, and its advert names the new one. It is
            // heard again once the controller talks to it there.
            let moved = Self.stale
            let arrived = LockedValue(false)
            endpoint.move(to: moved)
            operational.withLock { $0 = moved }
            link.setAddressedInterceptor { _, side, destination in
                switch side {
                case .a:
                    guard destination == moved else { return .drop }
                    arrived.withLock { $0 = true }
                    return .deliver(after: .zero)
                case .b:
                    return arrived.value ? .deliver(after: .zero) : .drop
                }
            }

            // Lost one granted max interval plus the MRP exhaustion horizon
            // after the last report (the priming one, before the move).
            let exhaustion = MRPConfig(peer: fast, maxRetransmissions: Self.retransmissions)
                .exhaustionHorizon(peerActive: false)
            let liveness = Duration.seconds(Int(maxInterval)) + exhaustion
            #expect(try await Self.waitUntil(within: liveness + Self.hangGuard) { lost.value >= 1 }, "declared lost")

            // Re-established after: the first backoff; a re-subscribe on the
            // cached (dead) session that exhausts; the second backoff; and a
            // CASE attempt at the old address that exhausts before the
            // refresh and the handshake at the new one.
            let reestablish = ControllerSubscription.backoff(attempt: 0) + exhaustion
                + ControllerSubscription.backoff(attempt: 1) + exhaustion
            #expect(try await Self.waitUntil(within: reestablish + Self.hangGuard) { established.value.count >= 2 }, "re-subscribed")

            _ = try await controller.invokeCommand(
                nodeID: device.nodeID, endpointID: light.endpointID,
                clusterID: .onOff, commandID: OnOffCluster.Command.toggle
            )
            #expect(try await Self.waitUntil(within: Self.hangGuard) { values.value.contains(true) }, "the toggle is reported")
            #expect(await controller.device(for: device.nodeID)?.operationalAddress == moved)
            #expect(await controller.device(for: device.nodeID)?.mrpParameters == Self.advertisedMRP)
            #expect(discovery.resolveCount(name: name, serviceType: .operational) == 1)
            await subscription.cancel()
            reader.cancel()
        } catch {
            await controller.stop(); await server.stop()
            throw error
        }
        await controller.stop(); await server.stop()
    }
}

/// The device's link endpoint, sending from an address that can change (a
/// device that moved replies from its new address).
private final class MovableEndpoint: MatterUDPTransport, Sendable {
    private let base: FaultInjectingEndpoint
    private let current: LockedValue<MatterAddress>

    init(_ base: FaultInjectingEndpoint) {
        self.base = base
        self.current = LockedValue(base.address)
    }

    func move(to address: MatterAddress) {
        current.withLock { $0 = address }
    }

    var address: MatterAddress { current.value }

    func send(_ data: Data, to address: MatterAddress) async throws {
        try await base.send(data, to: address, from: current.value)
    }

    func receive() -> AsyncStream<(Data, MatterAddress)> {
        base.receive()
    }

    func bind(port: UInt16) async throws {
        try await base.bind(port: port)
    }

    func close() async {
        await base.close()
    }
}

/// Delegates to `inner`, except that resolving an operational instance
/// waits until cancelled. If it is never cancelled, it resolves normally
/// after `hangGuard`, so a missed deadline shows as a result.
private final class SuspendingOperationalDiscovery: ServiceDiscovery, Sendable {
    private let inner: InMemoryDiscovery
    private let hangGuard: Duration
    private let cancelled = LockedValue(false)

    init(inner: InMemoryDiscovery, hangGuard: Duration) {
        self.inner = inner
        self.hangGuard = hangGuard
    }

    var resolveCancelled: Bool { cancelled.value }

    func advertise(service: ServiceRecord) async throws {
        try await inner.advertise(service: service)
    }

    func browse(serviceType: ServiceType) -> AsyncStream<ServiceRecord> {
        inner.browse(serviceType: serviceType)
    }

    func resolve(_ record: ServiceRecord) async throws -> NetworkAddress {
        try await resolveService(record).address
    }

    func resolveService(_ record: ServiceRecord) async throws -> ResolvedService {
        if record.serviceType == .operational {
            do {
                try await Task.sleep(for: hangGuard)
            } catch {
                cancelled.withLock { $0 = true }
                throw error
            }
        }
        return try await inner.resolveService(record)
    }

    func stopAdvertising() async {
        await inner.stopAdvertising()
    }

    func stopAdvertising(name: String) async {
        await inner.stopAdvertising(name: name)
    }
}
