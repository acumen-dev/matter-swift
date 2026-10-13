// ControllerIMClientTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MatterTypes
import MatterModel
import MatterProtocol
import MatterDevice
import MatterController
import MatterTestSupport

@Suite("Controller IM client against the device server", .serialized, .timeLimit(.minutes(3)))
struct ControllerIMClientTests {

    private static let commissioningTimeout = TLVElement.structure([
        .init(tag: .contextSpecific(0), value: .unsignedInt(180))
    ])

    @Test("A timed-only command is refused without TimedRequest and accepted with it")
    func timedInvoke() async throws {
        let link = FaultInjectingLink(seed: 11)
        let (server, _) = try await startServer(on: link, toggles: LockedValue(0))
        let controller = try makeController(on: link, maxRetransmissions: 4)
        do {
            let device = try await controller.commission(address: link.b.address, setupCode: passcode, mrp: patient)

            // The device answers with an InvokeResponse carrying the command
            // status NeedsTimedInteraction (0xC6 = 198), not a top-level
            // StatusResponse, so it surfaces as IMError.invalidStatus.
            await #expect(throws: IMError.invalidStatus("Command error: status 198")) {
                _ = try await controller.invokeCommand(
                    nodeID: device.nodeID, endpointID: EndpointID(rawValue: 0),
                    clusterID: .adminCommissioning, commandID: CommandID(rawValue: 0x01),
                    commandFields: Self.commissioningTimeout
                )
            }

            let fields = try await controller.invokeCommand(
                nodeID: device.nodeID, endpointID: EndpointID(rawValue: 0),
                clusterID: .adminCommissioning, commandID: CommandID(rawValue: 0x01),
                commandFields: Self.commissioningTimeout,
                timedTimeout: .seconds(30)
            )
            #expect(fields == nil)
        } catch {
            await controller.stop(); await server.stop()
            throw error
        }
        await controller.stop(); await server.stop()
    }

    /// Poll until `condition` holds. The ceiling is a hang guard, not a latency
    /// budget: passing runs return as soon as the outcome holds.
    private func waitUntil(_ condition: @Sendable () async -> Bool) async throws -> Bool {
        let deadline = ContinuousClock.now + .seconds(30)
        while ContinuousClock.now < deadline {
            if await condition() { return true }
            try await Task.sleep(for: .milliseconds(20))
        }
        return await condition()
    }

    @Test("A subscription delivers the priming report and a report after a toggle")
    func subscribeAndReport() async throws {
        let link = FaultInjectingLink(seed: 12)
        let (server, light) = try await startServer(on: link, toggles: LockedValue(0))
        let controller = try makeController(on: link, maxRetransmissions: 4)
        do {
            let device = try await controller.commission(address: link.b.address, setupCode: passcode, mrp: patient)
            let path = AttributePath(endpointID: light.endpointID, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff)
            let subscription = try await controller.subscribe(nodeID: device.nodeID, SubscriptionRequest(attributePaths: [path], minInterval: 0, maxInterval: 30))
            let seen = LockedValue<[Bool]>([])
            let reader = Task {
                for await event in subscription.events {
                    if case .report(let report) = event {
                        for attribute in report.attributes {
                            if let value = attribute.attributeData?.data.boolValue { seen.withLock { $0.append(value) } }
                        }
                    }
                }
            }
            #expect(try await waitUntil { seen.value.first == false }, "priming report states the current value")
            _ = try await controller.invokeCommand(nodeID: device.nodeID, endpointID: light.endpointID, clusterID: .onOff, commandID: OnOffCluster.Command.toggle)
            #expect(try await waitUntil { seen.value.contains(true) }, "the toggle is reported")
            await subscription.cancel()
            reader.cancel()
        } catch {
            await controller.stop(); await server.stop()
            throw error
        }
        await controller.stop(); await server.stop()
    }

    @Test("A device that goes silent is declared lost, and the subscription is restored when it returns")
    func lostAndRestored() async throws {
        let link = FaultInjectingLink(seed: 13)
        let (server, light) = try await startServer(on: link, toggles: LockedValue(0))
        let controller = try makeController(on: link, maxRetransmissions: 2)
        do {
            let device = try await controller.commission(address: link.b.address, setupCode: passcode, mrp: patient)
            // The drop phase needs a silent device to give up quickly.
            await controller.setMRPParameters(fast, for: device.nodeID)
            let path = AttributePath(endpointID: light.endpointID, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff)
            let subscription = try await controller.subscribe(nodeID: device.nodeID, SubscriptionRequest(attributePaths: [path], minInterval: 0, maxInterval: 2))
            let log = LockedValue<[String]>([])
            let first = LockedValue<String?>(nil)
            let reader = Task {
                for await event in subscription.events {
                    switch event {
                    case .established: log.withLock { $0.append("established") }
                    case .lost(let reason):
                        if first.value == nil { first.withLock { $0 = reason } }
                        log.withLock { $0.append("lost") }
                    case .report: break
                    }
                }
            }
            #expect(try await waitUntil { log.value == ["established"] })
            link.setDropProbability(1.0, from: .b)    // the device goes silent
            #expect(try await waitUntil { log.value.contains("lost") })
            #expect(first.value?.hasPrefix("no report within") == true)
            link.setDropProbability(0.0, from: .b)    // and comes back
            #expect(try await waitUntil { log.value.filter { $0 == "established" }.count >= 2 }, "re-subscribed")
            await subscription.cancel()
            reader.cancel()
        } catch {
            await controller.stop(); await server.stop()
            throw error
        }
        await controller.stop(); await server.stop()
    }

    @Test("Stopping the controller finishes a subscription's event stream")
    func stopFinishesSubscriptions() async throws {
        let link = FaultInjectingLink(seed: 14)
        let (server, light) = try await startServer(on: link, toggles: LockedValue(0))
        let controller = try makeController(on: link, maxRetransmissions: 4)
        do {
            let device = try await controller.commission(address: link.b.address, setupCode: passcode, mrp: patient)
            let path = AttributePath(endpointID: light.endpointID, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff)
            let subscription = try await controller.subscribe(nodeID: device.nodeID, SubscriptionRequest(attributePaths: [path], minInterval: 0, maxInterval: 30))
            let finished = LockedValue(false)
            let reader = Task {
                for await _ in subscription.events {}
                finished.withLock { $0 = true }
            }
            await controller.stop()
            #expect(try await waitUntil { finished.value }, "events finishes once the controller stops")
            reader.cancel()
        } catch {
            await controller.stop(); await server.stop()
            throw error
        }
        await server.stop()
    }

    @Test("A subscribe after stop() throws")
    func subscribeAfterStop() async throws {
        let link = FaultInjectingLink(seed: 15)
        let (server, light) = try await startServer(on: link, toggles: LockedValue(0))
        let controller = try makeController(on: link, maxRetransmissions: 4)
        do {
            let device = try await controller.commission(address: link.b.address, setupCode: passcode, mrp: patient)
            let path = AttributePath(endpointID: light.endpointID, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff)
            await controller.stop()
            await #expect(throws: MessagingError.stopped) {
                _ = try await controller.subscribe(nodeID: device.nodeID, SubscriptionRequest(attributePaths: [path], minInterval: 0, maxInterval: 30))
            }
        } catch {
            await controller.stop(); await server.stop()
            throw error
        }
        await server.stop()
    }

    @Test("A re-subscribe that fails on a dead link drops the cached session, so the next one re-handshakes")
    func failedResubscribeInvalidatesSession() async throws {
        let link = FaultInjectingLink(seed: 16)
        let (server, light) = try await startServer(on: link, toggles: LockedValue(0))
        let controller = try makeController(on: link, maxRetransmissions: 2)
        do {
            let device = try await controller.commission(address: link.b.address, setupCode: passcode, mrp: patient)
            // The drop phase needs a silent device to give up quickly.
            await controller.setMRPParameters(fast, for: device.nodeID)
            let path = AttributePath(endpointID: light.endpointID, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff)
            let subscription = try await controller.subscribe(nodeID: device.nodeID, SubscriptionRequest(attributePaths: [path], minInterval: 0, maxInterval: 2))
            let before = try await controller.session(for: device.nodeID).localSessionID
            let reasons = LockedValue<[String]>([])
            let established = LockedValue(0)
            let reader = Task {
                for await event in subscription.events {
                    switch event {
                    case .established: established.withLock { $0 += 1 }
                    case .lost(let reason): reasons.withLock { $0.append(reason) }
                    case .report: break
                    }
                }
            }
            #expect(try await waitUntil { established.value == 1 })
            link.setDropProbability(1.0, from: .b)
            #expect(try await waitUntil { reasons.value.contains { $0.hasPrefix("re-subscribe failed") } })
            link.setDropProbability(0.0, from: .b)
            #expect(try await waitUntil { established.value >= 2 }, "re-subscribed")
            let after = try await controller.session(for: device.nodeID).localSessionID
            #expect(after != before, "the dead session was replaced by a fresh handshake")
            await subscription.cancel()
            reader.cancel()
        } catch {
            await controller.stop(); await server.stop()
            throw error
        }
        await controller.stop(); await server.stop()
    }

    @Test("stop() cancels every subscription created by concurrent subscribe calls")
    func concurrentSubscribesAreAllCancelledByStop() async throws {
        let link = FaultInjectingLink(seed: 17)
        let (server, light) = try await startServer(on: link, toggles: LockedValue(0))
        let controller = try makeController(on: link, maxRetransmissions: 4)
        do {
            let device = try await controller.commission(address: link.b.address, setupCode: passcode, mrp: patient)
            let nodeID = device.nodeID
            let path = AttributePath(endpointID: light.endpointID, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff)
            // One already tracked, so concurrent calls have an entry to prune-check.
            let first = try await controller.subscribe(nodeID: nodeID, SubscriptionRequest(attributePaths: [path], minInterval: 0, maxInterval: 30))
            var subscriptions = try await withThrowingTaskGroup(of: ControllerSubscription.self) { group in
                for _ in 0..<4 {
                    group.addTask {
                        try await controller.subscribe(nodeID: nodeID, SubscriptionRequest(attributePaths: [path], minInterval: 0, maxInterval: 30))
                    }
                }
                var all: [ControllerSubscription] = []
                for try await subscription in group { all.append(subscription) }
                return all
            }
            subscriptions.append(first)
            #expect(subscriptions.count == 5)
            let finished = LockedValue(0)
            let readers = subscriptions.map { subscription in
                Task {
                    for await _ in subscription.events {}
                    finished.withLock { $0 += 1 }
                }
            }
            await controller.stop()
            #expect(try await waitUntil { finished.value == 5 }, "every subscription's events finishes")
            readers.forEach { $0.cancel() }
        } catch {
            await controller.stop(); await server.stop()
            throw error
        }
        await server.stop()
    }
}
