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
            let device = try await controller.commission(address: link.b.address, setupCode: passcode, mrp: fast)

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
                timedTimeout: .seconds(2)
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
            let device = try await controller.commission(address: link.b.address, setupCode: passcode, mrp: fast)
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
            let device = try await controller.commission(address: link.b.address, setupCode: passcode, mrp: fast)
            let path = AttributePath(endpointID: light.endpointID, clusterID: .onOff, attributeID: OnOffCluster.Attribute.onOff)
            let subscription = try await controller.subscribe(nodeID: device.nodeID, SubscriptionRequest(attributePaths: [path], minInterval: 0, maxInterval: 2))
            let log = LockedValue<[String]>([])
            let reader = Task {
                for await event in subscription.events {
                    switch event {
                    case .established: log.withLock { $0.append("established") }
                    case .lost: log.withLock { $0.append("lost") }
                    case .report: break
                    }
                }
            }
            #expect(try await waitUntil { log.value == ["established"] })
            link.setDropProbability(1.0, from: .b)    // the device goes silent
            #expect(try await waitUntil { log.value.contains("lost") })
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
            let device = try await controller.commission(address: link.b.address, setupCode: passcode, mrp: fast)
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
}
