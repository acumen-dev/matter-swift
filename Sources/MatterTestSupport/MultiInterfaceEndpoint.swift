// MultiInterfaceEndpoint.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Logging
import Synchronization
import MatterTransport

/// A `MatterUDPTransport` that pretends to be a multi-homed host: wraps one side of a
/// `FaultInjectingLink`, selects and pins paths with the real `PathSelector`, and records each send.
///
/// Reachability is by destination host (canonicalised, port ignored); the local address of a
/// path is the interface snapshot's first address. Log wording and levels mirror
/// `POSIXUDPSocketCore`.
public final class MultiInterfaceEndpoint: MatterUDPTransport, Sendable {
    public struct Interface: Sendable {
        public var snapshot: InterfaceSnapshot
        /// Peer hosts this interface reaches.
        public var reachable: Set<String>

        public init(snapshot: InterfaceSnapshot, reachable: Set<String>) {
            self.snapshot = snapshot
            self.reachable = reachable
        }
    }

    private struct State: Sendable {
        var interfaces: [Interface]
        var routeTable: String?
        var arrival: String?
        var monitor = InterfacePolicyMonitor(policy: .automatic)
        var sends: [(data: Data, to: MatterAddress, path: MatterPath)] = []
        var datagrams: AsyncStream<MatterDatagram>?
        var legacy: AsyncStream<(Data, MatterAddress)>?
    }

    private let endpoint: FaultInjectingEndpoint
    private let logger: Logger
    private let state: Mutex<State>

    public init(wrapping endpoint: FaultInjectingEndpoint, interfaces: [Interface], routeTable: String?, logger: Logger) {
        self.endpoint = endpoint
        self.logger = logger
        var interfaces = interfaces
        for i in interfaces.indices {
            interfaces[i].reachable = Set(interfaces[i].reachable.map(Self.canonical))
        }
        self.state = Mutex(State(interfaces: interfaces, routeTable: routeTable, arrival: interfaces.first?.snapshot.name))
    }

    // MARK: - Test controls

    public func setInterface(_ name: String, up: Bool) {
        state.withLock { state in
            if let i = state.interfaces.firstIndex(where: { $0.snapshot.name == name }) {
                state.interfaces[i].snapshot.isUp = up
            }
        }
    }

    public func setReachable(_ name: String, _ hosts: Set<String>) {
        state.withLock { state in
            if let i = state.interfaces.firstIndex(where: { $0.snapshot.name == name }) {
                state.interfaces[i].reachable = Set(hosts.map(Self.canonical))
            }
        }
    }

    /// Replace `name`'s addresses; its first is the local address of paths on it.
    public func setAddresses(_ name: String, _ addresses: [String]) {
        state.withLock { state in
            if let i = state.interfaces.firstIndex(where: { $0.snapshot.name == name }) {
                state.interfaces[i].snapshot.addresses = addresses
            }
        }
    }

    public func setRouteTable(_ name: String?) {
        state.withLock { $0.routeTable = name }
    }

    /// The path inbound datagrams are reported as having arrived on, until changed.
    public func setArrival(_ name: String) {
        state.withLock { $0.arrival = name }
    }

    /// Every send that left, in order, with the path it used.
    public var sends: [(data: Data, to: MatterAddress, path: MatterPath)] {
        state.withLock { $0.sends }
    }

    public var policy: InterfacePolicy {
        state.withLock { $0.monitor.policy }
    }

    // MARK: - MatterUDPTransport

    public func send(_ data: Data, to address: MatterAddress) async throws {
        _ = try await send(data, to: address, via: nil)
    }

    public func send(_ data: Data, to address: MatterAddress, via path: MatterPath?) async throws -> MatterSendResult? {
        let host = Self.canonical(address.host)
        let result: MatterSendResult
        if let path {
            let reaches = state.withLock { state in
                state.interfaces.first(where: { $0.snapshot.index == path.interfaceIndex && $0.snapshot.name == path.interfaceName })
                    .map { $0.snapshot.isUp && $0.reachable.contains(host) } ?? false
            }
            guard reaches else {
                logger.debug("UDP send by \(path) to \(host): failed: errno=\(EHOSTUNREACH) (\(String(cString: strerror(EHOSTUNREACH))))")
                throw TransportPathError.pathUnavailable(path, errno: EHOSTUNREACH)
            }
            result = MatterSendResult(path: path, selection: nil)
        } else {
            let (interfaces, routeTable, changes, policy) = state.withLock { state in
                let snapshots = state.interfaces.map(\.snapshot)
                return (state.interfaces, state.routeTable, state.monitor.update(snapshots), state.monitor.policy)
            }
            logInterfaceChanges(changes)
            func reaches(_ interface: Interface) -> Bool { interface.snapshot.isUp && interface.reachable.contains(host) }
            let selection = PathSelector(policy: policy).select(interfaces: interfaces.map(\.snapshot)) { snapshot in
                if let snapshot {
                    guard let i = interfaces.first(where: { $0.snapshot.name == snapshot.name }), reaches(i) else { return nil }
                    return (snapshot.index, snapshot.addresses.first ?? "")
                }
                guard let routeTable, let i = interfaces.first(where: { $0.snapshot.name == routeTable }), reaches(i) else { return nil }
                return (i.snapshot.index, i.snapshot.addresses.first ?? "")
            }
            guard let selected = selection.path, let how = selection.outcome else {
                logger.debug("No allowed route to \(host) under \(policy)")
                throw TransportPathError.noAllowedRoute(peer: address)
            }
            if !selection.skipped.isEmpty {
                let skips = selection.skipped.map { "\($0.name) preferred, \(Self.reason($0.reason))" }
                logger.info("Path to \(host): \(skips.joined(separator: "; ")); using \(selected.interfaceName) (\(selected.localAddress))")
            }
            result = MatterSendResult(path: selected, selection: how)
        }
        try await endpoint.send(data, to: address)
        state.withLock { $0.sends.append((data, address, result.path)) }
        return result
    }

    /// Each stream is built once and returned on every call: a fresh pump per call would end
    /// the shared underlying stream when one consumer stops.
    public func receiveDatagrams() -> AsyncStream<MatterDatagram> {
        state.withLock { state in
            if let existing = state.datagrams { return existing }
            let source = endpoint.receive()
            let (stream, continuation) = AsyncStream<MatterDatagram>.makeStream()
            let pump = Task { [self] in
                for await (data, sender) in source {
                    continuation.yield(MatterDatagram(data: data, sender: sender, path: arrivalPath()))
                }
                continuation.finish()
            }
            continuation.onTermination = { _ in pump.cancel() }
            state.datagrams = stream
            return stream
        }
    }

    public func receive() -> AsyncStream<(Data, MatterAddress)> {
        let datagrams = receiveDatagrams()
        return state.withLock { state in
            if let existing = state.legacy { return existing }
            let (stream, continuation) = AsyncStream<(Data, MatterAddress)>.makeStream()
            let pump = Task {
                for await datagram in datagrams { continuation.yield((datagram.data, datagram.sender)) }
                continuation.finish()
            }
            continuation.onTermination = { _ in pump.cancel() }
            state.legacy = stream
            return stream
        }
    }

    public func bind(port: UInt16) async throws {
        try await endpoint.bind(port: port)
    }

    public func close() async {
        await endpoint.close()
    }

    public func setInterfacePolicy(_ policy: InterfacePolicy) async {
        let changes = state.withLock { state in
            state.monitor = InterfacePolicyMonitor(policy: policy)
            return state.monitor.update(state.interfaces.map(\.snapshot))
        }
        logger.debug("Matter interface policy: \(policy)")
        logInterfaceChanges(changes)
    }

    // MARK: - Helpers

    private func arrivalPath() -> MatterPath? {
        state.withLock { state in
            guard let name = state.arrival,
                  let i = state.interfaces.first(where: { $0.snapshot.name == name }) else { return nil }
            return MatterPath(
                interfaceIndex: i.snapshot.index, interfaceName: name,
                localAddress: i.snapshot.addresses.first ?? "")
        }
    }

    private static func canonical(_ host: String) -> String {
        MatterAddress(host: host, port: 0).canonicalised.host
    }

    private func logInterfaceChanges(_ changes: [(name: String, problem: InterfaceProblem?)]) {
        for change in changes {
            switch change.problem {
            case .down?:
                logger.warning("Interface \(change.name) named in the Matter interface policy is down")
            case .missing?:
                logger.warning("Interface \(change.name) named in the Matter interface policy is missing")
            case nil:
                logger.info("Interface \(change.name) named in the Matter interface policy is available again")
            }
        }
    }

    private static func reason(_ skip: PathSelection.Skip) -> String {
        switch skip {
        case .missing: "missing"
        case .down: "down"
        case .excluded: "excluded"
        case .noRoute: "no route"
        }
    }
}
