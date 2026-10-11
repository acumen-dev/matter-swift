// FaultInjectingLink.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Synchronization
import MatterProtocol
import MatterTransport

/// Two in-memory `MatterUDPTransport` endpoints joined by a link that drops
/// datagrams per direction, reproducibly from a seed, and lets a test
/// script any datagram's fate (delay, duplicate, drop; reordering is a
/// delay) through an interceptor. Each direction has its own generator, so
/// how the two directions interleave never changes either one's sequence.
///
/// Everything one endpoint sends is delivered to the other whatever the
/// destination address; the receiver sees the sending endpoint's `address`
/// as the source unless ``FaultInjectingEndpoint/send(_:to:from:)`` names
/// another.
public final class FaultInjectingLink: Sendable {

    public enum Side: Sendable, Hashable {
        case a
        case b

        var other: Side { self == .a ? .b : .a }
    }

    /// An interceptor's verdict on one datagram.
    public enum Delivery: Sendable, Equatable {
        /// Deliver once, after `after` (`.zero` = now).
        case deliver(after: Duration)
        /// Deliver now and a second copy `after` later.
        case duplicate(after: Duration)
        case drop
    }

    /// Endpoint `a` (10.0.0.1:5540) — conventionally the controller.
    public let a: FaultInjectingEndpoint
    /// Endpoint `b` (10.0.0.2:5540) — conventionally the device or scripted peer.
    public let b: FaultInjectingEndpoint
    private let core: LinkCore

    /// - Parameter clock: clock for delayed deliveries; `nil` uses `ContinuousClock`.
    ///   A ``ManualClock`` delivers them from ``ManualClock/advance(by:)``.
    public init(seed: UInt64, clock: (any MRPClock)? = nil) {
        let (streamA, continuationA) = AsyncStream<(Data, MatterAddress)>.makeStream()
        let (streamB, continuationB) = AsyncStream<(Data, MatterAddress)>.makeStream()
        let core = LinkCore(seed: seed, clock: clock, toA: continuationA, toB: continuationB)
        self.core = core
        self.a = FaultInjectingEndpoint(address: MatterAddress(host: "10.0.0.1", port: 5540), side: .a, core: core, stream: streamA)
        self.b = FaultInjectingEndpoint(address: MatterAddress(host: "10.0.0.2", port: 5540), side: .b, core: core, stream: streamB)
    }

    /// Drop each datagram sent from `side` with probability `p` (seeded).
    public func setDropProbability(_ p: Double, from side: Side) {
        core.update(side) { $0.dropProbability = p }
    }

    /// Drop the next `count` datagrams sent from `side`, before any other rule.
    public func dropNext(_ count: Int, from side: Side) {
        core.update(side) { $0.dropNext += count }
    }

    /// Decide each datagram's fate instead of the drop probability (after
    /// `dropNext`). Runs outside the link's lock but must not block.
    public func setInterceptor(_ interceptor: (@Sendable (Data, Side) -> Delivery)?) {
        core.setInterceptor(interceptor)
    }

    /// Every datagram sent from `side`, delivered or not, in send order.
    public func sent(from side: Side) -> [Data] {
        core.read(side) { $0.log }
    }

    /// Datagrams yielded to `side`'s receive stream so far.
    public func deliveredCount(to side: Side) -> Int {
        core.read(side.other) { $0.delivered }
    }
}

/// One end of a ``FaultInjectingLink``.
public final class FaultInjectingEndpoint: MatterUDPTransport, Sendable {
    public let address: MatterAddress
    let side: FaultInjectingLink.Side
    let core: LinkCore
    let stream: AsyncStream<(Data, MatterAddress)>

    init(address: MatterAddress, side: FaultInjectingLink.Side, core: LinkCore, stream: AsyncStream<(Data, MatterAddress)>) {
        self.address = address
        self.side = side
        self.core = core
        self.stream = stream
    }

    public func send(_ data: Data, to address: MatterAddress) async throws {
        core.transmit(data, from: side, sender: self.address)
    }

    /// Send with a different apparent source address (a second peer, or a
    /// peer whose port changed).
    public func send(_ data: Data, to address: MatterAddress, from source: MatterAddress) async throws {
        core.transmit(data, from: side, sender: source)
    }

    public func receive() -> AsyncStream<(Data, MatterAddress)> {
        stream
    }

    public func bind(port: UInt16) async throws {}

    public func close() async {
        core.finish(side)
    }
}

// MARK: - Link core

final class LinkCore: Sendable {
    typealias Side = FaultInjectingLink.Side
    typealias Delivery = FaultInjectingLink.Delivery
    typealias Interceptor = @Sendable (Data, Side) -> Delivery

    struct Direction: Sendable {
        var dropProbability = 0.0
        var rng: SplitMix64
        var dropNext = 0
        var log: [Data] = []
        var delivered = 0
    }

    struct State: Sendable {
        var fromA: Direction
        var fromB: Direction
        var interceptor: Interceptor?

        subscript(side: Side) -> Direction {
            get { side == .a ? fromA : fromB }
            set {
                if side == .a { fromA = newValue } else { fromB = newValue }
            }
        }
    }

    private enum Decision: Sendable {
        case dropped
        case intercept(Interceptor)
        case decided(Delivery)
    }

    private let state: Mutex<State>
    private let clock: (any MRPClock)?
    private let toA: AsyncStream<(Data, MatterAddress)>.Continuation
    private let toB: AsyncStream<(Data, MatterAddress)>.Continuation

    init(
        seed: UInt64,
        clock: (any MRPClock)?,
        toA: AsyncStream<(Data, MatterAddress)>.Continuation,
        toB: AsyncStream<(Data, MatterAddress)>.Continuation
    ) {
        state = Mutex(State(
            fromA: Direction(rng: SplitMix64(seed: seed)),
            fromB: Direction(rng: SplitMix64(seed: seed ^ 0xD1B5_4A32_D192_ED03)),
            interceptor: nil
        ))
        self.clock = clock
        self.toA = toA
        self.toB = toB
    }

    func update(_ side: Side, _ body: (inout Direction) -> Void) {
        state.withLock { body(&$0[side]) }
    }

    func read<T: Sendable>(_ side: Side, _ body: (Direction) -> T) -> T {
        state.withLock { body($0[side]) }
    }

    func setInterceptor(_ interceptor: Interceptor?) {
        state.withLock { $0.interceptor = interceptor }
    }

    func finish(_ side: Side) {
        (side == .a ? toA : toB).finish()
    }

    /// Apply the faults for one datagram sent from `side`.
    func transmit(_ data: Data, from side: Side, sender: MatterAddress) {
        let decision: Decision = state.withLock { state in
            var direction = state[side]
            defer { state[side] = direction }
            direction.log.append(data)
            if direction.dropNext > 0 {
                direction.dropNext -= 1
                return .dropped
            }
            if let interceptor = state.interceptor {
                return .intercept(interceptor)
            }
            let dropped = Double(direction.rng.next() >> 11) * 0x1.0p-53 < direction.dropProbability
            return .decided(dropped ? .drop : .deliver(after: .zero))
        }

        let delivery: Delivery
        switch decision {
        case .dropped:
            return
        case .intercept(let interceptor):
            delivery = interceptor(data, side)
        case .decided(let decided):
            delivery = decided
        }

        switch delivery {
        case .drop:
            return
        case .deliver(let delay):
            deliver(data, from: side, sender: sender, after: delay)
        case .duplicate(let delay):
            deliver(data, from: side, sender: sender, after: .zero)
            deliver(data, from: side, sender: sender, after: delay)
        }
    }

    private func deliver(_ data: Data, from side: Side, sender: MatterAddress, after delay: Duration) {
        if delay > .zero {
            schedule(data, from: side, sender: sender, after: delay)
        } else {
            deliverNow(data, from: side, sender: sender)
        }
    }

    private func deliverNow(_ data: Data, from side: Side, sender: MatterAddress) {
        state.withLock { $0[side].delivered += 1 }
        (side == .a ? toB : toA).yield((data, sender))
    }

    private func schedule(_ data: Data, from side: Side, sender: MatterAddress, after delay: Duration) {
        let deliver: @Sendable () -> Void = { [self] in
            self.deliverDelayed(data, from: side, sender: sender)
        }
        if let manual = clock as? ManualClock {
            manual.schedule(at: manual.now + delay, deliver)
            return
        }
        let clock: any MRPClock = self.clock ?? ContinuousClock()
        let deadline = clock.now + delay
        Task {
            do {
                try await clock.sleep(until: deadline)
            } catch {
                return
            }
            deliver()
        }
    }

    private func deliverDelayed(_ data: Data, from side: Side, sender: MatterAddress) {
        deliverNow(data, from: side, sender: sender)
    }
}
