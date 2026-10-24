# Multi-homed interface paths — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Matter's UDP transport on a multi-homed host sends to each peer by a pinned
interface and source address, chosen under a user-set interface policy, and CASE honours a
peer's `busy` wait.

**Architecture:** A POSIX socket core in `MatterTransport` (C shim for `sendmsg`/`recvmsg`
with `PKTINFO`) under both platform transports; a pure `PathSelector` applies the
`InterfacePolicy`; the controller messenger and the device server record each exchange's and
session's path and pass it back on every send. acumen-matter stores the policy in each
agent's ConfigStore and exposes a Network interfaces admin flow.

**Tech Stack:** Swift 6.2, SwiftPM, Swift Testing, POSIX sockets (Darwin/Glibc), a C target,
swift-log, swift-metrics, swift-distributed-tracing.

**Spec:** `docs/design/multihomed-interface-paths.md` (same directory). Read it first.

## Global Constraints

- swift-matter branch `feat/multihomed-interface-paths` (exists, spec committed). acumen-matter
  branch `feat/interface-policy`, cut from `origin/main` in David's checkout. No worktrees.
- swift-matter is consumed by tag: acumen-matter pins `from: "1.0.0-beta.9"`; this work ships
  as `1.0.0-beta.10`, and **the tag needs David's approval**.
- Never restart, stop or start the house process (Monagle Manor). Stop at "built".
- The controller keeps the port it binds (`0` in acumen-matter); the bridge binds `5540`. Every
  send leaves from the bound port.
- `InterfacePolicy` semantics: allowed = up interfaces minus `excluded`; `preferred` is an order,
  not an allow-list; unlisted interfaces rank after listed ones.
- Re-pin only on authenticated (decrypted, counter-accepted) traffic. Unsecured traffic never
  moves a pin.
- Logging: fall-through and re-pin at info; named interface missing/down at warning (on apply and
  on state change only); per-datagram path at trace. Debug/trace instrumentation is permanent.
- Metrics (label prefix from configuration, default `matter`):
  `<prefix>_transport_path_selections_total{outcome=preferred|fallthrough|route_table}`,
  `<prefix>_transport_path_repins_total{reason=arrival|route_lost}`,
  `<prefix>_case_busy_waits_total`.
- Linux gate: `swift:6.2-noble`, `--cpus=2`, arm64. Check Docker disk first
  (`docker system df`; the VM disk is shared with the house's ClickHouse); remove gate volumes after.
- File header style: `// <File>.swift` / `// Copyright 2026 Monagle Pty Ltd`.
- Tests use Swift Testing (`import Testing`, `@Suite`, `@Test`, `#expect`, `#require`). Socket
  suites are `.serialized` with a `.timeLimit`.

## Deviations from the spec, decided while planning

1. `send(_:to:via:)` returns `MatterSendResult?` (path plus the selection outcome when one was
   made) instead of `MatterPath?`, so the messenger can count selections without
   `MatterTransport` depending on swift-metrics.
2. The busy wait runs on a new `MatterController.Configuration.retryClock` (default
   `ContinuousClock()`): the controller's messenger clock is not injectable from the controller,
   and `discoveryClock` is documented as not covering protocol timing.
3. The device server pins **per peer address** rather than per session: its `SessionEntry.address`
   is fixed for the session's life, so keying by address gives the same behaviour (handshake pins on
   first arrival, the session inherits it, authenticated arrival re-pins) with one lookup at one
   send helper.

---

## File structure

swift-matter:

| File | Responsibility |
|---|---|
| `Sources/CMatterSockets/include/CMatterSockets.h`, `Sources/CMatterSockets/CMatterSockets.c` | C shim: socket options, `sendmsg` with `IPV6_PKTINFO`/`IP_PKTINFO`, `recvmsg` returning arrival ifindex + destination address, scoped route probe. `#ifdef __APPLE__` / Linux. |
| `Sources/MatterTransport/MatterPath.swift` | `MatterPath`, `MatterDatagram`, `MatterSendResult`, `TransportPathError`. |
| `Sources/MatterTransport/UDPTransport.swift` (modify) | Protocol requirements `receiveDatagrams()`, `send(_:to:via:)`, `setInterfacePolicy(_:)` with defaults. |
| `Sources/MatterTransport/InterfacePolicy.swift` | `InterfacePolicy`, `InterfaceSnapshot`, `PathSelector`, `PathSelection`, `InterfacePolicyMonitor`. Pure. |
| `Sources/MatterTransport/POSIXInterfaces.swift` | `getifaddrs` listing and `routeProbe(peer:interface:)` (public: acumen-matter's flow uses them). |
| `Sources/MatterTransport/POSIXUDPSocketCore.swift` | Sockets, receive threads, pinned send, selection under policy, logging. |
| `Sources/MatterApple/AppleUDPTransport.swift` (rewrite) | Thin actor over the core. |
| `Sources/MatterLinux/LinuxUDPTransport.swift` (rewrite) | Thin actor over the core; no NIO. |
| `Sources/MatterTestSupport/MultiInterfaceEndpoint.swift` | Fake multi-interface transport over a `FaultInjectingLink` endpoint. |
| `Sources/MatterController/Messaging/ControllerMessenger*.swift` (modify) | Exchange/session pins, re-pin, route loss, telemetry. |
| `Sources/MatterController/MatterController.swift` (modify) | `interfaces`, `retryClock`, busy wait, path to `registerSession`. |
| `Sources/MatterDevice/Server/MatterDeviceServer.swift` (modify) | `Config.interfaces`, per-peer pins, one send helper. |
| `Tests/MatterTransportTests/*` (new target) | Selector, monitor, core on loopback. |

acumen-matter:

| File | Responsibility |
|---|---|
| `Sources/AcumenMatterCore/InterfacePolicyStore.swift` | ConfigStore keys ↔ `InterfacePolicy`. |
| `Sources/AcumenMatterCore/NetworkInterfacesFlow.swift` | Shared admin flow (view + set). |
| Agent/Exposure registration + apply paths | Register the flow, apply via reload / server restart. |

---

### Task 1: C shim and path types

**Files:**
- Create: `Sources/CMatterSockets/include/CMatterSockets.h`, `Sources/CMatterSockets/CMatterSockets.c`
- Create: `Sources/MatterTransport/MatterPath.swift`
- Modify: `Package.swift` (C target; `MatterTransport` depends on it; new `MatterTransportTests` target)
- Test: `Tests/MatterTransportTests/SocketShimTests.swift`

**Interfaces:**
- Produces (C): `int cms_open_udp(int family, uint16_t port, int *err)` (binds, `V6ONLY` for v6,
  `SO_REUSEADDR`, enables `IPV6_RECVPKTINFO` / Darwin `IP_RECVPKTINFO` / Linux `IP_PKTINFO`);
  `ssize_t cms_send(int fd, const void *buf, size_t len, const struct sockaddr *dst, socklen_t dstlen, uint32_t ifindex, const char *src_literal)`
  (`ifindex` 0 and `src_literal` NULL/"" mean unset; adds the `PKTINFO` cmsg only when either is set);
  `ssize_t cms_recv(int fd, void *buf, size_t len, struct sockaddr_storage *from, uint32_t *ifindex, char *dst_literal, size_t dst_cap)`;
  `int cms_route_probe(int family, const char *peer_literal, uint32_t scope_ifindex, uint32_t ifindex, char *src_out, size_t src_cap)`
  (0 = route, `src_out` = source the kernel picks; otherwise errno; `ifindex` 0 = unscoped);
  `uint16_t cms_bound_port(int fd)`.
- Produces (Swift, `MatterTransport`):

```swift
public struct MatterPath: Sendable, Hashable, CustomStringConvertible {
    public var interfaceIndex: UInt32
    public var interfaceName: String
    /// Canonical literal, no zone.
    public var localAddress: String
    public init(interfaceIndex: UInt32, interfaceName: String, localAddress: String)
    public var description: String { "\(interfaceName)/\(localAddress)" }
}

public struct MatterDatagram: Sendable {
    public var data: Data
    public var sender: MatterAddress
    /// nil when the transport cannot tell.
    public var path: MatterPath?
    public init(data: Data, sender: MatterAddress, path: MatterPath?)
}

public enum PathSelectionOutcome: String, Sendable { case preferred, fallthrough, routeTable = "route_table" }

public struct MatterSendResult: Sendable, Equatable {
    public var path: MatterPath
    /// Set when this send selected the path (no `via`); nil when it used a pinned one.
    public var selection: PathSelectionOutcome?
}

public enum TransportPathError: Error, Sendable, Equatable {
    /// A pinned path can no longer reach the peer (EHOSTUNREACH, ENETUNREACH, EADDRNOTAVAIL).
    case pathUnavailable(MatterPath, errno: Int32)
    /// No allowed interface has a route to the peer.
    case noAllowedRoute(peer: MatterAddress)
}
```

- [ ] **Step 1: Write the failing shim test** (loopback, both families)

```swift
// SocketShimTests.swift
import Testing
import Foundation
import CMatterSockets
@testable import MatterTransport

@Suite("C socket shim", .serialized, .timeLimit(.minutes(1)))
struct SocketShimTests {
    @Test("PKTINFO send keeps the bound source port and recv reports the arrival path (IPv6)")
    func pktinfoKeepsPortV6() throws {
        var err: Int32 = 0
        let rx = cms_open_udp(AF_INET6, 0, &err); try #require(rx >= 0)
        let tx = cms_open_udp(AF_INET6, 0, &err); try #require(tx >= 0)
        defer { close(rx); close(tx) }
        let lo = loopbackIndex()
        var dst = sockaddr_in6.loopback(port: cms_bound_port(rx))
        let sent = withUnsafePointer(to: &dst) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                cms_send(tx, [UInt8(1)], 1, $0, socklen_t(MemoryLayout<sockaddr_in6>.size), lo, "::1")
            }
        }
        #expect(sent == 1)
        var buf = [UInt8](repeating: 0, count: 16); var from = sockaddr_storage(); var ifindex: UInt32 = 0
        var dstText = [CChar](repeating: 0, count: 64)
        let n = cms_recv(rx, &buf, 16, &from, &ifindex, &dstText, 64)
        #expect(n == 1)
        #expect(from.port == cms_bound_port(tx))      // the bound port, not an ephemeral one
        #expect(ifindex == lo)
        #expect(String(cString: dstText) == "::1")
    }

    @Test("Route probe answers on loopback and refuses an unreachable scope")
    func routeProbe() {
        var src = [CChar](repeating: 0, count: 64)
        #expect(cms_route_probe(AF_INET6, "::1", 0, 0, &src, 64) == 0)
        #expect(String(cString: src) == "::1")
    }
}
```

Add `loopbackIndex()` (`if_nametoindex("lo0")` on Darwin, `"lo"` on Linux), `sockaddr_in6.loopback(port:)`
and `sockaddr_storage.port` as `fileprivate` helpers in the test file, plus the IPv4 twin of the
first test (`127.0.0.1`).

- [ ] **Step 2: Run, expect a build failure** — `swift test --filter SocketShimTests` → "no such module 'CMatterSockets'".
- [ ] **Step 3: Implement the shim.** Use `#define __APPLE_USE_RFC_3542 1` before the includes on
  Darwin and `#define _GNU_SOURCE` on Linux. `cms_send` builds one cmsg: v6 `IPPROTO_IPV6/IPV6_PKTINFO`
  with `struct in6_pktinfo {ipi6_addr, ipi6_ifindex}`; v4 `IPPROTO_IP/IP_PKTINFO` with
  `struct in_pktinfo {ipi_ifindex, ipi_spec_dst}`. `cms_recv` walks cmsgs for `IPV6_PKTINFO` /
  `IP_PKTINFO` (Linux) / `IP_RECVDSTADDR`+`IP_RECVIF` fallback only if Darwin rejects
  `IP_RECVPKTINFO`. `cms_route_probe`: `socket(family, SOCK_DGRAM)`, scope with `IPV6_BOUND_IF`/`IP_BOUND_IF`
  (Darwin) or `IPV6_UNICAST_IF`/`IP_UNICAST_IF` (Linux, v4 value in network byte order) when
  `ifindex != 0`, `connect()` to port 9, `getsockname()` → `inet_ntop`, close; `scope_ifindex` sets
  `sin6_scope_id` for link-local peers. Package.swift:

```swift
.target(name: "CMatterSockets", dependencies: []),
// MatterTransport: add "CMatterSockets" to dependencies
.testTarget(name: "MatterTransportTests", dependencies: ["MatterTransport", "CMatterSockets", "MatterTestSupport"]),
```

  Write `MatterPath.swift` exactly as in Interfaces.
- [ ] **Step 4: Verify on Darwin that `IP_PKTINFO` on send works for IPv4.** If the IPv4 test fails
  on macOS, fall back in the C code to `IP_BOUND_IF` set/clear around `sendto` for IPv4 only and note
  it in the C file's header comment. Run `swift test --filter SocketShimTests` → PASS.
- [ ] **Step 5: Commit** — `git add Package.swift Sources/CMatterSockets Sources/MatterTransport/MatterPath.swift Tests/MatterTransportTests && git commit -m "Transport: C socket shim for PKTINFO sends and arrival paths"`

### Task 2: Interface policy and path selection (pure)

**Files:**
- Create: `Sources/MatterTransport/InterfacePolicy.swift`
- Test: `Tests/MatterTransportTests/PathSelectorTests.swift`

**Interfaces:**
- Consumes: `MatterPath`, `PathSelectionOutcome`, `MatterAddress`.
- Produces:

```swift
public struct InterfacePolicy: Sendable, Equatable, CustomStringConvertible {
    public var preferred: [String]
    public var excluded: Set<String>
    public init(preferred: [String] = [], excluded: Set<String> = [])
    public static let automatic = InterfacePolicy()
    public func allows(_ interfaceName: String) -> Bool { !excluded.contains(interfaceName) }
}

public struct InterfaceSnapshot: Sendable, Equatable {
    public var name: String
    public var index: UInt32
    public var isUp: Bool          // IFF_UP && IFF_RUNNING
    public var addresses: [String] // canonical literals, link-local without zone
    public init(name: String, index: UInt32, isUp: Bool, addresses: [String])
}

public enum InterfaceProblem: Sendable, Equatable { case missing, down }

public struct PathSelection: Sendable, Equatable {
    public enum Skip: Sendable, Equatable { case missing, down, excluded, noRoute }
    public var path: MatterPath?
    public var outcome: PathSelectionOutcome?
    /// Preferred interfaces passed over before the chosen one, in order, with why.
    public var skipped: [(name: String, reason: Skip)]  // implement Equatable by hand
}

public struct PathSelector: Sendable {
    public init(policy: InterfacePolicy)
    /// `route(interface)` returns the source address that interface would use for `peer`, or nil
    /// (no route). `route(nil)` is the unscoped route table's choice: (interface index, source).
    public func select(
        interfaces: [InterfaceSnapshot],
        route: (InterfaceSnapshot?) -> (index: UInt32, source: String)?
    ) -> PathSelection
}

/// Tracks which named interfaces are missing or down, so each change is logged once.
public struct InterfacePolicyMonitor: Sendable {
    public init(policy: InterfacePolicy)
    /// Problems with named (preferred or excluded) interfaces now, keyed by name.
    public static func problems(policy: InterfacePolicy, interfaces: [InterfaceSnapshot]) -> [String: InterfaceProblem]
    /// Changes since the last call: (name, problem now, or nil = resolved).
    public mutating func update(_ interfaces: [InterfaceSnapshot]) -> [(name: String, problem: InterfaceProblem?)]
}
```

Selection algorithm (spec §1): for each `preferred` name in order — missing → skip `.missing`;
down → `.down`; excluded → `.excluded`; `route(iface) == nil` → `.noRoute`; else choose, outcome
`.preferred` if nothing was skipped, otherwise `.fallthrough`. Then `route(nil)`: if it names an
interface that is up and allowed, choose it, outcome `.routeTable` when `preferred` is empty, else
`.fallthrough`. Then the remaining up, allowed, unlisted interfaces in snapshot order with a route,
outcome `.fallthrough`. Else `path == nil`.

- [ ] **Step 1: Write the failing tests**

```swift
// PathSelectorTests.swift
import Testing
@testable import MatterTransport

private let en0 = InterfaceSnapshot(name: "en0", index: 7, isUp: true, addresses: ["fd48::a"])
private let en1 = InterfaceSnapshot(name: "en1", index: 15, isUp: true, addresses: ["fd48::b"])
private func routes(_ map: [String: String], table: String?) -> (InterfaceSnapshot?) -> (index: UInt32, source: String)? {
    { iface in
        guard let iface else {
            guard let table, let s = map[table] else { return nil }
            return (table == "en0" ? 7 : 15, s)
        }
        return map[iface.name].map { (iface.index, $0) }
    }
}

@Suite("PathSelector")
struct PathSelectorTests {
    @Test("Automatic uses the route table's choice")
    func automatic() {
        let s = PathSelector(policy: .automatic).select(interfaces: [en0, en1], route: routes(["en0": "fd48::a"], table: "en0"))
        #expect(s.path == MatterPath(interfaceIndex: 7, interfaceName: "en0", localAddress: "fd48::a"))
        #expect(s.outcome == .routeTable)
    }

    @Test("The first preferred interface with a route wins")
    func preferred() {
        let s = PathSelector(policy: .init(preferred: ["en1", "en0"]))
            .select(interfaces: [en0, en1], route: routes(["en0": "fd48::a", "en1": "fd48::b"], table: "en0"))
        #expect(s.path?.interfaceName == "en1")
        #expect(s.outcome == .preferred)
    }

    @Test("A preferred interface with no route falls through, and says why")
    func fallthrough() {
        let s = PathSelector(policy: .init(preferred: ["en1", "en0"]))
            .select(interfaces: [en0, en1], route: routes(["en0": "fd48::a"], table: "en0"))
        #expect(s.path?.interfaceName == "en0")
        #expect(s.outcome == .fallthrough)
        #expect(s.skipped.map(\.name) == ["en1"])
        #expect(s.skipped.first?.reason == .noRoute)
    }

    @Test("An excluded interface is never chosen, even as the route table's choice")
    func excluded() {
        let s = PathSelector(policy: .init(excluded: ["en0"]))
            .select(interfaces: [en0, en1], route: routes(["en0": "fd48::a", "en1": "fd48::b"], table: "en0"))
        #expect(s.path?.interfaceName == "en1")
        let none = PathSelector(policy: .init(excluded: ["en0"]))
            .select(interfaces: [en0, en1], route: routes(["en0": "fd48::a"], table: "en0"))
        #expect(none.path == nil)
    }

    @Test("Missing and down preferred interfaces are skipped with their reason")
    func missingAndDown() {
        var down1 = en1; down1.isUp = false
        let s = PathSelector(policy: .init(preferred: ["en9", "en1", "en0"]))
            .select(interfaces: [en0, down1], route: routes(["en0": "fd48::a", "en1": "fd48::b"], table: "en0"))
        #expect(s.path?.interfaceName == "en0")
        #expect(s.skipped.map(\.reason) == [.missing, .down])
    }

    @Test("The monitor reports each named interface's problem once, and its recovery")
    func monitor() {
        var m = InterfacePolicyMonitor(policy: .init(preferred: ["en1"], excluded: ["en9"]))
        var down1 = en1; down1.isUp = false
        #expect(m.update([en0, down1]).map(\.name).sorted() == ["en1", "en9"])
        #expect(m.update([en0, down1]).isEmpty)
        let recovered = m.update([en0, en1])
        #expect(recovered.count == 1 && recovered[0].name == "en1" && recovered[0].problem == nil)
    }
}
```

- [ ] **Step 2: Run** `swift test --filter PathSelectorTests` → FAIL (types missing).
- [ ] **Step 3: Implement** `InterfacePolicy.swift` per the Interfaces block and algorithm. A missing
  excluded interface is a `.missing` problem too (it may be a typo).
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** — `git commit -m "Transport: interface policy, path selection and interface monitoring"`

### Task 3: POSIX core, interface listing, and the platform transports over it

**Files:**
- Create: `Sources/MatterTransport/POSIXInterfaces.swift`, `Sources/MatterTransport/POSIXUDPSocketCore.swift`
- Modify: `Sources/MatterTransport/UDPTransport.swift`
- Rewrite: `Sources/MatterApple/AppleUDPTransport.swift`, `Sources/MatterLinux/LinuxUDPTransport.swift`
- Modify: `Package.swift` (MatterLinux keeps NIO only for discovery; drop NIO from `MatterLinuxTests` if unused)
- Test: `Tests/MatterTransportTests/POSIXUDPSocketCoreTests.swift`; update `Tests/MatterAppleTests/AppleUDPTransportTests.swift`, `Tests/MatterLinuxTests/LinuxTransportTests.swift`

**Interfaces:**
- Consumes: Task 1 shim and types; Task 2 `PathSelector`, `InterfacePolicyMonitor`.
- Produces:

```swift
// UDPTransport.swift — added requirements, with defaults in an extension
public protocol MatterUDPTransport: Sendable {
    func send(_ data: Data, to address: MatterAddress) async throws
    func receive() -> AsyncStream<(Data, MatterAddress)>
    func bind(port: UInt16) async throws
    func close() async
    func receiveDatagrams() -> AsyncStream<MatterDatagram>
    func send(_ data: Data, to address: MatterAddress, via path: MatterPath?) async throws -> MatterSendResult?
    func setInterfacePolicy(_ policy: InterfacePolicy) async
}
extension MatterUDPTransport {
    public func receiveDatagrams() -> AsyncStream<MatterDatagram> { /* map receive(), path nil */ }
    public func send(_ data: Data, to address: MatterAddress, via path: MatterPath?) async throws -> MatterSendResult? {
        try await send(data, to: address); return nil
    }
    public func setInterfacePolicy(_ policy: InterfacePolicy) async {}
}

// POSIXInterfaces.swift
public enum POSIXInterfaces {
    public static func snapshot() -> [InterfaceSnapshot]
    /// Source address `interface` would use to reach `peer`; nil = no route. nil interface = unscoped.
    public static func route(to peer: MatterAddress, via interface: InterfaceSnapshot?) -> (index: UInt32, source: String)?
}

// POSIXUDPSocketCore.swift
public final class POSIXUDPSocketCore: Sendable {   // state behind a Mutex
    public init(logger: Logger)
    public func bind(port: UInt16) throws             // v6 first; v4 on the port v6 got
    public var boundPort: UInt16? { get }
    public var datagrams: AsyncStream<MatterDatagram> { get }
    public func setPolicy(_ policy: InterfacePolicy)   // logs warning per named missing/down interface
    public func send(_ data: Data, to address: MatterAddress, via path: MatterPath?) throws -> MatterSendResult
    public func close()
}
```

Core `send` rules:
- strip brackets; a `%zone` on a link-local host sets `scope_ifindex`;
- `via != nil`: `cms_send` with `via.interfaceIndex`/`via.localAddress`; errno in
  {`EHOSTUNREACH`, `ENETUNREACH`, `EADDRNOTAVAIL`} → `TransportPathError.pathUnavailable(via, errno:)`;
  other errno → `TransportError.sendFailed`;
- `via == nil`: `PathSelector(policy).select(interfaces: POSIXInterfaces.snapshot(), route: { POSIXInterfaces.route(to: address, via: $0) })`.
  Before selecting, run the monitor and log each change at warning (`"Interface en1 named in the
  Matter interface policy is down"` / `"… is missing"`) or info on recovery. A selection with skips
  logs at info: `"Path to <peer>: en1 preferred, no route; using en0 (fd48::a)"`. `path == nil` →
  `TransportPathError.noAllowedRoute(peer:)`. Then send pinned as above and return
  `MatterSendResult(path:, selection: outcome)`;
- trace log per send: host, port, length, path.

Receive threads (one per socket) call `cms_recv`, build `MatterAddress` exactly as the current Apple
receive loop does (append `%ifname` for link-local senders), resolve `ifindex → name` with
`if_indextoname`, and yield `MatterDatagram(data:sender:path:)`. `receive()` on the wrappers maps
`datagrams` to `(data, sender)`.

`AppleUDPTransport` / `LinuxUDPTransport` keep their public `init(logger:)`, `bind(port:)`,
`boundPort()`, `receive()`, `close()`, and add the three requirements by delegating to the core.
Remove the `IPV6_BOUND_IF` toggle and its doc paragraphs; replace the class doc's "Source-port
correctness" and "Link-local routing" sections with: one socket per family bound to the port; every
send carries `PKTINFO`; measured on macOS 27 that `PKTINFO` on a bound socket keeps the bound port.

- [ ] **Step 1: Write failing core tests** (`POSIXUDPSocketCoreTests`, `.serialized`, `.timeLimit(.minutes(2))`):
  - "A selected send returns the path and leaves from the bound port": two cores on `[::]:0`, send
    `via: nil` to `::1:<rx port>`; result path interface is loopback; the receiver's datagram sender
    port equals the sender's `boundPort` and its `path?.localAddress == "::1"`.
  - "A pinned send uses the pinned path": send `via:` the path from the first send; same assertions.
  - "A pinned path with an address not on the host fails as pathUnavailable": `via: MatterPath(interfaceIndex: lo, interfaceName: "lo0"/"lo", localAddress: "fd00:dead::1")` → throws `.pathUnavailable` with `EADDRNOTAVAIL`.
  - "Excluding loopback leaves no route to ::1": policy `excluded: [loopbackName]` → `.noAllowedRoute`.
  - "A named interface that does not exist is logged at warning on apply": `LogCapture`, policy
    `preferred: ["nosuch0"]` → one warning containing `nosuch0` and `missing`.
  - "IPv4 and IPv6 share one port when bound to 0": `bind(port: 0)`; send to `127.0.0.1` and `::1`
    receivers; both arrive from `boundPort`.
- [ ] **Step 2: Run** `swift test --filter POSIXUDPSocketCoreTests` → FAIL.
- [ ] **Step 3: Implement** `POSIXInterfaces`, the core, the protocol additions, and both wrappers.
- [ ] **Step 4: Run** `swift test --filter "POSIXUDPSocketCoreTests|AppleUDPTransportTests|SocketShimTests|PathSelectorTests"` → PASS. Existing Apple transport tests must still pass unchanged except comments.
- [ ] **Step 5: Linux check of this task alone** (Docker disk first):
  `docker system df` then
  `docker run --rm --cpus=2 --platform linux/arm64 -v "$PWD":/src -w /src swift:6.2-noble swift test --filter "MatterTransportTests|MatterLinuxTests"` → PASS.
- [ ] **Step 6: Commit** — `git commit -m "Transport: one POSIX socket core under the Apple and Linux transports"`

### Task 4: Multi-interface fake

**Files:**
- Create: `Sources/MatterTestSupport/MultiInterfaceEndpoint.swift`
- Test: `Tests/MatterTransportTests/MultiInterfaceEndpointTests.swift`

**Interfaces:**
- Consumes: `FaultInjectingLink`/`FaultInjectingEndpoint`, `PathSelector`, `InterfacePolicyMonitor`, `LogCapture`.
- Produces:

```swift
/// A `MatterUDPTransport` that pretends to be a multi-homed host: wraps one side of a
/// `FaultInjectingLink`, selects and pins paths with the real `PathSelector`, and records each send.
public final class MultiInterfaceEndpoint: MatterUDPTransport, Sendable {
    public struct Interface: Sendable { public var snapshot: InterfaceSnapshot; public var reachable: Set<String> /* peer hosts */ }
    public init(wrapping endpoint: FaultInjectingEndpoint, interfaces: [Interface], routeTable: String?, logger: Logger)
    public func setInterface(_ name: String, up: Bool)
    public func setReachable(_ name: String, _ hosts: Set<String>)
    public func setRouteTable(_ name: String?)
    /// The path inbound datagrams are reported as having arrived on, until changed.
    public func setArrival(_ name: String)
    public var sends: [(data: Data, to: MatterAddress, path: MatterPath)] { get }
    public var policy: InterfacePolicy { get }
    // MatterUDPTransport: send(_:to:) = send(via: nil); pinned send to an interface without the
    // peer in `reachable` throws pathUnavailable(path, errno: EHOSTUNREACH).
}
```

The local address of a path is the interface snapshot's first address.

- [ ] **Step 1: Failing tests** — pinned send to an unreachable host throws `pathUnavailable`; `setArrival("en1")` makes `receiveDatagrams()` report `en1`; `setInterfacePolicy` with a missing name logs a warning through the injected logger.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** — `git commit -m "TestSupport: multi-interface fake transport"`

### Task 5: Controller messenger pinning

**Files:**
- Modify: `Sources/MatterController/Messaging/ControllerMessenger.swift`, `ControllerMessenger+Sessions.swift`, `ControllerExchange` (wherever defined), the telemetry type (`ControllerTelemetry`) for the two counters
- Modify: `Sources/MatterController/MatterController.swift` (`Configuration.interfaces`, `makeMessenger`, CASE/PASE registration passes the handshake path, CASE span attributes)
- Test: `Tests/MatterControllerTests/Messaging/MessengerPathTests.swift`

**Interfaces:**
- Consumes: Task 3 protocol, Task 4 fake.
- Produces:
  - `ControllerMessenger.Configuration.interfaces: InterfacePolicy = .automatic`; `start()` calls
    `await transport.setInterfacePolicy(configuration.interfaces)` once before the receive loop
    (make `start()` remain synchronous by doing this in the detached receive task before iterating,
    and gate the first send on it with a stored `Task<Void, Never>` `policyApplied` that `send` awaits).
  - `MatterController.Configuration.interfaces: InterfacePolicy` (init parameter, default `.automatic`), copied in `makeMessenger`.
  - `var exchangePaths: [ExchangeKey: MatterPath]` (unsecured exchanges); `SessionEntry.path: MatterPath?`.
  - `registerSession(_:peerAddress:path:mrp:)` — `path` defaulted `nil`.
  - `ControllerExchange.path() async -> MatterPath?` → `messenger.pinnedPath(for: key)`.
  - `Outgoing` gains `key: ExchangeKey?` (nil for nothing); all sends go through
    `func sendPinned(_ bytes: Data, to address: MatterAddress, key: ExchangeKey?) async throws`.
  - `MessagingError.pathLost(ExchangeKey, MatterPath)` (new case) for a handshake whose path vanished.

`sendPinned` rules:
1. `pinned = key.flatMap(pinnedPath(for:))`.
2. `result = try await transport.send(bytes, to: address, via: pinned)`.
3. If `pinned == nil`, `let r = result`: record `r.path` (unsecured → `exchangePaths[key]`; secured →
   `sessions[id].path`), and if `r.selection != nil` increment
   `transport_path_selections_total{outcome: r.selection.rawValue}`.
4. On `TransportPathError.pathUnavailable(path, errno)`:
   - secured: clear the session path, log info
     `"Session 0x1a2b: \(path.interfaceName) lost its route to \(peer); re-selecting"`, increment
     `transport_path_repins_total{reason: route_lost}`, retry once with `via: nil`, record, log info
     `"Session 0x1a2b re-pinned to \(new)"`;
   - unsecured: fail the exchange with `.pathLost(key, path)` via `finishExchange` (+ `failed[key]`
     when no waiter), log info, rethrow nothing.
5. `removeExchange` also drops `exchangePaths[key]`. `stop()` clears `exchangePaths`.

Receive side: `start()` iterates `transport.receiveDatagrams()`; `handleDatagram(_:from:path:)`;
`process(... arrival: MatterPath?)`:
- unsecured, peer-initiated exchange being opened (`manager.open` branch): `exchangePaths[key] = arrival` when `arrival` is allowed;
- secured, `verdict == .accepted`: if `let arrival, arrival != entry.path`: allowed → set
  `entry.path = arrival`, info `"Session 0x1a2b re-pinned \(old?.interfaceName ?? "none") → \(arrival.interfaceName) (traffic arrived on \(arrival.interfaceName))"`,
  repin counter `reason: arrival` (only when `old != nil`); excluded → debug log, keep.
- unsecured traffic on an exchange we opened never changes `exchangePaths`.

`MatterController`: in `caseHandshake`, before `handshake.close()`, read `let path = await handshake.path()`
and return it with the session; `establishCASESession` passes it to `registerSession(path:)` and sets
span attributes `matter.interface` / `matter.local_address`. Same for PASE registration.

- [ ] **Step 1: Failing tests** (`MessengerPathTests`, `ManualClock`, `MultiInterfaceEndpoint` wrapping `link.a` with `en0` (`fd48::a`, reaches `10.0.0.2`) and `en1` (`fd48::b`, reaches `10.0.0.2`), route table `en0`):
  - "Every frame of a handshake leaves by the path its first frame chose": open exchange, send reliable, flip route table to `en1`, let MRP retransmit and send the next frame → all `sends` have `en0`.
  - "Preference is honoured on first contact": policy `preferred: ["en1"]` → first send on `en1`; `matter_transport_path_selections_total{outcome=preferred}` == 1.
  - "A preferred interface without a route falls through": `en1` unreachable → `en0`, outcome `fallthrough`, info log names `en1`.
  - "An excluded interface is never used": `excluded: ["en0"]`, route table `en0` → `en1`; then exclude both → send fails, exchange receive throws.
  - "A session replies by the path its traffic arrived on": register session with path `en0`; peer sends authenticated message with `setArrival("en1")` → the ack/reply goes out on `en1`; info log "re-pinned en0 → en1"; repin counter `reason=arrival` == 1.
  - "Unauthenticated traffic never moves a pin": unsecured exchange pinned on `en0`; peer reply arrives on `en1` → next frame still `en0`. Also: a secured frame that fails decryption arriving on `en1` leaves the session on `en0`.
  - "Losing a route re-pins a session": session on `en1`, `setReachable("en1", [])`, send → goes out on `en0`; counter `reason=route_lost`.
  - "Losing a route fails a handshake at once": unsecured exchange pinned to `en1`, `setReachable("en1", [])`, MRP retransmit → `receive` throws `.pathLost`.
  - "A named interface that is missing is reported": controller/messenger configured `preferred: ["en7"]` → warning captured.
- [ ] **Step 2: Run** `swift test --filter MessengerPathTests` → FAIL.
- [ ] **Step 3: Implement** per the rules above.
- [ ] **Step 4: Run** `swift test --filter MatterControllerTests` → PASS (all existing messenger tests still green: `FaultInjectingEndpoint` gets default `nil` paths).
- [ ] **Step 5: Commit** — `git commit -m "Controller: pin each exchange and session to a path; re-pin on authenticated arrival and route loss"`

### Task 6: CASE busy wait

**Files:**
- Modify: `Sources/MatterController/MatterController.swift` (`Configuration.retryClock`, `expect`, `caseHandshake`, `establishCASESession`), `ControllerTelemetry` (busy counter)
- Test: `Tests/MatterControllerTests/Observability/CASEBusyTests.swift`

**Interfaces:**
- Produces: `MatterController.Configuration.retryClock: any MRPClock` (init parameter, default
  `ContinuousClock()`); internal `CASEBusy: Error { let minimumWait: Duration }`.

Implementation:
- In `caseHandshake`, after the Sigma1 request returns: if it is a StatusReport whose
  `protocolID == MatterProtocolID.secureChannel.rawValue` and `protocolStatus == SecureChannelStatusCode.busy.rawValue`,
  throw `CASEBusy(minimumWait: .milliseconds(Int(wait)))`, where `wait` is `protocolData` read as
  little-endian `UInt16`, or 0 (debug log) if absent/short. Check this before `expect`.
- In `establishCASESession`, wrap the first `caseHandshake` call in a loop: up to 3 busy retries;
  `deadline = retryClock.now + operationTimeout` fixed at the first attempt; on `CASEBusy`: if
  `retryClock.now + minimumWait > deadline` throw `ControllerError.caseSessionFailed("peer busy; asked to wait \(ms) ms")`;
  else log info `"Node busy; retrying CASE in \(ms) ms"` (node metadata), increment
  `<prefix>_case_busy_waits_total`, `try await retryClock.sleep(until: retryClock.now + minimumWait)`, retry.
  After 3 busy answers throw `caseSessionFailed("peer busy after 3 attempts")`.

- [ ] **Step 1: Failing tests** (rig from `makeCASEControllerRig`, with `retryClock: ManualClock()` added to `makeControllerRig` as an optional parameter):
  - "A busy Sigma1 waits the stated time before a fresh Sigma1": peer answers Sigma1 with
    `StatusReportMessage(generalStatus: .busy, protocolID: 0, protocolStatus: 4, protocolData: Data([0xD0, 0x07]))` (2000 ms);
    wait until the manual clock has a sleeper (`ManualClock` API), assert no new Sigma1 counter yet,
    advance 2 s, next new frame is a Sigma1, complete CASE as in `SessionTelemetryTests.caseEstablished` → session established; busy counter == 1; info log "busy".
  - "A busy wait longer than the operation timeout fails at once": wait `0xFFFF` ms with `operationTimeout` 30 s → `caseSessionFailed` mentioning "busy", no second Sigma1.
  - "Three busy answers give up": answer busy (0 ms) three times → fails "after 3 attempts".
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** `swift test --filter "CASEBusyTests|SessionTelemetryTests"` → PASS.
- [ ] **Step 5: Commit** — `git commit -m "Controller: honour a CASE busy StatusReport's minimum wait"`

### Task 7: Device server pinning

**Files:**
- Modify: `Sources/MatterDevice/Server/MatterDeviceServer.swift`
- Test: `Tests/MatterDeviceTests/DeviceServerPathTests.swift`

**Interfaces:**
- Produces: `MatterDeviceServer.Config.interfaces: InterfacePolicy` (init parameter, default `.automatic`).

Implementation:
- `start()`: `await transport.setInterfacePolicy(config.interfaces)` before `bind`.
- `var peerPaths: [MatterAddress: MatterPath] = [:]`; cleared in `stop()`.
- `receiveLoop` iterates `transport.receiveDatagrams()`; `handleDatagram(_:from:arrival:)`.
  - unsecured: `if peerPaths[sender] == nil, let arrival, config.interfaces.allows(arrival.interfaceName) { peerPaths[sender] = arrival }`.
  - secured: after the dedup check accepts in `handleSecuredMessage`, if `arrival` differs and is
    allowed → `peerPaths[address] = arrival`, info log `"Peer <addr> re-pinned <old> → <new>"`.
    Pass `arrival` through to `handleSecuredMessage` as a new parameter.
- One helper; replace every `transport.send(x, to: y)` in the file (≈15 sites) with it:

```swift
/// Send to `address` by its pinned path, selecting (and pinning) one when it has none. A pinned
/// path that lost its route is dropped and re-selected once.
private func send(_ data: Data, to address: MatterAddress) async throws {
    do {
        if let result = try await transport.send(data, to: address, via: peerPaths[address]), peerPaths[address] == nil {
            peerPaths[address] = result.path
        }
    } catch TransportPathError.pathUnavailable(let lost, _) {
        logger.info("Path \(lost) to \(address) lost its route; re-selecting")
        peerPaths[address] = nil
        if let result = try await transport.send(data, to: address, via: nil) {
            peerPaths[address] = result.path
        }
    }
}
```

- [ ] **Step 1: Failing tests** using `MultiInterfaceEndpoint` around the server's link side:
  "A reply leaves by the interface the request arrived on" (PBKDFParamRequest arriving on `en1` →
  PBKDFParamResponse sent on `en1`, route table `en0`); "An authenticated message on another interface
  re-pins the peer"; "Config.interfaces reaches the transport" (fake's `policy` equals config's).
  Follow the existing device-server test setup in `Tests/MatterDeviceTests` (find one driving PASE
  with `ScriptedPeer`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** `swift test --filter MatterDeviceTests` → PASS.
- [ ] **Step 5: Commit** — `git commit -m "Device server: reply by each peer's arrival path; interface policy in Config"`

### Task 8: Docs, full suites, swift-matter PR

**Files:**
- Modify: `Sources/MatterSwift/MatterSwift.docc/PlatformTransport.md` (the three new requirements, `InterfacePolicy`, the C shim), `Sources/MatterSwift/MatterSwift.docc/UsingTheController.md` (a "Multi-homed hosts" section), spec status line → "implemented".

- [ ] **Step 1:** Update docs. **Step 2:** `swift build` and `swift test` (full) on macOS → all pass; record counts.
- [ ] **Step 3:** `docker system df` (note free space; stop if the VM disk is near full and tell David).
  `docker run --rm --cpus=2 --platform linux/arm64 -v "$PWD":/src -w /src swift:6.2-noble bash -c "swift build && swift test"` → all pass. Remove any build volume created.
- [ ] **Step 4:** Commit docs; `git push -u origin feat/multihomed-interface-paths`;
  `gh pr create --repo acumen-dev/swift-matter` with summary, measurements, test evidence; bind with ccd_pr tools.
- [ ] **Step 5:** Ask David to approve tagging `1.0.0-beta.10` after merge. Do not tag without it.

### Task 9: acumen-matter — policy store and Network interfaces flow

Starts after Task 8's branch exists. Until the tag exists, build against the branch with a local
override that is **not committed**: `swift package edit matter-swift --path ../swift-matter` (then
`swift package unedit` + `swift package update` and print the resolved revision before the PR).

**Files:**
- Create: `Sources/AcumenMatterCore/InterfacePolicyStore.swift`, `Sources/AcumenMatterCore/NetworkInterfacesFlow.swift`
- Modify: `Package.swift` (`AcumenMatterCore` depends on `MatterTransport` product if it does not already)
- Test: `Tests/AcumenMatterAgentTests/InterfacePolicyStoreTests.swift`, `Tests/AcumenMatterAgentTests/NetworkInterfacesFlowTests.swift`

**Interfaces:**

```swift
public enum InterfacePolicyStore {
    public static let preferKey = "network.interfaces.prefer"
    public static let excludeKey = "network.interfaces.exclude"
    /// Absent → .automatic. Names are trimmed; empty entries dropped.
    public static func read(from configStore: any AgentConfigStore) -> InterfacePolicy
    public static func write(_ policy: InterfacePolicy, to configStore: any AgentConfigStore) async throws
}

/// What the flow needs from an agent.
public protocol NetworkInterfacesAdministering: Sendable {
    func interfacePolicy() async -> InterfacePolicy
    /// Saves and applies; the returned text says what happened ("The controller restarted…").
    func setInterfacePolicy(_ policy: InterfacePolicy) async throws -> String
    /// Peers whose reachability the flow shows per interface (controller: one operational address
    /// per Thread prefix of its nodes; bridge: empty).
    func reachabilityTargets() async -> [MatterAddress]
    /// Shown before confirming a save.
    var applyConsequence: String { get }
}

public enum NetworkInterfacesFlow {
    public static func run(session: any AdminSession, admin: any NetworkInterfacesAdministering,
                           interfaces: @Sendable () -> [InterfaceSnapshot] = POSIXInterfaces.snapshot,
                           route: @Sendable (MatterAddress, InterfaceSnapshot?) -> (index: UInt32, source: String)? = POSIXInterfaces.route(to:via:)) async throws
}
```

Flow: display labeled values — policy (`Preferred: en0, en1` / `Excluded: —` / `Automatic`); one row
per interface: `en0 — up — fd48::a — reaches fdf3:5376:d756::/64` (or "no route"), flagging named
interfaces that are missing or down. Select: "Change order", "Change exclusions", "Use automatic",
"Done". Order: multi-step select building the list from up interfaces. Exclusions: select toggles.
Confirm with `applyConsequence`, then `setInterfacePolicy` and display its returned text. Malformed
stored text: `read` logs nothing (no logger) — the agent logs at warning when it reads at start
(`InterfacePolicyStore.read` returns `.automatic` and the agent compares raw text to detect
unreadable values: non-empty raw with zero valid names).

- [ ] **Step 1: Failing tests** — store round trip (`["en0","en1"]`, `["en5"]`), absent → automatic,
  `" en0 , ,en1 "` → `["en0","en1"]`; flow with a fake session (follow `AdminFlowTests`' fake) shows
  rows for fake interfaces, flags a missing preferred name, saves a new order and displays the
  consequence text.
- [ ] **Step 2: Run** `swift test --filter "InterfacePolicyStoreTests|NetworkInterfacesFlowTests"` → FAIL.
- [ ] **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** — `git commit -m "Network interfaces: policy store and admin flow"`

### Task 10: acumen-matter — apply in both agents

**Files:**
- Modify: `Sources/AcumenMatterAgent/AcumenMatterAgent.swift` (read policy in `startNow`, pass
  `interfaces:` into `MatterController.Configuration` in `loadController`; warn on unreadable value),
  `AcumenMatterAgent+Administering.swift` (conform to `NetworkInterfacesAdministering`: save then
  `reload()`, mapping failures like `setPolicy` does), `AdminFlows/AdminFlowRegistration.swift`
  (`matter.network`, "Network interfaces", "Choose which network interfaces Matter uses, in order").
- Modify: `Sources/AcumenMatterExposure/MatterExposureAgent.swift` (read policy from
  `context.configStore`, pass `interfaces:` into `MatterDeviceServer.Config`; `restartServer()` =
  stop + start the server), its `AdminFlowRegistration.swift` (`network`, same name).
- Test: `Tests/AcumenMatterAgentTests/AcumenMatterAgentAdminTests.swift` (new cases),
  `Tests/AcumenMatterExposureTests/ExposureInterfacePolicyTests.swift`.

- [ ] **Step 1: Failing tests** — saving a policy through the agent's administering surface writes
  the keys and reloads, and the reloaded controller's transport received the policy (inject a
  transport-recording `makeNetwork` seam if none exists — add `makeNetwork: @Sendable () -> (any MatterUDPTransport, any MatterDiscovery)`
  to the agent init, defaulting to the current static); an unreadable stored value logs a warning
  and runs automatic; the exposure agent's server config carries the stored policy.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** `swift test` (full) → PASS.
- [ ] **Step 5: Commit** — `git commit -m "Agents: apply the interface policy; Network interfaces flow in both"`

### Task 11: acumen-matter release wiring and PR

- [ ] **Step 1:** After David approves and `1.0.0-beta.10` is tagged: `swift package unedit matter-swift && swift package update`; print the resolved swift-matter revision; raise `Package.swift` to `from: "1.0.0-beta.10"`.
- [ ] **Step 2:** Full `swift test` on macOS; Linux gate as Task 8 Step 3.
- [ ] **Step 3:** Commit, push `feat/interface-policy`, `gh pr create --repo acumen-dev/acumen-matter`, bind with ccd_pr tools. The house is not restarted; David sets the policy from the flow after his own restart.
