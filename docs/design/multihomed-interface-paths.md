# Multi-homed hosts: interface policy and per-peer path pinning

Status: approved design, 2026-10-23. Spans swift-matter and acumen-matter.

## Problem

The house Mac is dual-homed: Ethernet `en0` and Wi-Fi `en1`, both on
`fd48:725f:4956:4566::/64`. Three Apple Thread border routers advertise the Thread
prefix `fdf3:5376:d756::/64`, and the Mac's route to it moved between `en1` and `en0`
during the morning of 2026-10-23. From about 08:52 to 10:01 two Eve covers (nodes 0x5
and 0x7) acknowledged our CASE Sigma1 and sent Sigma2, but never received our Sigma3 or
acks: they kept re-sending Sigma2. Both recovered on their own before a capture.

Every send today leaves one socket bound to `[::]:<port>` with no source address or
interface, so the kernel chooses both per datagram.

### What was measured (macOS 27, the house Mac)

- `sendmsg` with `IPV6_PKTINFO` on a **bound** socket keeps the bound source port, for
  an ephemeral or fixed port, with a source address, an interface index or both, to
  global and link-local destinations. The comment in `AppleUDPTransport` saying it gives
  an ephemeral port is wrong for a bound socket. One socket per interface is not needed.
- macOS behaves as a strong host for these sends. With all three border routers learnt
  on `en0` only (`ndp -rn`; `route get -ifscope en1` finds nothing), a send to the Thread
  prefix with `en1`'s address as source, or with `en1` as interface, fails with
  `EHOSTUNREACH`. The source address effectively selects the interface.

### Plausible mechanism (unproven)

If the route moved between Sigma1 and Sigma3, Sigma3 left from the other interface's
address. The device holds the unsecured CASE exchange against the Sigma1 source address,
so it does not match Sigma3 and keeps re-sending Sigma2 to the old address, which still
reaches us (same /64 on both interfaces). Pinning each exchange's source address and
interface closes this regardless of whether it was the cause.

## Decisions

1. The controller keeps the port it binds (ephemeral today; the bridge binds 5540).
   Every send leaves from that bound port.
2. The policy is set on `MatterController.Configuration` and
   `MatterDeviceServer.Config`; each pushes it into its transport at start.
3. Preference is an order, not a requirement: use the first allowed interface that has
   a route to the peer, fall through and log when it has none. Exclusion is the only
   hard limit.
4. acumen-matter keeps the policy in each agent's ConfigStore, set from an admin flow;
   saving rebuilds that agent's transport.
5. Apple and Linux transports share one POSIX socket core (Darwin/Glibc). The Linux
   transport stops using NIO: NIO 2.95 reports packet info on receive but cannot set
   `IPV6_PKTINFO` on a write.
6. The bridge (`MatterDeviceServer`) pins the same way, as a responder.

## 1. Policy

In `MatterTransport`:

```swift
public struct InterfacePolicy: Sendable, Equatable {
    public var preferred: [String]     // interface names, most preferred first
    public var excluded: Set<String>   // never used to send
    public static let automatic = InterfacePolicy(preferred: [], excluded: [])
}
```

- **Allowed** = every interface that is up, minus `excluded`. Unlisted interfaces stay
  allowed and rank after the listed ones.
- **Selection** for a peer with no pinned path (first contact, or re-selection):
  1. each `preferred` interface in order that is allowed and has a route to the peer;
  2. else the route table's own choice, if its interface is allowed;
  3. else any remaining allowed interface with a route;
  4. else `noAllowedRoute(peer)`.
  A step past the first preferred interface is logged at info with the reason
  (`en1 preferred, no route to fdf3:…; using en0`).
- **Route check** (no root, no packets): a throwaway UDP socket of the peer's family,
  scoped to the interface (`IPV6_BOUND_IF`/`IP_BOUND_IF` on Darwin;
  `IPV6_UNICAST_IF`/`IP_UNICAST_IF` on Linux), `connect()`ed to the peer.
  `EHOSTUNREACH`/`ENETUNREACH` = no route; `getsockname()` gives the source address that
  interface would use. The unscoped variant gives the route table's choice.
- **Missing or down interfaces** named in the policy are logged at warning when the
  policy is applied, and again only when their state changes during selection (never
  per send).
- **Arrival on an excluded interface** is accepted (we cannot steer a peer's traffic) but
  never becomes a pin and is never replied through.
- Selection is a pure `PathSelector` over an interface snapshot and a route-check
  function, so it is tested without sockets.

## 2. Transport

`POSIXUDPSocketCore` in `MatterTransport`, `#if canImport(Darwin)` / `canImport(Glibc)`:

- an `AF_INET6`/`IPV6_V6ONLY=1` socket and an `AF_INET` socket, both bound to the
  requested port (the IPv4 one to the port the IPv6 one actually got, when it was 0);
- one receive thread per socket using `recvmsg` with `IPV6_RECVPKTINFO` /
  `IP_RECVPKTINFO` (Darwin `IP_RECVPKTINFO`, Linux `IP_PKTINFO`), yielding the arrival
  interface index and local (destination) address;
- `sendmsg` with `IPV6_PKTINFO` / `IP_PKTINFO` carrying the pinned interface and source
  address; link-local destinations set the interface the same way (the `IPV6_BOUND_IF`
  toggle and its comment go);
- interface listing (`getifaddrs`, `IFF_UP`/`IFF_RUNNING`) and the route check.

`AppleUDPTransport` and `LinuxUDPTransport` become thin actors over the core, keeping
their names, inits and `boundPort()`. `MatterLinux`'s transport no longer imports NIO
(its discovery still does).

### Protocol

```swift
public struct MatterPath: Sendable, Hashable {
    public var interfaceIndex: UInt32
    public var interfaceName: String
    public var localAddress: String       // canonical literal, no zone
}
public struct MatterDatagram: Sendable {
    public var data: Data
    public var sender: MatterAddress
    public var path: MatterPath?           // nil when the transport cannot tell
}

extension MatterUDPTransport {
    func receiveDatagrams() -> AsyncStream<MatterDatagram>             // default: wraps receive(), path nil
    func send(_ data: Data, to: MatterAddress, via: MatterPath?) async throws -> MatterPath?
                                                                       // default: send(_:to:), returns nil
    func setInterfacePolicy(_ policy: InterfacePolicy) async           // default: no-op
}
```

These are protocol requirements with default implementations, so existing transports
and test fakes compile unchanged. `send(_:to:via:)` with `via == nil` selects under the
policy and returns the path used. A pinned path whose send fails with `EHOSTUNREACH`,
`ENETUNREACH` or `EADDRNOTAVAIL` throws `TransportPathError.pathUnavailable(path, errno)`.
`MatterController` and `MatterDeviceServer` call `setInterfacePolicy` before their
first send; the new configuration field is `interfaces: InterfacePolicy = .automatic`.

## 3. Pinning

### Controller (`ControllerMessenger`)

- **Exchanges we initiate (PASE, CASE):** the first send has no path; the transport
  selects and returns one, stored per `ExchangeKey`. Every later frame on that exchange
  (Sigma3, acks, MRP retransmissions; `Outgoing` gains `path`) uses it. Unauthenticated
  traffic never moves it.
- **Sessions:** `registerSession(_:peerAddress:path:mrp:)` gives the session the
  handshake's path (`SessionEntry.path`).
- **Re-pin** only on a message that decrypted and passed counter de-duplication (the gate
  that already updates `peerAddress`): if its arrival path is on a different allowed
  interface, the session re-pins to it and logs at info
  (`session 0x1a2b re-pinned en1 → en0 (traffic arrived on en0)`). Arrival on an
  excluded interface leaves the pin (debug log).
- **Peer-initiated exchanges** reply by their session's path; an unsecured one by its
  arrival path.
- **Route lost** (`pathUnavailable`): a secure session re-selects, logs at info
  (`session 0x1a2b: en1 lost its route to fdf3:…; re-pinned to en0`) and resends — the
  device accepts the new source because the message authenticates. An unsecured
  handshake in flight fails at once (changing source mid-handshake breaks it anyway);
  the next CASE attempt starts clean.

### Device server (`MatterDeviceServer`)

Same rules as a responder: a PASE/CASE handshake is pinned to the arrival path of its
first message; the session inherits it; re-pin only on authenticated arrival; route loss
re-selects for sessions. Replies to the iPhone therefore leave from the address it sent
to, by the interface it arrived on.

## 4. CASE busy

A Sigma1 answered by a StatusReport with Secure Channel protocol status `busy` (4)
carries a little-endian `uint16` minimum wait in milliseconds in `protocolData`.
`caseHandshake` raises an internal `peerBusy(minimumWait:)`; `establishCASESession`
waits at least that long on `MatterController.Configuration.retryClock`, then retries with a
fresh Sigma1, at most three times. The retry count and the `operationTimeout` deadline are one
budget per establishment, shared by its first and post-address-refresh attempts. A wait that would pass `operationTimeout` fails instead with
`caseSessionFailed("peer busy; asked to wait N ms")`. Each wait is logged at info. A
missing or short `protocolData` is treated as a 0 ms wait (logged at debug).

## 5. Telemetry

- `<prefix>_transport_path_selections_total{outcome=preferred|fallthrough|route_table}`
- `<prefix>_transport_path_repins_total{reason=arrival|route_lost}`
- `<prefix>_case_busy_waits_total`
- The chosen path (`matter.interface`, `matter.local_address`) as attributes on the CASE
  span; the path in trace-level send/receive logs. All permanent.

## 6. acumen-matter

- `AcumenMatterCore.InterfacePolicyStore`: ConfigStore keys `network.interfaces.prefer`
  (comma-separated, in order) and `network.interfaces.exclude`. Absent reads as
  `.automatic`; an unreadable value reads as `.automatic` and logs at warning.
- A shared **Network interfaces** admin flow, registered by both `AcumenMatterAgent`
  and `MatterExposureAgent` (each with its own ConfigStore and policy):
  - *view*: the policy, and every host interface with up/down, addresses, and whether it
    has a route to each Thread prefix of the agent's paired nodes (controller) — named
    interfaces that are missing or down are flagged;
  - *set*: order and exclusions, then save.
- Applying: the controller agent's existing `reload()` rebuilds controller and transport
  (sessions re-establish); the exposure agent restarts its `MatterDeviceServer` (the
  bridge drops briefly in Apple Home). The flow says which before confirming.

## 7. Testing

swift-matter:
- `FakeMultiInterfaceTransport` (MatterTestSupport): named interfaces with up/down,
  local addresses and per-peer routes; records each send with its path.
- Reply path equals arrival path; first contact honours preference and falls through
  when the preferred interface has no route; excluded interfaces never used; a missing
  or down named interface is reported (captured log); authenticated arrival re-pins,
  unauthenticated does not; route loss re-pins a session and fails a handshake fast;
  busy waits on a manual clock, retries, and gives up past the timeout.
- `PathSelector` unit tests.
- POSIX core on loopback (macOS and Linux): bound source port kept with `PKTINFO`,
  arrival path reported, route check answers.

acumen-matter: store round trip and unreadable value; flow shows interfaces and saves;
saving reloads and the new transport receives the policy.

Both full suites on macOS and in `swift:6.2-noble --cpus=2` (arm64; check Docker disk
first — it is shared with the house's ClickHouse).

## 8. Delivery

1. swift-matter: branch `feat/multihomed-interface-paths`, PR.
2. Tag `1.0.0-beta.10` after merge — needs David's approval.
3. acumen-matter: own branch, pin raised to `from: "1.0.0-beta.10"`, PR. Before the
   tag exists it builds locally against the swift-matter branch; that override is
   removed before the PR.
4. The house only re-resolves acumen-matter. Setting a policy is David's, from the flow,
   after he restarts the house himself.
