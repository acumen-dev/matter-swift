# Platform Transport

Understand the transport abstraction layer and how to implement custom transports.

## Overview

MatterSwift separates protocol logic from platform-specific networking via two protocols defined in the `MatterTransport` module. The library ships with implementations for Apple platforms (Network.framework) and Linux (SwiftNIO), and you can implement your own for other platforms.

## Transport Protocols

### MatterUDPTransport

Handles UDP datagram send/receive:

```swift
public protocol MatterUDPTransport: Sendable {
    func send(_ data: Data, to address: MatterAddress) async throws
    func receive() -> AsyncStream<(Data, MatterAddress)>
    func bind(port: UInt16) async throws
    func close() async
}
```

- `bind(port:)` — Start listening on a UDP port
- `send(_:to:)` — Send a datagram to a specific address
- `receive()` — AsyncStream of incoming datagrams with sender address
- `close()` — Stop listening and release resources

### MatterDiscovery

Handles mDNS/DNS-SD service advertisement, browsing and resolution. `MatterDiscovery` is an alias for `ServiceDiscovery` from [mdns-swift](https://github.com/acumen-dev/mdns-swift)'s `MDNSCore` (and `MatterServiceRecord` for its `ServiceRecord`):

```swift
public protocol ServiceDiscovery: Sendable {
    func advertise(service: ServiceRecord) async throws
    func browse(serviceType: ServiceType) -> AsyncStream<ServiceRecord>
    func resolve(_ record: ServiceRecord) async throws -> NetworkAddress
    func resolveService(_ record: ServiceRecord) async throws -> ResolvedService
    func stopAdvertising() async
    func stopAdvertising(name: String) async
}
```

- `advertise(service:)` — Register an mDNS service record
- `browse(serviceType:)` — Discover services of a type; `browse(type:)` is a convenience taking a `MatterServiceType` (commissionable or operational)
- `resolve(_:)` — Resolve a service record to a network address
- `resolveService(_:)` — Resolve a service record to its address *and* TXT record. The controller uses it to commission from a setup code and to follow a device that moved. A default implementation returns `resolve(_:)`'s address with the TXT the browse record carried, so a discovery that predates it still works.
- `stopAdvertising()` / `stopAdvertising(name:)` — Remove all advertised records, or one (the default for the latter stops all)

The resolve contract the controller relies on:

- **Cancellation.** `resolve` and `resolveService` must honour task cancellation, throwing `CancellationError` promptly. A resolve may wait indefinitely for an instance that never answers; the controller bounds every resolve (`commissionableResolveTimeout`, `addressRefreshTimeout`, `discoveryTimeout`) by cancelling it, and a resolve that ignores cancellation holds those bounds open.
- **TXT.** `resolveService` may return an empty `txtRecords` when the TXT could not be obtained; only failing to resolve the address throws. The controller then keeps what it already has (the browse record's TXT when commissioning; the stored retransmission timing after a move).
- **Host form.** An IPv6 host may be returned in brackets (`"[fd00::1]"`, the URL-host form); the controller strips them, and the built-in transports accept either form. A host name rather than an IP literal is not used: a commissionable record that resolves to one is skipped, and a moved device's address is not updated to one.

## Built-In Implementations

### Apple (MatterApple module)

- **`AppleUDPTransport`** — Uses `NWConnection` and `NWListener` from Network.framework
- **`AppleDiscovery`** — Uses `NWBrowser` for browsing, `DNSServiceRegister` for advertisement

Features:
- IPv4 + IPv6 dual-stack
- Interface-aware mDNS registration (prevents cross-interface address leakage on dual-homed hosts)
- Link-local IPv6 AAAA record registration for each active LAN interface
- Automatic interface detection (filters out VPN tunnels, bridges, virtual interfaces)

### Linux (MatterLinux module)

- **`LinuxUDPTransport`** — Uses SwiftNIO `DatagramBootstrap` bound to `::` (dual-stack IPv6)
- **`LinuxDiscovery`** — Pure-Swift mDNS implementation (RFC 6762) over multicast UDP (224.0.0.251:5353)

Features:
- No external mDNS daemon required (no avahi dependency)
- PTR/SRV/TXT record advertisement; responds to incoming PTR queries from other mDNS clients
- DNS-SD browsing: follows a PTR with SRV and TXT queries, then A/AAAA for the SRV target, with RFC 6762 backoff for unanswered follow-ups
- Resolution to address, SRV port and TXT (`resolveService`) from a TTL-honouring record cache, cancellable, with a bounded wait
- DNS wire-format encode/decode with pointer decompression

## Platform Selection

The `MatterSwift` umbrella module automatically selects the right transport via conditional compilation:

```swift
// In MatterSwift.swift:
#if canImport(Network)
@_exported import MatterApple
#elseif canImport(Glibc) || canImport(Musl)
@_exported import MatterLinux
#endif
```

When you `import MatterSwift`, `AppleUDPTransport` and `AppleDiscovery` are available on Darwin, while `LinuxUDPTransport` and `LinuxDiscovery` are available on Linux.

## Implementing a Custom Transport

To support a new platform (e.g., embedded systems, Windows, or a testing mock):

1. **Create a new module** (e.g., `MatterMyPlatform`) that depends on `MatterTransport`.

2. **Implement `MatterUDPTransport`**:

```swift
import MatterTransport

public actor MyUDPTransport: MatterUDPTransport {
    private var continuation: AsyncStream<(Data, MatterAddress)>.Continuation?

    public func bind(port: UInt16) async throws {
        // Set up your platform's UDP socket on the given port
        // Start receiving datagrams and yield them to the continuation
    }

    public func send(_ data: Data, to address: MatterAddress) async throws {
        // Send a UDP datagram to the specified address
    }

    public func receive() -> AsyncStream<(Data, MatterAddress)> {
        AsyncStream { continuation in
            self.continuation = continuation
        }
    }

    public func close() async {
        continuation?.finish()
        // Clean up socket resources
    }
}
```

3. **Implement `MatterDiscovery`**:

```swift
public actor MyDiscovery: MatterDiscovery {
    public func advertise(service: MatterServiceRecord) async throws {
        // Register the service with your platform's mDNS system
    }

    public nonisolated func browse(serviceType: ServiceType) -> AsyncStream<MatterServiceRecord> {
        // Browse for mDNS services of the given type
    }

    public func resolve(_ record: MatterServiceRecord) async throws -> MatterAddress {
        // Resolve a service record to an IP address and port.
        // Must throw CancellationError promptly when the task is cancelled.
    }

    public func resolveService(_ record: MatterServiceRecord) async throws -> ResolvedService {
        // Optional (a default exists): the address plus the instance's TXT record.
        // Same cancellation contract as resolve(_:).
    }

    public func stopAdvertising() async {
        // Remove all registered mDNS records
    }
}
```

4. **Use your transport**:

```swift
let server = MatterDeviceServer(
    bridge: bridge,
    transport: MyUDPTransport(),
    discovery: MyDiscovery(),
    config: .init(discriminator: 3840, passcode: 20202021)
)
```

## Testing with Loopback Transport

The test suite includes a `LoopbackTransport` that routes messages in-memory without real networking. This pattern is useful for integration testing:

```swift
// Create paired transports that route to each other
let (deviceTransport, controllerTransport) = LoopbackTransport.createPair()

// Use them in your device and controller
let server = MatterDeviceServer(bridge: bridge, transport: deviceTransport, ...)
let controller = MatterController(transport: controllerTransport, ...)
```
