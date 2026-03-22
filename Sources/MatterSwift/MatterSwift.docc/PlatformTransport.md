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

Handles mDNS/DNS-SD service advertisement and browsing:

```swift
public protocol MatterDiscovery: Sendable {
    func advertise(service: MatterServiceRecord) async throws
    func browse(type: MatterServiceType) -> AsyncStream<MatterServiceRecord>
    func resolve(_ record: MatterServiceRecord) async throws -> MatterAddress
    func stopAdvertising() async
}
```

- `advertise(service:)` — Register an mDNS service record
- `browse(type:)` — Discover services of a given type (commissionable or operational)
- `resolve(_:)` — Resolve a service record to a network address
- `stopAdvertising()` — Remove all advertised records

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
- PTR/SRV/TXT record advertisement and browsing
- DNS wire-format encode/decode with pointer decompression
- Responds to incoming PTR queries from other mDNS clients

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

    public func browse(type: MatterServiceType) -> AsyncStream<MatterServiceRecord> {
        // Browse for mDNS services of the given type
    }

    public func resolve(_ record: MatterServiceRecord) async throws -> MatterAddress {
        // Resolve a service record to an IP address and port
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
