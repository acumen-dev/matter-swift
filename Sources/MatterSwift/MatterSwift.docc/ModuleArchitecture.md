# Module Architecture

Understand MatterSwift's module structure and how the pieces fit together.

## Overview

MatterSwift is split into 10 modules with a clear dependency hierarchy. Each module has a focused responsibility, enabling you to import only what you need and keeping compile times fast.

## Module Dependency Graph

```
MatterTypes (TLV, identifiers, status codes)
    ↑
MatterModel (cluster definitions, device types)
    ↑
MatterCrypto (SPAKE2+, CASE, AES-CCM, certificates)
    ↑
MatterProtocol (MRP, sessions, Interaction Model)
    ↑
├── MatterDevice (device/bridge role)
└── MatterController (controller role)

MatterTransport (platform-agnostic UDP, mDNS protocols)
    ↑
├── MatterApple (Network.framework, CryptoKit)
└── MatterLinux (SwiftNIO, pure-Swift mDNS)

MatterSwift (umbrella re-export of all modules)
```

## Module Reference

### MatterTypes

**Purpose**: Core types shared by all modules. Zero external dependencies.

**Key types**:
- `TLVEncoder` / `TLVDecoder` — Matter's Tag-Length-Value binary format
- `TLVElement` / `TLVValue` — TLV data representation
- `EndpointID`, `ClusterID`, `AttributeID`, `CommandID`, `EventID` — Typed identifiers
- `FabricID`, `NodeID`, `FabricIndex` — Fabric-scoped identifiers
- `StatusCode` — Matter protocol status codes
- `MatterFabricStore`, `MatterAttributeStore`, `MatterControllerStore` — Storage protocols
- `StoredDeviceState`, `StoredAttributeData`, `StoredControllerState` — Codable state types

**When to import**: When you need TLV encoding, identifiers, or storage protocols without pulling in the rest of the stack.

### MatterModel

**Purpose**: Cluster definitions, device types, and attribute schemas. The "data dictionary" of the Matter specification.

**Key types**:
- 110 generated cluster enums (e.g., `OnOffCluster`, `LevelControlCluster`, `ColorControlCluster`)
- Each cluster provides `Attribute`, `Command`, `Event` enums with typed IDs
- `DeviceTypeID` with required/optional cluster mappings for 72 device types
- `ClusterMetadata` — Runtime cluster registry for dynamic lookup
- Hand-written cluster extensions for complex types (ACL entries, network structs, etc.)

**When to import**: When you need cluster/attribute/command IDs or device type definitions.

### MatterCrypto

**Purpose**: All cryptographic operations required by the Matter protocol.

**Key types**:
- `SPAKE2PVerifier` / `SPAKE2PContext` — Password-authenticated key exchange
- `CASESession` — Certificate-Authenticated Session Establishment (Sigma protocol)
- `CASEKeyDerivation` — Transcript-hash-based session key derivation
- `MatterCertificate` — Matter TLV ↔ X.509 DER certificate conversion
- `FabricInfo` — Fabric credentials, compressed fabric ID, IPK derivation
- `DeviceAttestationCredentials` — Test DAC/PAI/PAA certificate chain
- `AES128CCM` — Message encryption/decryption
- `PKCS10CSRBuilder` — Certificate signing request generation

**When to import**: When working with certificates, key exchange, or encryption directly.

### MatterTransport

**Purpose**: Platform-agnostic protocol definitions for networking.

**Key types**:
- `MatterUDPTransport` — Protocol for UDP send/receive/bind
- `MatterDiscovery` — Protocol for mDNS advertise/browse/resolve
- `MatterAddress` — Network address (host, port, interface)
- `MatterServiceRecord` — mDNS service record

**When to import**: When implementing a custom transport for a new platform.

### MatterProtocol

**Purpose**: The wire protocol layer — everything between raw UDP and the application.

**Key types**:
- `MessageHeader` / `ExchangeHeader` — Message framing
- `SessionTable` — Active session management
- `MRPManager` — Message Reliability Protocol (retransmission, deduplication)
- `InteractionModelHandler` — Read/Write/Subscribe/Invoke processing
- `ReportDataChunker` — Splits large responses for UDP MTU
- `SubscriptionManager` — Subscription lifecycle and dirty tracking
- `AttributeStore` — In-memory attribute storage with data version tracking
- `EventStore` — Ring-buffer event storage with priority levels

**When to import**: When working with the protocol layer directly (rare for most users).

### MatterDevice

**Purpose**: Device and bridge role — the primary API for creating Matter devices.

**Key types**:
- `MatterBridge` — High-level bridge facade with convenience device methods
- `MatterDeviceServer` — UDP server with PASE/CASE and IM routing
- `BridgedEndpoint` — Handle for updating device state from bridge logic
- `EndpointManager` — Endpoint registration and attribute routing
- `CommissioningState` — Commissioning flow state machine
- 28 `ClusterHandler` implementations (OnOff, LevelControl, ColorControl, etc.)
- `SetupPayload` — QR code and manual pairing code generation

**When to import**: When building a Matter device or bridge.

### MatterController

**Purpose**: Controller role — commissioning and operational device interaction.

**Key types**:
- `MatterController` — High-level controller with async/await API
- `CommissioningController` — Pure commissioning state machine
- `FabricManager` — Multi-fabric credential management
- `OperationalController` — Post-commissioning attribute/command operations
- `SubscriptionClient` — Client-side subscription management
- `DeviceRegistry` — Commissioned device tracking

**When to import**: When building a Matter controller or commissioner.

### MatterApple

**Purpose**: Apple platform networking using Network.framework.

**Key types**:
- `AppleUDPTransport` — UDP via `NWConnection` / `NWListener`
- `AppleDiscovery` — mDNS via `NWBrowser`, interface-aware registration

**When to import**: On Apple platforms (macOS, iOS). The `MatterSwift` umbrella imports this automatically on Darwin.

### MatterLinux

**Purpose**: Linux platform networking using SwiftNIO.

**Key types**:
- `LinuxUDPTransport` — UDP via `DatagramBootstrap` (dual-stack IPv6)
- `LinuxDiscovery` — Pure-Swift mDNS (RFC 6762) via multicast UDP

**When to import**: On Linux. The `MatterSwift` umbrella imports this automatically on Linux.

### MatterSwift

**Purpose**: Convenience umbrella that re-exports all modules.

```swift
// This single import gives you everything:
import MatterSwift
```

On Apple platforms, it includes `MatterApple`. On Linux, it includes `MatterLinux`. Use individual module imports if you want to minimize your dependency surface.

## External Dependencies

| Dependency | Used By | Purpose |
|------------|---------|---------|
| [swift-crypto](https://github.com/apple/swift-crypto) | MatterCrypto | P-256, AES, SHA-256, HKDF, HMAC |
| [swift-certificates](https://github.com/apple/swift-certificates) | MatterCrypto | X.509 certificate building |
| [swift-asn1](https://github.com/apple/swift-asn1) | MatterCrypto | ASN.1/DER encoding |
| [swift-log](https://github.com/apple/swift-log) | MatterTransport, MatterProtocol | Structured logging |
| [swift-collections](https://github.com/apple/swift-collections) | MatterProtocol | OrderedDictionary, Deque |
| [swift-nio](https://github.com/apple/swift-nio) | MatterLinux | UDP transport on Linux |
