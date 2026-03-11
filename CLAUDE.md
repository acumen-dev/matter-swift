# SwiftMatter

Native Swift implementation of the Matter smart home protocol. Provides both device/bridge and controller roles for building Matter-compatible applications.

## Commands

```bash
swift build          # Build all targets
swift test           # Run test suite (Swift Testing)
```

## Module Architecture

| Module | Purpose | Dependencies |
|--------|---------|-------------|
| `MatterTypes` | Core types, TLV encoding/decoding, status codes, identifiers. Zero external dependencies | none |
| `MatterModel` | Cluster definitions, device types, attribute schemas. Code-generated from Matter XML specs | MatterTypes |
| `MatterCrypto` | SPAKE2+, CASE/Sigma, AES-128-CCM session encryption, Matter Operational Certificates | MatterTypes, swift-crypto, swift-certificates, swift-asn1 |
| `MatterTransport` | Platform-agnostic transport protocol abstractions (UDP, mDNS/DNS-SD) | MatterTypes, swift-log |
| `MatterProtocol` | Wire protocol: message framing, MRP (reliability), session management, Interaction Model | MatterTypes, MatterModel, MatterCrypto, MatterTransport |
| `MatterDevice` | Device/bridge role: endpoint management, attribute storage, subscription reports, commissioning responder | MatterProtocol |
| `MatterController` | Controller role: commissioning, operational communication, device management | MatterProtocol |
| `MatterApple` | Apple platform transport: Network.framework for UDP/mDNS, CryptoKit integration | MatterTransport, MatterCrypto |
| `SwiftMatter` | Convenience re-export of all modules | all |

### Module Dependency Graph

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
└── MatterLinux (SwiftNIO, swift-crypto, avahi) — future
```

## Key Concepts

### TLV (Tag-Length-Value)

Matter's binary wire format. All protocol messages, attribute values, and certificates use TLV encoding. Similar to CBOR but simpler. Types include: signed/unsigned integers (1-8 bytes), booleans, UTF-8 strings, octet strings, null, floats/doubles, structures, arrays, and lists.

Tags can be anonymous, context-specific (1-byte), common profile (2-byte), or fully qualified (vendor + profile + tag). Context tags are most common in protocol messages.

### Endpoints, Clusters, Attributes

- **Endpoint**: A logical sub-device within a node. Endpoint 0 = root node (utility clusters). For bridges: endpoint 1 = aggregator, 2+ = bridged devices.
- **Cluster**: A collection of related functionality (e.g., OnOff, LevelControl, ColorControl). Identified by 32-bit cluster ID.
- **Attribute**: Persistent state within a cluster (e.g., OnOff.onOff, LevelControl.currentLevel). Identified by 16-bit attribute ID within its cluster.
- **Command**: An action on a cluster (e.g., OnOff.on, LevelControl.moveToLevel). Has request/response schemas.
- **Event**: An asynchronous notification from a cluster (e.g., DoorLock.doorLockAlarm).

### Device Types

Specification-defined templates that prescribe which clusters an endpoint must implement:

| Device Type | ID | Required Clusters |
|---|---|---|
| On/Off Light | 0x0100 | OnOff, Descriptor |
| Dimmable Light | 0x0101 | OnOff, LevelControl, Descriptor |
| Color Temperature Light | 0x0102 | OnOff, LevelControl, ColorControl (CT), Descriptor |
| Extended Color Light | 0x010D | OnOff, LevelControl, ColorControl (full), Descriptor |
| On/Off Plug-in Unit | 0x010A | OnOff, Descriptor |
| Contact Sensor | 0x0015 | BooleanState, Descriptor |
| Occupancy Sensor | 0x0107 | OccupancySensing, Descriptor |
| Temperature Sensor | 0x0302 | TemperatureMeasurement, Descriptor |
| Humidity Sensor | 0x0307 | RelativeHumidityMeasurement, Descriptor |
| Thermostat | 0x0301 | Thermostat, Descriptor |
| Door Lock | 0x000A | DoorLock, Descriptor |
| Window Covering | 0x0202 | WindowCovering, Descriptor |
| Fan | 0x002B | FanControl, Descriptor |
| Bridge | 0x000E | Descriptor (with PartsList), BridgedDeviceBasicInformation |
| Smoke CO Alarm | 0x0076 | SmokeCoAlarm, Descriptor |

### Sessions and Security

- **PASE (Password-Authenticated Session Establishment)**: Used during commissioning. SPAKE2+ protocol with the device's setup passcode. Establishes encrypted session for provisioning.
- **CASE (Certificate-Authenticated Session Establishment)**: Used for all operational communication. Mutual authentication via Node Operational Certificates (NOCs) using ECDSA/ECDH (P-256).
- **Session encryption**: AES-128-CCM for all messages after session establishment.
- **Fabrics**: A trust domain. Each fabric has a root CA, and all nodes in the fabric have NOCs signed by that CA. A device can belong to multiple fabrics (multi-admin).

### Message Reliability Protocol (MRP)

UDP-based reliable messaging. Features:
- Message counters for deduplication
- ACK piggyback (ack previous message in next response)
- Standalone ACKs for one-way messages
- Retransmission with exponential backoff (configurable idle/active intervals)
- Exchange tracking (request/response pairs)

### Interaction Model

The application-layer protocol for reading/writing data:
- **Read**: Request attribute/event values. Supports chunked responses for large payloads.
- **Write**: Set attribute values. Timed writes add a timeout for security-sensitive operations.
- **Subscribe**: Establish ongoing attribute/event monitoring. Server sends reports on changes (min/max intervals).
- **Invoke**: Execute commands. Timed invokes for security-sensitive operations.
- **DataVersion filtering**: Clients track per-cluster data versions to skip unchanged data in reads/subscribes.

### Bridge Architecture

A Matter bridge exposes non-Matter devices as Matter endpoints:
- **Endpoint 0**: Root node — identity, commissioning, credentials, access control
- **Endpoint 1**: Aggregator (device type 0x000E) — its Descriptor.PartsList lists all bridged endpoints
- **Endpoints 2+**: Bridged devices — each has device-type-specific clusters + BridgedDeviceBasicInformation + Descriptor
- **External attribute storage**: Bridge implements read/write callbacks to serve attribute values from its own data structures
- **Dynamic endpoints**: Added/removed at runtime as bridged devices come and go

### Commissioning Flow

1. Device advertises as commissionable via mDNS (`_matterc._udp`) or BLE
2. Commissioner reads setup code (QR or manual 11-digit)
3. PASE session established via SPAKE2+ with the passcode
4. Commissioner provisions network credentials (Wi-Fi/Thread)
5. Commissioner issues Node Operational Certificate (NOC)
6. Commissioner writes Access Control entries
7. Device begins operational mDNS advertisement (`_matter._tcp`)
8. All further communication uses CASE sessions

## Transport Abstractions

Platform-specific networking is abstracted via protocols:

```swift
protocol MatterUDPTransport: Sendable {
    func send(_ data: Data, to address: MatterAddress) async throws
    func receive() -> AsyncStream<(Data, MatterAddress)>
    func bind(port: UInt16) async throws
    func close() async
}

protocol MatterDiscovery: Sendable {
    func advertise(service: MatterServiceRecord) async throws
    func browse(type: MatterServiceType) -> AsyncStream<MatterServiceRecord>
    func resolve(_ record: MatterServiceRecord) async throws -> MatterAddress
    func stopAdvertising() async
}
```

- **MatterApple**: Uses `NWConnection`/`NWListener` for UDP, `NWBrowser` for mDNS
- **MatterLinux** (future): Uses SwiftNIO `DatagramBootstrap` for UDP, avahi for mDNS

## Crypto Primitives Required

All available via CryptoKit (Apple) / swift-crypto (Linux):

| Primitive | Use |
|---|---|
| P-256 (ECDSA) | Certificate signing/verification, CASE authentication |
| P-256 (ECDH) | Key agreement in CASE/Sigma |
| SPAKE2+ (P-256) | Password-authenticated key exchange for PASE |
| PBKDF2-SHA256 | SPAKE2+ verifier computation from passcode |
| HKDF-SHA256 | Session key derivation from shared secrets |
| AES-128-CCM | Message encryption/decryption |
| HMAC-SHA256 | Message authentication in SPAKE2+ |
| SHA-256 | General hashing |

Note: AES-128-CCM is not directly in CryptoKit — use `_CryptoExtras` or implement CCM mode from AES-CTR + CBC-MAC.

## Code Conventions

- **Copyright header:** `// FileName.swift\n// Copyright 2026 Monagle Pty Ltd`
- **Section markers:** `// MARK: - Section Name`
- **Imports:** Explicit, no wildcards
- **Access levels:** Public API types are `public`. Internal implementation details are `internal` or `package`
- **Documentation:** Triple-slash `///` with code examples
- **Tests:** Swift Testing framework (`import Testing`, `@Suite("Name")`, `@Test("description")`)
- **Concurrency:** Swift 6.2 strict concurrency. Sendable types throughout. Actors where needed for mutable state

## Concurrency Model

| Type | Approach | Rationale |
|------|----------|-----------|
| TLV encoder/decoder | Value types (struct) | Stateless, pure functions |
| Session table | Actor | Mutable shared state across exchanges |
| Exchange manager | Actor | Tracks in-flight request/response pairs |
| Endpoint storage | Actor or `@unchecked Sendable` | Attribute values mutated by both bridge and protocol |
| Subscription manager | Actor | Tracks per-fabric subscription state |
| UDP transport | Actor wrapping NWConnection | Socket lifecycle |
| mDNS discovery | Actor wrapping NWBrowser | Browse/advertise lifecycle |

## Reference Materials

- [Matter Specification](https://csa-iot.org/developer-resource/specifications-download-request/) — requires CSA account
- [matter.js source](https://github.com/matter-js/matter.js) — primary architectural reference (TypeScript)
- [rs-matter source](https://github.com/project-chip/rs-matter) — Rust reference implementation
- [connectedhomeip data_model XML](https://github.com/project-chip/connectedhomeip/tree/master/data_model) — cluster definitions for code generation
- [connectedhomeip bridge-app](https://github.com/project-chip/connectedhomeip/tree/master/examples/bridge-app) — bridge pattern reference
- [Matter TLV specification](https://project-chip.github.io/connectedhomeip-doc/) — TLV encoding details

## Common Pitfalls

- **AES-128-CCM is not AES-GCM**: Matter uses CCM (Counter with CBC-MAC), not GCM. CryptoKit does not expose CCM directly — use `_CryptoExtras` or build from AES block cipher primitives.
- **TLV signed integers**: Matter TLV uses signed integers in 1/2/4/8 byte widths. The encoder must choose the smallest width that fits the value. Decoders must accept any width.
- **TLV tag encoding**: Context tags use 1 byte. Common profile tags use 2 bytes. Fully qualified tags use 6 bytes. Most protocol messages use context tags exclusively.
- **Message counters are per-session**: Each session maintains its own monotonic message counter. Counters must never wrap within a session.
- **MRP idle vs active intervals**: Devices in idle mode use longer retransmission intervals (typically 500ms) than active mode (typically 300ms). The intervals are negotiated during session establishment.
- **SPAKE2+ uses W0 and W1**: The verifier computation from passcode requires PBKDF2 with a specific salt and iteration count. W0 is used in the protocol exchange, W1 is the verifier stored on the device.
- **Matter certificates are TLV-encoded**: Unlike typical X.509 which uses DER, Matter Operational Certificates use a TLV encoding defined in the spec. They still carry the same P-256 public keys and signatures.
- **Subscription max interval floor**: The Matter spec mandates a minimum max-interval of 60 seconds for subscriptions. Controllers may request shorter, but devices should enforce this floor.
- **Fabric-scoped data**: Many attributes (ACLs, bindings, group keys) are fabric-scoped — they have different values per fabric. The Interaction Model includes fabric filtering for reads/subscribes.
- **Timed writes/invokes**: Security-sensitive operations (door locks, garage doors) require a timed flow where the client first requests a timeout window, then sends the actual write/invoke within that window.
- **Bridge PartsList updates**: When dynamic endpoints are added/removed, the aggregator's Descriptor.PartsList attribute must be updated and subscription reports must be sent to all subscribers.
- **Setup passcode restrictions**: Certain passcodes are invalid (00000000, 11111111, 22222222, ..., 99999999, 12345678, 87654321). The spec lists exactly which ones.
- **Discriminator is 12 bits**: Values 0-4095. Used to distinguish between multiple commissionable devices. The long discriminator (12 bits) is in the QR code; a short discriminator (4 bits, top 4 of long) is in mDNS/BLE advertisements.
