# Persistent Storage

Implement storage so your Matter device or controller survives restarts.

## Overview

Matter devices and controllers maintain critical state that must persist across process restarts. Without persistence, a device must be recommissioned after every restart, and a controller loses its fabric credentials and device registry.

MatterSwift defines three storage protocols in the `MatterTypes` module. Implement them and pass your stores to the bridge or controller at initialisation.

## What Needs to Be Persisted

### For Devices/Bridges (`MatterFabricStore`)

| Data | Why It Matters |
|------|---------------|
| Fabric credentials | NOCs, root certificates, fabric IDs — without these, CASE sessions fail |
| ACL entries | Access control lists per fabric — without these, all requests are denied |
| PBKDF salt and iterations | Apple Home caches these after first PASE — changing them breaks recommissioning |
| Commissioning state | Fail-safe state, staged credentials during active commissioning |

### For Devices/Bridges (`MatterAttributeStore`)

| Data | Why It Matters |
|------|---------------|
| Attribute values | Device state (on/off, level, temperature) — controllers expect continuity |
| Data versions | Per-cluster version counters — subscriptions use these for delta reports |

### For Controllers (`MatterControllerStore`)

| Data | Why It Matters |
|------|---------------|
| Root CA key | Signs all NOCs — losing it means you can't communicate with commissioned devices |
| Fabric info | Fabric ID, controller node ID |
| Device registry | Commissioned device node IDs, operational addresses and how each passed attestation |
| Session cache | Active CASE sessions for fast reconnection |

## Storage Protocols

### MatterFabricStore

```swift
public protocol MatterFabricStore: Sendable {
    func load() async throws -> StoredDeviceState?
    func save(_ state: StoredDeviceState) async throws
}
```

`StoredDeviceState` is `Codable` and contains all fabric, ACL, and commissioning data.

### MatterAttributeStore

```swift
public protocol MatterAttributeStore: Sendable {
    func load() async throws -> StoredAttributeData?
    func save(_ data: StoredAttributeData) async throws
}
```

`StoredAttributeData` is `Codable` and contains all attribute values and data versions.

### MatterControllerStore

```swift
public protocol MatterControllerStore: Sendable {
    func load() async throws -> StoredControllerState?
    func save(_ state: StoredControllerState) async throws
}
```

`StoredControllerState` is `Codable` and contains fabric credentials, device registry, and session state.

### The controller store contract

A `MatterControllerStore` implementation must honour these rules, which `MatterControllerStoreConformance` checks:

- `load()` returns `nil` when nothing has been saved. It throws when state exists but cannot be read, including state written by a newer library (see below). It never returns partial state.
- `save(_:)` replaces the stored state entirely; there is no merge. It returns only once the state has been handed to durable storage as far as the implementation can tell. A failed save throws and leaves the previous state intact.
- Saved state loads back equal, secrets byte for byte.

`MatterController.loadOrCreate` saves a freshly generated identity immediately, and throws rather than return a controller whose identity exists nowhere. Callers must serialise concurrent `loadOrCreate` calls on one store: two racing calls could each create and save a different identity. A new identity gets a random IPK epoch key.

### Secret fields

`StoredControllerState` is mostly public data (certificates, node IDs, addresses), but three fields are secret and must be readable by the owning user only and never logged:

| Field | What it is |
|-------|------------|
| `identity.rootKeyRaw` | The fabric root CA private key |
| `identity.operationalKeyRaw` | The controller's operational private key |
| `identity.ipkEpochKey` | The fabric's Identity Protection Key epoch key |

A store backed by an encrypted secret store should protect at least these. The certificates, including the root and operational certificates, are public.

### Schema versioning

`StoredControllerState` carries a `schemaVersion`, currently 2. Version 2 added the per-device attestation record (`StoredAttestationRecord`: verified, or overridden with the approved DAC fingerprint, reason and time). A blob with no `schemaVersion` is version 1 and decodes with no attestation records. A blob with a version newer than the library understands throws on load, so an older library refuses it up front instead of dropping what it does not know on the next save.

That check does not exist in 1.0.0-beta.5 and earlier. Those releases will load a version 2 file and silently drop `schemaVersion` and the attestation records the next time they save. Do not run an older library against state a newer one wrote.

### Testing your store

The `MatterStoreConformance` product runs the contract against any implementation: empty load, save and load equality (secrets and both attestation record kinds included), replacement on a second save, and decoding of a version 1 blob. It imports Testing, so link it only from test targets. Give it a closure that returns a fresh, empty store each time it is called:

```swift
// Package.swift
.testTarget(
    name: "MyStoreTests",
    dependencies: [
        "MyStore",
        .product(name: "MatterStoreConformance", package: "matter-swift"),
    ]
)
```

```swift
import Testing
import MatterStoreConformance

@Suite("MyControllerStore")
struct MyControllerStoreTests {
    @Test("conforms to the MatterControllerStore contract")
    func conforms() async throws {
        try await MatterControllerStoreConformance.run { MyControllerStore.makeEmpty() }
    }
}
```

Failures are reported through `Issue.record`.

### The JSON file store

`JSONFileControllerStore` is a ready-made implementation for standalone and development use. It writes the state as plaintext JSON, owner-only (`0600`): the file is created with that mode before any bytes are written, then renamed over the target, so the secrets are never readable by others, and a save tightens a more permissive existing file. It does not encrypt, and it does not fsync the containing directory, so power loss immediately after a save can still lose it. A production embedder should supply its own `MatterControllerStore` that keeps the root CA key in its own secret store.

## Implementing a Simple File Store

Here's a minimal JSON file-based implementation:

```swift
import Foundation
import MatterTypes

final class JSONFileStore<T: Codable & Sendable>: Sendable {
    let fileURL: URL

    init(directory: URL, filename: String) {
        self.fileURL = directory.appendingPathComponent(filename)
    }

    func load() async throws -> T? {
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return nil
        }
        let data = try Data(contentsOf: fileURL)
        return try JSONDecoder().decode(T.self, from: data)
    }

    func save(_ state: T) async throws {
        let data = try JSONEncoder().encode(state)
        try data.write(to: fileURL, options: .atomic)
    }
}

// Conform to storage protocols
final class FileFabricStore: MatterFabricStore, Sendable {
    private let store = JSONFileStore<StoredDeviceState>(
        directory: .applicationSupportDirectory,
        filename: "matter-fabric.json"
    )

    func load() async throws -> StoredDeviceState? {
        try await store.load()
    }

    func save(_ state: StoredDeviceState) async throws {
        try await store.save(state)
    }
}

final class FileAttributeStore: MatterAttributeStore, Sendable {
    private let store = JSONFileStore<StoredAttributeData>(
        directory: .applicationSupportDirectory,
        filename: "matter-attributes.json"
    )

    func load() async throws -> StoredAttributeData? {
        try await store.load()
    }

    func save(_ data: StoredAttributeData) async throws {
        try await store.save(data)
    }
}
```

## Wiring Stores to MatterBridge

Pass your stores when creating the bridge:

```swift
let fabricStore = FileFabricStore()
let attributeStore = FileAttributeStore()

let bridge = MatterBridge(
    config: .init(vendorName: "MyCompany", productName: "Hub"),
    fabricStore: fabricStore,
    attributeStore: attributeStore
)
```

The bridge loads persisted state during initialisation and saves automatically when state changes (fabric commits, attribute writes).

## Wiring Stores to MatterController

```swift
let controllerStore = FileControllerStore()

let controller = try MatterController(
    transport: AppleUDPTransport(),
    discovery: AppleDiscovery(),
    configuration: .init(fabricID: FabricID(rawValue: 1)),
    store: controllerStore
)
```

## What Happens Without Persistence

If you don't provide stores:

- **Device/Bridge**: Works for the current session, but after restart:
  - A new random PBKDF salt is generated — Apple Home's cached parameters become invalid
  - All fabric credentials are lost — CASE sessions fail
  - Controllers must recommission the device from scratch

- **Controller**: Works for the current session, but after restart:
  - The root CA key is regenerated — existing NOCs are no longer valid
  - The device registry is empty — no knowledge of previously commissioned devices
  - All devices must be recommissioned

For development and testing, running without persistence is fine. For any production use, implement at least `MatterFabricStore`.

## PBKDF Salt Persistence

A particularly important detail for bridges: the PBKDF salt used during SPAKE2+ must be stable across restarts. Apple Home (and most controllers) cache the salt and iteration count after a successful PASE session. If the device generates a new salt on restart, the cached parameters produce a different SPAKE2+ verifier, and commissioning fails silently.

`MatterFabricStore` handles this automatically — the salt is included in `StoredDeviceState`.
