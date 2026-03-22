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
| Device registry | Commissioned device node IDs and operational addresses |
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
