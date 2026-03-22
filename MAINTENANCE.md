# MatterSwift Maintenance Guide

How to build, test, extend, and maintain the MatterSwift library.

## Prerequisites

- **Swift 6.1+** (Xcode 16.3+ on macOS)
- **Docker** (for Linux testing)
- **connectedhomeip repo** (optional, for reference tests and code generation)

## Building and Testing

### Quick Commands

```bash
swift build                    # Debug build
swift test --parallel          # Run all tests
make linux-build               # Build in Docker (swift:6.2-noble)
make linux-test                # Run tests in Docker
```

### Test Targets

| Target | What It Tests | Requires |
|--------|--------------|----------|
| MatterTypesTests | TLV encoding/decoding | Nothing |
| MatterModelTests | Cluster codability, device type registry | Nothing |
| MatterCryptoTests | CASE, SPAKE2+, certificates, CSR | Nothing |
| MatterProtocolTests | MRP, sessions, Interaction Model | Nothing |
| MatterDeviceTests | Cluster handlers, subscriptions, commissioning | Nothing |
| MatterControllerTests | Commissioning flow, fabric management | Nothing |
| MatterAppleTests | Apple transport | macOS |
| MatterLinuxTests | Linux transport | Linux |
| IntegrationTests | End-to-end with chip-tool | chip-tool binary |
| ReferenceTests | Crypto vectors, chip-cert conformance | chip-cert binary |

### Reference Tests (Optional)

Reference tests validate against the CHIP SDK's official tools:

```bash
make ref-setup          # Clone connectedhomeip, build chip-cert + chip-tool (~30 min first run)
make ref-setup-cert     # Build chip-cert only (faster)
make ref-test           # Run reference tests
make ref-all            # Build chip-cert then run reference tests
```

The CHIP SDK version is pinned in `Tools/RefImpl/CONNECTEDHOMEIP_VERSION` (currently `v1.4.0.0`).

If chip-cert/chip-tool are not available, reference and integration tests skip gracefully.

## Code Generation Pipeline

Cluster definitions and device types are **auto-generated** from the Matter specification XML, not hand-written.

### How It Works

```
connectedhomeip/data_model/1.4/clusters/*.xml
connectedhomeip/data_model/1.4/device_types/*.xml
                    ↓
        Tools/MatterModelGenerator/
        (Swift executable, ~2,770 lines)
                    ↓
Sources/MatterModel/Generated/
├── ClusterDefinitions.generated.swift     (cluster ID constants)
├── ClusterMetadata.generated.swift        (runtime cluster registry)
├── Clusters/                              (110 .generated.swift files)
│   ├── OnOffCluster.generated.swift
│   ├── LevelControlCluster.generated.swift
│   └── ...
└── DeviceTypes/
    └── DeviceTypeRegistry.generated.swift (72 device types)
```

### Running Code Generation

```bash
make ref-setup          # Ensure connectedhomeip is cloned
make generate-model     # Regenerate all cluster definitions
```

This runs the `MatterModelGenerator` tool against the XML data model and writes output to `Sources/MatterModel/Generated/`.

**Generated files are committed to git.** This allows developers to review diffs when the spec version changes and means consumers don't need the CHIP SDK to build.

### CI Enforcement

The CI pipeline has a "generated code freshness" job that:
1. Regenerates cluster definitions from the XML source
2. Compares the output to the committed files
3. **Fails the PR** if they differ

If CI fails with "Generated code is out of date", run `make generate-model` and commit the results.

## Updating to a New Matter Spec Version

1. **Update the version pin:**
   ```bash
   echo "v1.5.0.0" > Tools/RefImpl/CONNECTEDHOMEIP_VERSION
   ```

2. **Re-clone and regenerate:**
   ```bash
   make ref-clean          # Remove old binaries
   make ref-setup          # Clone new version
   make generate-model     # Regenerate cluster definitions
   ```

3. **Review the diff:**
   ```bash
   git diff Sources/MatterModel/Generated/
   ```
   Look for new clusters, changed attribute IDs, new commands, or removed fields.

4. **Update hand-written code if needed:**
   - New required attributes on existing clusters → update handlers in `Sources/MatterDevice/Clusters/`
   - New required clusters for existing device types → update `MatterBridge` convenience methods
   - Changed command schemas → update handler command parsing

5. **Re-extract test vectors (if crypto tests changed):**
   ```bash
   python3 Tools/RefImpl/extract_test_vectors.py
   ```

6. **Run tests:**
   ```bash
   swift test --parallel
   make ref-test
   ```

7. **Commit everything:**
   ```bash
   git add -A
   git commit -m "Update Matter spec to v1.5.0.0"
   ```

## Adding a New Cluster Handler

Cluster handlers live in `Sources/MatterDevice/Clusters/` and conform to the `ClusterHandler` protocol.

### Step-by-Step

1. **Check if the cluster definition exists** in `Sources/MatterModel/Generated/Clusters/`. If the cluster is in the 9 "skipped" set (Access Control, Basic Information, etc.), it will have a `.spec.generated.swift` file with just IDs.

2. **Create the handler file:**
   ```
   Sources/MatterDevice/Clusters/MyNewClusterHandler.swift
   ```

3. **Implement `ClusterHandler`:**
   ```swift
   // MyNewClusterHandler.swift
   // Copyright 2026 Monagle Pty Ltd

   import MatterTypes
   import MatterModel
   import MatterProtocol

   public final class MyNewClusterHandler: ClusterHandler, @unchecked Sendable {
       public let clusterID: ClusterID = .myNewCluster

       public func initialAttributes() -> [(AttributeID, TLVValue)] {
           [
               (MyNewCluster.Attribute.someAttribute, .unsignedInt(0)),
           ]
       }

       public func handleCommand(
           _ commandID: CommandID,
           fields: TLVElement?,
           context: ClusterCommandContext
       ) async throws -> [TLVElement]? {
           switch commandID {
           case MyNewCluster.Command.someCommand:
               // Handle the command
               return nil // or return response TLV
           default:
               throw MatterError.unsupportedCommand
           }
       }
   }
   ```

4. **Reference existing handlers** for patterns:
   - Simple: `OnOffHandler.swift` (on/off/toggle commands)
   - Medium: `LevelControlHandler.swift` (attribute writes + commands)
   - Complex: `ColorControlHandler.swift` (multiple command schemas, feature flags)
   - Fabric-scoped: `AccessControlHandler.swift` (fabric filtering)

5. **Wire it into `MatterBridge`** if adding a new device type convenience method.

6. **Add tests** in `Tests/MatterDeviceTests/`:
   ```
   Tests/MatterDeviceTests/MyNewClusterHandlerTests.swift
   ```

## Adding a New Bridge Device Type

To add a convenience method like `addSmokeCOAlarm()`:

1. **Look up the device type** in `Sources/MatterModel/Generated/DeviceTypes/DeviceTypeRegistry.generated.swift` for the device type ID and required clusters.

2. **Add the method to `MatterBridge`:**
   ```swift
   public func addSmokeCOAlarm(name: String, uniqueID: String = "") -> BridgedEndpoint {
       let clusters: [(ClusterID, ClusterHandler)] = [
           (.smokeCoAlarm, SmokeCoAlarmHandler()),
           // Add other required clusters
       ]
       return registerBridgedEndpoint(
           name: name,
           uniqueID: uniqueID,
           deviceTypeID: .smokeCOAlarm,
           clusters: clusters
       )
   }
   ```

3. **Add setters to `BridgedEndpoint`** for bridge-side state updates.

4. **Add tests** for the new device type.

## Reference Test Infrastructure

### Crypto Vector Tests

Test vectors are extracted from the connectedhomeip C++ test headers and converted to Swift:

```bash
python3 Tools/RefImpl/extract_test_vectors.py
```

This reads from `connectedhomeip/src/crypto/tests/*.h` and writes Swift fixtures to `Tests/ReferenceTests/Fixtures/`. The fixtures are committed to the repo so tests run without the CHIP SDK.

Vectors cover: AES-128-CCM, HKDF-SHA256, HMAC-SHA256, PBKDF2-SHA256, SHA-256, and Destination ID computation.

### Certificate Conformance Tests

`Tests/ReferenceTests/CertificateConformanceTests.swift` uses the `chip-cert` binary to validate:
- RCAC and NOC generation (TLV encoding)
- TLV → DER conversion (byte-for-byte match)
- Certificate chain validation (PAA → PAI → DAC)

### Integration Tests

`Tests/IntegrationTests/` runs chip-tool against a MatterSwift device server over loopback:
- Commission via PASE → CASE
- Read OnOff attribute
- Toggle OnOff command
- Subscription with report

## CI Pipeline

Located at `.github/workflows/ci.yml`. Three jobs:

1. **Generated code freshness** (Linux)
   - Sparse-clones connectedhomeip XML
   - Regenerates cluster definitions
   - Fails if output differs from committed code

2. **macOS build + test** (macos-15, depends on job 1)
   - `swift build && swift test --parallel`
   - Skips IntegrationTests and ReferenceTests

3. **Linux build + test** (swift:6.2-noble, depends on job 1)
   - Same test suite with `.build/` caching

10-minute timeout per job. Concurrency group prevents parallel runs on the same branch.

## Code Conventions

### Copyright Header
```swift
// FileName.swift
// Copyright 2026 Monagle Pty Ltd
```

### Section Markers
```swift
// MARK: - Section Name
```

### Testing Framework
Swift Testing (not XCTest):
```swift
import Testing

@Suite("My Cluster Handler")
struct MyClusterHandlerTests {
    @Test("handles toggle command")
    func toggleCommand() async throws {
        // ...
    }
}
```

### Concurrency
Swift 6 strict concurrency throughout:
- **Value types** for stateless operations (TLV codec, messages)
- **Actors** for mutable shared state (session table, subscription manager, transport)
- **`@unchecked Sendable`** for bridge-owned types with controlled internal synchronisation
- All public APIs are `Sendable`
