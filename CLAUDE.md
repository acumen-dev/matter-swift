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
7. Device begins operational mDNS advertisement (`_matter._tcp`) — **immediately after AddNOC** (not after CommissioningComplete)
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

---

## Current Implementation Status

### What is working (as of this branch)

- **PASE / SPAKE2+**: Full handshake working — PBKDFParamRequest/Response, Pake1/2/3
- **Commissioning flow**: AddNOC, AddTrustedRootCertificate, WriteACL, CommissioningComplete
- **Operational mDNS**: Advertised after AddNOC (before CommissioningComplete) with interface restriction
- **PBKDF salt persistence**: Stable across restarts so Apple Home's cached params remain valid
- **CASE key derivation**: Full transcript-hash approach (Sigma1/Sigma2/Sigma3) per Matter spec §5.5.2
- **CASE signature format**: IEEE P1363 (64-byte raw r‖s) for both cert sigs and Sigma2/3 TBE sigs
- **Sigma1 retransmit handling**: Stored Sigma2 is resent on duplicate Sigma1 (same exchange ID)
- **Stale session graceful handling**: Decryption failures on established sessions silently dropped
- **Compressed Fabric ID**: Fixed to use HKDF-SHA256 over full 64-byte public key (not X-only)
- **IPK derivation**: Fixed info string from `"GroupKeyHash"` to `"GroupKey v1.0"` per spec
- **ACL fabricIndex fixup**: Stage-to-commit path stamps the real fabricIndex onto all staged entries
- **Device Attestation Credentials**: X.509 PAI/DAC with correct Matter VID/PID OIDs in Subject DN
- **PASE MRP session params**: Tag 5 (responderSessionParams) always included in PBKDFParamResponse

- **Certificate DER TBS** (FIXED): `tbsData()` now produces X.509 DER `TBSCertificate` bytes, matching chip-cert byte-for-byte. Signatures use IEEE P1363 (rawRepresentation). Certificate chain validation works end-to-end.
- **Reference test framework**: chip-cert conformance tests (TLV→DER conversion, NOC chain validation, TBS comparison) and crypto vector tests (AES-CCM, HKDF, HMAC, PBKDF2, SHA-256, Destination ID)
- **chip-tool integration tests**: End-to-end commissioning (PASE→CASE) and attribute read/toggle against the CHIP SDK's chip-tool binary. Commission + OnOff read + OnOff toggle all pass.
- **CASE encrypted sessions**: Nonce construction uses session node IDs (not message header). Secured unicast omits source node ID from wire header. Full CASE session establishment and encrypted IM exchange verified against chip-tool.
- **AddNOC admin ACL**: Creates initial Administer ACL from caseAdminSubject per spec §11.17.6.8. Staged ACLs available during fail-safe for CASE CommissioningComplete.
- **Pake1 retransmit dedup**: Stored Pake2 is resent on duplicate Pake1 (same pattern as PBKDFParamRequest and Sigma1)
- **Attestation credentials**: Auto-generated test DAC chain (PAA→PAI→DAC) on server startup

---

## Uncommitted Changes Reference

This section documents all 30 files with uncommitted changes so Claude (in a future session) can understand the purpose of each change without re-reading every diff.

### `Sources/MatterCrypto/CASEKeyDerivation.swift` (+162/-88)

**What changed:** Complete rewrite of sigma key and session key derivation to use SHA-256 transcript hashes per Matter Core Spec §5.5.2.

**Before:** Used a single 48-byte HKDF output with a static salt (IPK ‖ responderRandom ‖ responderEphPubKey ‖ initiatorEphPubKey) and info string `"SEKeys"`. Split it 0-15 = S2K, 16-31 = S3K.

**After:** Three separate HKDF derivations:

- **S2K** (`deriveSigma2Key`): `salt = IPK ‖ σ2.Responder_Random ‖ σ2.Responder_EPH_PubKey ‖ SHA256(σ1)`, info = `"Sigma2"`, length = 16 bytes
- **S3K** (`deriveSigma3Key`): `salt = IPK ‖ SHA256(σ1 ‖ σ2)`, info = `"Sigma3"`, length = 16 bytes
- **Session keys** (`deriveSessionKeys`): `salt = IPK ‖ SHA256(σ1 ‖ σ2 ‖ σ3)`, info = `"SessionKeys"`, length = 48 bytes → I2R[0..15] ‖ R2I[16..31] ‖ Attestation[32..47]

All three now accept `SharedSecret` (not `Data`) so `hkdfDerivedSymmetricKey()` can be called on the ECDH secret directly.

### `Sources/MatterCrypto/CASESession.swift` (+199/-?)

**What changed:** Updated both initiator and responder sides to use the new transcript-hash key derivation, store raw Sigma message bytes in context objects, and fix P1363 signature formats.

**Key changes:**

1. **`InitiatorContext`** now carries `sigma1Bytes: Data` (the raw TLV bytes sent to the responder).

2. **`ResponderContext`** now carries:
   - `sharedSecret: SharedSecret` (retained so S3K and session keys can be derived later — previously discarded after S2K)
   - `sigma1Bytes: Data` (raw Sigma1 bytes received)
   - `sigma2Bytes: Data` (raw Sigma2 bytes sent)
   - Removed: `s2k`, `s3k` (no longer pre-computed in step 1)

3. **TBE signatures are IEEE P1363** — changed from `.derRepresentation` to `.rawRepresentation` in both Sigma2 and Sigma3 payloads. Verification also changed to `rawRepresentation`. The Matter spec §6.6.1 requires 64-byte raw r‖s format.

4. **Raw NOC/ICAC bytes forwarded** — `responderStep1()` uses `fabricInfo.rawNOC ?? fabricInfo.noc.tlvEncode()` instead of always re-encoding. This ensures Apple Home receives back the exact NOC bytes it installed rather than a re-encoded version that may differ.

5. **Sigma1 retransmit detection** — if `handleSigma1` is called twice with the same exchange ID, the stored `sigma2Payload` is resent without re-processing. Regenerating a fresh Sigma2 with different ephemeral keys would invalidate any in-flight Sigma3.

6. **`[CASE-DIAG]` diagnostic prints** — hex dumps of TBS2, SIG, PUBKEY, and NOC for offline Python verification. These print on every Sigma2 generation and must be removed once cert verification is fixed.

### `Sources/MatterCrypto/MatterCertificate.swift` (+138/-?)

**What changed:** Added `rawTLV: Data?` field to preserve original bytes from `fromTLV()`, rewrote `tbsData()` to scan for the signature field in raw bytes, added extensive diagnostics to `verify(with:)`.

**Key changes:**

1. **`tbsData()` rewritten** — now produces X.509 DER `TBSCertificate` bytes using `PKCS10CSRBuilder` helpers. Maps Matter DN attributes to OIDs, Matter epoch times to UTCTime/GeneralizedTime, and Matter extensions to standard X.509 extensions. Output matches chip-cert byte-for-byte.

2. **`toX509Name()`** added to `MatterDistinguishedName` — converts Matter DN attributes to X.509 RDN sequences with OIDs under `1.3.6.1.4.1.37244.1.*` and 16-char hex UTF8String values.

3. **`toX509Extension()`** added to `CertificateExtension` — encodes each extension to X.509 DER with correct criticality flags (BasicConstraints, KeyUsage, EKU all critical).

4. **Signature format** — `generateRCAC()`/`generateNOC()` now use `sig.rawRepresentation` (IEEE P1363, 64 bytes) instead of `sig.derRepresentation`. `verify(with:)` tries P1363 first, falls back to DER.

5. **Default validity dates** — `generateRCAC()`/`generateNOC()` default to current time → 10 years instead of epoch 0.

6. **All diagnostic prints removed** — `[TBS-DIAG]`, `[VERIFY-DIAG]` removed from this file; `[CASE-DIAG]`, `[CASE-CHAIN]` removed from `CASESession.swift`.

### `Sources/MatterCrypto/FabricInfo.swift` (+114/-?)

**What changed:** Added `rawNOC`, `rawICAC`, and `ipkEpochKey` fields; fixed `compressedFabricID()` to use HKDF rather than HMAC; fixed `deriveIPK()` info string.

**Key changes:**

1. **`rawNOC: Data?`** — exact TLV bytes of the NOC as received during commissioning. Used by `CASESession.responderStep1()` to avoid re-encoding. Passed through `toFabricInfo()` in `CommissioningState`.

2. **`rawICAC: Data?`** — exact TLV bytes of the ICAC. Also forwarded verbatim in Sigma2. Defaults to `icac?.tlvEncode()` if not provided.

3. **`ipkEpochKey: Data`** — the IPK epoch key from the AddNOC command's `IPKValue` field. Defaults to 16 zero bytes for backward compatibility. Previously `deriveIPK()` always used all-zeros regardless.

4. **`compressedFabricID()` rewritten** — was using `HMAC<SHA256>(key: xCoordinate, data: fabricIDBytes)`. Must be `HKDF<SHA256>(IKM: fullRawKey, salt: fabricIDBytes, info: "CompressedFabric", length: 8)` per spec §4.3.1.2.2. The full 64-byte raw key (X‖Y without the 0x04 prefix) is the IKM — not just the 32-byte X coordinate. The old approach produced a CFID that did not match Apple Home.

5. **`deriveIPK()` info string** — was `"GroupKeyHash"`. Correct string is `"GroupKey v1.0"` per Matter spec §4.12.3. The epoch key parameter is now `Data?` with `nil` defaulting to `self.ipkEpochKey`.

### `Sources/MatterDevice/Server/CommissioningState.swift` (+59/-?)

**What changed:** Added PBKDF persistence fields, `onNOCStaged`/`onNOCReverted` callbacks, and ACL fabricIndex fixup on commit.

**Key changes:**

1. **`pbkdfSalt: Data?` and `pbkdfIterations: Int`** — stored so that `MatterDeviceServer` can use the same salt on restart. Apple Home (and most commissioners) cache PBKDF parameters after a successful PASE. If the salt changes on restart, `hasPBKDFParameters = true` causes SPAKE2+ to fail because the verifier was computed with a different salt.

2. **`onNOCStaged: (() -> Void)?`** — called immediately after `commitNOC()` stages the NOC. The server uses this to advertise the operational mDNS record. Per Matter spec §4.3.5, the device MUST begin operational advertisement after AddNOC, not after CommissioningComplete. Apple Home waits for this record before sending CommissioningComplete.

3. **`onNOCReverted: (() -> Void)?`** — called when `disarmFailSafe()` or `ArmFailSafe(expiryLengthSeconds=0)` reverts staged credentials. Server withdraws the operational advertisement.

4. **ACL fabricIndex fixup** — commissioners may omit `fabricIndex` in ACL writes. On commit, staged ACLs are rebuilt with the real `fabricIndex` so fabric-scoped attribute filtering works correctly.

5. **Persistence** — `pbkdfSalt` and `pbkdfIterations` are included in `StoredDeviceState` (via `StoredTypes.swift`) for cross-restart persistence.

### `Sources/MatterDevice/Server/MatterDeviceServer.swift` (+590/-?)

**What changed:** Major rewrite of the commissioning flow and CASE session handling. Primary changes:

1. **PBKDF salt persistence** — `start()` now calls `loadFromStore()` first and uses the persisted salt if present, only generating a new random salt on first run. The salt + iterations are saved immediately after generation.

2. **Random `unsecuredCounter`** — changed from `0` to `UInt32.random(in: 0...UInt32.max)`. Per Matter spec §4.10.2.3, the initial value must be a fresh random value to avoid the controller's replay-protection window rejecting messages from a previous run.

3. **`stagedOperationalInstanceName`** and **`paseCommissioningInterface`** — new actor state:
   - `paseCommissioningInterface`: captured from Pake3 sender's interface name (e.g., `"en0"`), used to restrict operational AAAA records to the commissioning interface
   - `stagedOperationalInstanceName`: the operational instance name advertised after AddNOC; used by `revokeStagedNOCAdvertisement()` to withdraw it if fail-safe expires

4. **`onNOCStaged` / `onNOCReverted` hooks** — wired up in `start()` to `advertiseStagedNOC()` and `revokeStagedNOCAdvertisement()`.

5. **`advertiseStagedNOC()`** — parses staged RCAC and NOC to extract the compressed fabric ID and node ID, constructs the operational instance name (`<nodeID>-<cfid>._matter._tcp`), advertises it via `discovery`, and stores the name in `stagedOperationalInstanceName`.

6. **`revokeStagedNOCAdvertisement()`** — calls `discovery.stopAdvertising(name: stagedOperationalInstanceName)` and clears the field.

7. **Duplicate PBKDF request detection** — `handlePBKDFParamRequest` checks `paseHandshakes[exchangeID]` for an existing handshake and resends the stored response if found, rather than generating new random data. Avoids SPAKE2+ desync from duplicate Sigma1 on different interfaces.

8. **PBKDFParamResponse with session params** — `PBKDFParamResponse.tlvEncode(includePBKDFParams:)` now always includes tag 5 (MRP idle/active retrans timeouts). Apple Home appears to require this field.

9. **`hasPBKDFParameters` handling** — when the request has `hasPBKDFParameters = true`, the response is encoded without tag 4. Mistakenly including tag 4 causes the initiator to reject the response and retransmit indefinitely.

10. **Request TLV for SPAKE2+ transcript** — `handlePBKDFParamRequest` stores `data` (raw received bytes) rather than `request.tlvEncode()`. Re-encoding would drop optional fields the initiator included, producing a hash mismatch in the Pake3 verifier.

11. **Sigma1 retransmit** — if `caseHandshakes[exchangeID]` already exists, re-sends the stored `sigma2Payload` without reprocessing. Generating a new Sigma2 with fresh ephemeral keys would invalidate Sigma3.

12. **StatusReport logging** — unsecured `statusReport` opcode is now parsed and logged at warning level. Previously fell through to "ignoring unsecured opcode" debug log.

13. **Graceful decrypt failure** — `handleSecuredMessage` errors are caught and logged at debug level. Stale retransmits (wrong session keys from a previous run) silently drop.

14. **Interface restriction** — `paseCommissioningInterface` is passed as `preferredInterface` when advertising operational mDNS. This prevents the commissioner from receiving a link-local IPv6 address for a different interface (e.g., Ethernet) that is unreachable from its Wi-Fi segment.

### `Sources/MatterApple/AppleDiscovery.swift` (+577/-?)

**What changed:** Major rewrite of the mDNS registration logic to handle interface restriction, multi-interface AAAA records, and link-local IPv6.

**Key changes:**

1. **Interface restriction** — both commissionable and operational records are restricted to the primary LAN interface (lowest-indexed `en*` with IPv4). Previously `interfaceIndex=0` (all interfaces) caused conflict when the same hostname was registered twice, causing Bonjour to evict the record.

2. **`primaryLANInterface()` / `primaryLANInterfaceIndex()`** — helper methods that enumerate network interfaces via `getifaddrs` and return the first `en*` interface that is UP, RUNNING, non-loopback, non-point-to-point with an assigned IPv4 address. VPN tunnels (`utun*`), bridges (`bridge*`), and virtual interfaces are excluded.

3. **`registerAddressRecord(hostname:ifIndex:)`** — registers a link-local AAAA record for the custom hostname on a specific interface. Required because `DNSServiceRegister` with `interfaceIndex != 0` does NOT automatically answer AAAA queries for the default hostname on that interface. CHIP's address resolution prefers IPv6, so an explicit AAAA record is needed.

4. **`allActiveLANInterfaces()`** — enumerates all active `en*` interfaces with link-local IPv6 addresses (fe80::/10). Used to register AAAA on every interface so a query arriving on any interface is answered locally.

5. **`lookupIfIndex(forName:)`** — returns the `if_nametoindex()` result for a named interface.

6. **Custom hostname for SRV target** — operational records use a stable custom hostname (based on compressed fabric ID) rather than the system default `hostname.local`. This prevents conflicts when re-commissioning.

### `Sources/MatterApple/AppleUDPTransport.swift` (+474/-?)

**What changed:** Major rewrite for IPv4+IPv6 dual-stack, interface binding, and connection lifecycle.

### `Sources/MatterCrypto/DeviceAttestationCredentials.swift` (+331/-?)

**What changed:** Added Matter-correct VID/PID OIDs to PAI and DAC Subject DNs, fixed `buildTestCertificationDeclaration` to produce CMS-wrapped output.

**Key changes:**

1. **VID/PID OIDs in Subject DNs** — per Matter spec §6.3.5.3–4:
   - PAI Subject: `commonName`, `matterVendorId` (OID `1.3.6.1.4.1.37244.2.1`) as 4-char uppercase hex
   - DAC Subject: `commonName`, `matterVendorId`, `matterProductId` (OID `1.3.6.1.4.1.37244.2.2`)
   - Issuer DN in DAC must exactly match PAI Subject DN (including the VID OID)

2. **`pathLenConstraint`** — PAI gets `pathLenConstraint=0` in BasicConstraints (can sign DACs, not intermediate CAs).

3. **CMS-wrapped Certification Declaration** — `buildTestCertificationDeclaration` now returns a proper CMS `SignedData` structure rather than raw TLV.

### `Sources/MatterProtocol/PASE/PASEMessages.swift` (+58/-?)

**What changed:** `PBKDFParamResponse.tlvEncode()` gains `includePBKDFParams: Bool` parameter and always includes tag 5 (MRP session params).

- `includePBKDFParams: false` omits tag 4 (pbkdf_parameters). Required when `hasPBKDFParameters = true` in the request per Matter spec §5.3.2.1.
- Tag 5 (`responderSessionParams`) is always included — Apple Home appears to silently discard responses without it. Contains idle retrans timeout (default 4000ms) and active retrans timeout (default 300ms).

### `Sources/MatterDevice/Server/CommissioningState.swift` + `Sources/MatterTypes/Storage/StoredTypes.swift`

**`StoredDeviceState`** extended to include `pbkdfSalt: Data?` and `pbkdfIterations: Int?` for cross-restart PBKDF persistence.

### `Sources/MatterModel/Clusters/AccessControl.swift` (+8/-?)

**What changed:** `AccessControlEntry` now includes `fabricIndex: FabricIndex?` field so the fixup in `CommissioningState.commitFabric()` can copy the index through.

### `Sources/MatterModel/Clusters/GeneralCommissioning.swift` (+13/-?)

Minor: added typed constants or helper for GeneralCommissioning error codes (used in commissioning complete / fail-safe handling).

### `Sources/MatterDevice/Clusters/GeneralCommissioningHandler.swift` (+56/-?)

**What changed:** Improved fail-safe handling and error reporting. Stores `ArmFailSafe` expiry time and calls `disarmFailSafe()` correctly.

### `Sources/MatterDevice/Clusters/OperationalCredentialsHandler.swift` (+42/-?)

**What changed:** `AddNOC` handler now:
- Extracts `IPKValue` from the request and stores it in `CommissioningState`
- Calls `onNOCStaged` callback after staging the NOC
- Stores raw NOC and ICAC bytes for CASE

### `Sources/MatterDevice/Clusters/GroupKeyManagementHandler.swift` (+17)

Added `KeySetWrite` command handler — required by Apple Home during commissioning to write the operational group key set.

### `Sources/MatterDevice/Endpoint/ClusterHandler.swift` (+17)

Minor additions to cluster handler infrastructure.

### `Sources/MatterDevice/InteractionModelHandler.swift` (+31/-?)

Improvements to attribute read/write routing and error handling.

### `Sources/MatterTransport/Discovery.swift` (+14/-?)

Minor: added `preferredInterface: String?` parameter to `advertise()` so callers can request interface-scoped registration.

### `Sources/MatterController/CommissioningController.swift` (+14/-?)

Minor: updated to new API signatures.

### `Sources/MatterController/FabricManager.swift` (+6/-?)

Minor: updated to new `FabricInfo` init signature.

### `Sources/MatterDevice/Bridge/MatterBridge.swift` (+30/-?)

Minor: API adjustments. **Note:** Phase 0 of the AcumenMatterBridge plan (callback-accepting `add*()` overloads) is not yet implemented — see plan in the Acumen project's CLAUDE.md.

### Test files

- **`Tests/MatterCryptoTests/CertificateTests.swift`** (+126) — new test suite for cert encoding, TBS extraction, and signature verification
- **`Tests/MatterCryptoTests/CASEMessageTests.swift`** (+88) — tests for CASE key derivation and message encoding
- **`Tests/MatterDeviceTests/CommissioningHandlerTests.swift`** (+60) — tests for commissioning flow handlers
- **`Tests/MatterDeviceTests/DeviceAttestationTests.swift`** (+36) — tests for DAC/PAI generation
- **`Tests/MatterAppleTests/AppleUDPTransportTests.swift`** (+8) — transport tests
- **`Tests/IntegrationTests/LoopbackTests.swift`** (+11) — loopback integration tests

---

## Critical Known Bug: Certificate TBS Must Be X.509 DER

**FIXED.** `tbsData()` now produces X.509 DER `TBSCertificate` bytes that match chip-cert output byte-for-byte. Certificate signatures use IEEE P1363 format (`rawRepresentation`). All diagnostic prints removed.

### Implementation Details

- `MatterCertificate.tbsData()` builds DER using `PKCS10CSRBuilder` helpers
- `MatterDistinguishedName.toX509Name()` maps Matter DN attributes to OIDs under `1.3.6.1.4.1.37244.1.*` with 16-char hex UTF8String values
- `CertificateExtension.toX509Extension()` encodes each extension with correct X.509 criticality flags
- Time encoding: UTCTime (tag 0x17) for 2000-2049, GeneralizedTime (tag 0x18) for the 9999 no-expiry sentinel
- Serial numbers encoded without positive-integer 0x00 prefix (matches CHIP SDK behavior)
- `generateRCAC()`/`generateNOC()` default to current time → 10 years validity

### Reference Test Verification

The `ReferenceTests` target validates against the connectedhomeip SDK's `chip-cert` tool:
- `make ref-setup-cert` — builds chip-cert from source
- `make ref-test` — runs crypto vector + chip-cert conformance tests
- Tests verify: TLV→DER conversion, DER TBS byte-for-byte match, NOC chain validation

---

## Testing Without Apple Home: matter.js

**matter.js** (https://github.com/project-chip/matter.js) is a complete TypeScript Matter stack. Use it as a commissioner during development to avoid the Xcode-rebuild → open Apple Home → tap "Add Accessory" cycle.

### Setup

```bash
git clone https://github.com/project-chip/matter.js
cd matter.js
npm install
npm run build
```

### Commission the swift-matter bridge

Once the bridge is running and displaying its QR code / pairing code, commission it using the matter.js `ControllerNode` example:

```bash
# From the matter.js repo root, after build:
node packages/examples/dist/esm/ControllerNode.js  # as a commissioner
```

The `ControllerNode` example accepts a pairing code and commissions a device. Run it against your swift-matter bridge's pairing code. This replaces Apple Home for iteration — no app switching, no 30-second timeout, console output for all protocol messages.

### Standalone certificate validation

To check whether a Matter TLV cert's signature is valid without running a full commission flow, write a small script:

```js
import { MatterCertificateDecoder } from "@project-chip/matter.js/certificate";
import { Bytes } from "@project-chip/matter.js/util";

const rcacHex = "1530010...18";  // paste raw hex from diagnostic output
const rcac = Bytes.fromHex(rcacHex);
// matter.js decodes and verifies the RCAC self-signature internally
const cert = MatterCertificateDecoder.decodeCertificate(rcac);
console.log("decoded:", cert);
```

This immediately confirms whether cert bytes are valid per the matter.js implementation — and what it produces from `asUnsignedDer()` can be compared against what `tbsData()` returns.

### Confirming the TBS fix with matter.js

Once `tbsData()` is updated to return DER, validate against matter.js before testing with Apple Home:

```js
// cert-tbs.mjs
import { MatterCertificateDecoder } from "@project-chip/matter.js/certificate";
import { Bytes, ByteArray } from "@project-chip/matter.js/util";

// Hex-dump from [TBS-DIAG] printed by tbsData() — paste here
const tbsHex = "...";
// Raw NOC hex from [CASE-DIAG] printed by CASESession.responderStep1()
const nocHex = "...";

const noc = Bytes.fromHex(nocHex);
const cert = MatterCertificateDecoder.decodeCertificate(noc);

// matter.js internal DER TBS — compare byte-for-byte with our output
const matterJsTBS = cert.asUnsignedDer();
const ourTBS = Bytes.fromHex(tbsHex);

console.log("matter.js TBS:", Bytes.toHex(matterJsTBS));
console.log("our TBS:      ", Bytes.toHex(ourTBS));
console.log("match:", Bytes.toHex(matterJsTBS) === Bytes.toHex(ourTBS));
```

### chip-cert (alternate cert validation tool)

The connectedhomeip C++ SDK ships `chip-cert`, a standalone certificate validation tool. Build it from the SDK if you want to validate certs without installing matter.js:

```bash
# From connectedhomeip repo root
./scripts/build/build_examples.py --target chip-tool build
```

Then validate:
```bash
chip-cert validate-cert -c <rcac-der-file>
chip-cert validate-cert -c <noc-der-file> -i <rcac-der-file>
```

---

## Reference Materials

- [Matter Specification](https://csa-iot.org/developer-resource/specifications-download-request/) — requires CSA account
- [matter.js source](https://github.com/project-chip/matter.js) — primary architectural reference (TypeScript); `Certificate.ts` and `X509.ts` are the key files for the DER fix
- [rs-matter source](https://github.com/project-chip/rs-matter) — Rust reference implementation
- [connectedhomeip data_model XML](https://github.com/project-chip/connectedhomeip/tree/master/data_model) — cluster definitions for code generation
- [connectedhomeip bridge-app](https://github.com/project-chip/connectedhomeip/tree/master/examples/bridge-app) — bridge pattern reference
- [Matter TLV specification](https://project-chip.github.io/connectedhomeip-doc/) — TLV encoding details

---

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

---

## Common Pitfalls

- **AES-128-CCM is not AES-GCM**: Matter uses CCM (Counter with CBC-MAC), not GCM. CryptoKit does not expose CCM directly — use `_CryptoExtras` or build from AES block cipher primitives.

- **TLV signed integers**: Matter TLV uses signed integers in 1/2/4/8 byte widths. The encoder must choose the smallest width that fits the value. Decoders must accept any width.

- **TLV tag encoding**: Context tags use 1 byte. Common profile tags use 2 bytes. Fully qualified tags use 6 bytes. Most protocol messages use context tags exclusively.

- **Matter certificates are TLV *re-encodings* of X.509 certs**: The wire format is compact TLV, but the certificate *signature* was computed over the X.509 ASN.1 DER `TBSCertificate` bytes — not over any form of TLV. `MatterCertificate.tbsData()` handles this conversion. Key implementation details: serial numbers are encoded without a positive-integer 0x00 prefix (matching CHIP SDK), times use UTCTime for 2000-2049 and GeneralizedTime for the 9999 no-expiry sentinel, and ExtendedKeyUsage is marked critical.

- **Certificate signature format is IEEE P1363, not DER**: Matter spec §6.6.1 mandates 64-byte raw r‖s format for ECDSA signatures stored in TLV cert field 11. The old code used DER representation (`derRepresentation`) — it must be `rawRepresentation`.

- **TBE payload signatures in Sigma2/Sigma3 are also P1363**: Both `Sigma2Decrypted.signature` and `Sigma3Decrypted.signature` are IEEE P1363 (64 bytes). Not DER, not any ASN.1 encoding.

- **CASE key derivation uses transcript hashes, not static salts**: S2K, S3K, and session keys each use a different transcript hash (SHA-256 over the Sigma messages sent so far). Old code used a shared 48-byte HKDF output with a static salt. Verified against Matter Core Spec §5.5.2 and the CHIP SDK `CASESession.cpp` (`ConstructSaltSigma2`, `ConstructSaltSigma3`, `ConstructSaltSessionKeys`).

- **S2K salt uses only responderRandom, not initiatorRandom**: The S2K salt is `IPK ‖ σ2.Responder_Random ‖ σ2.Responder_EPH_PubKey ‖ SHA256(σ1)`. The initiator random is NOT included in the S2K salt even though Sigma1 includes an `initiatorRandom` field.

- **Compressed Fabric ID uses HKDF, not HMAC, over the full 64-byte key**: Common mistake to use only the X coordinate as HKDF IKM. The spec uses the full uncompressed public key with the 0x04 prefix stripped (64 bytes: X‖Y). Info string is `"CompressedFabric"`.

- **IPK info string is "GroupKey v1.0", not "GroupKeyHash"**: The HKDF info string for IPK derivation is `"GroupKey v1.0"` (with the space and version suffix). Using `"GroupKeyHash"` produces a different IPK and causes all CASE destination ID matching to fail.

- **PBKDF salt must be stable across restarts**: Apple Home caches PBKDF parameters (salt + iterations) after a successful PASE. On a subsequent commissioning attempt it sends `hasPBKDFParameters = true` and uses its cached parameters. If the device regenerates a new random salt on restart, the verifier is computed with a different salt and SPAKE2+ fails.

- **`hasPBKDFParameters = true` means omit tag 4 in response**: Per Matter spec §5.3.2.1, when the request has `hasPBKDFParameters = true`, the `PBKDFParamResponse` MUST omit tag 4 (pbkdf_parameters). Apple Home silently retransmits indefinitely if tag 4 is included.

- **PBKDFParamResponse tag 5 (MRP session params) is required by Apple Home**: The CHIP SDK always includes tag 5 with idle/active retransmission timeouts. Apple Home appears to discard responses without it. Always include tag 5 with idle=4000ms, active=300ms.

- **Use raw received bytes for SPAKE2+ transcript, not re-encoded bytes**: The SPAKE2+ key schedule (TT hash) covers the raw `PBKDFParamRequest` and `PBKDFParamResponse` bytes as received/sent. Re-encoding drops optional fields, produces a different byte sequence, and the Pake3 MAC verification fails.

- **Sigma1 retransmit must re-send stored Sigma2, not regenerate**: If the device generates a new Sigma2 with fresh ephemeral keys on a Sigma1 retransmit, any Sigma3 the commissioner already has in flight (based on the original Sigma2) will fail to decrypt.

- **Unsecured message counter must start random**: The `unsecuredCounter` must be initialised to a fresh `UInt32.random` per Matter spec §4.10.2.3. Starting at 0 causes the controller's per-peer replay-protection window to reject messages after a restart.

- **Operational mDNS must be advertised after AddNOC, before CommissioningComplete**: Apple Home waits for the operational advertisement before sending CommissioningComplete. If the device only advertises after CommissioningComplete, the commissioning times out. Wire up `CommissioningState.onNOCStaged` to start advertising immediately.

- **AAAA records for link-local IPv6 require interface-specific registration**: `DNSServiceRegister` with `interfaceIndex != 0` does NOT automatically answer AAAA queries on that interface. You must explicitly register an address record (`DNSServiceRegisterRecord` type `kDNSServiceType_AAAA`) on the specific interface so that `homed` can perform address resolution.

- **Dual-homed hosts need interface restriction**: On a Mac with both Wi-Fi (en0) and Ethernet (en1), registering mDNS records on all interfaces sends the iPhone a link-local address for the wrong interface. Capture `paseCommissioningInterface` from the Pake3 sender address and restrict the operational advertisement to that interface.

- **ACL fabricIndex must be stamped on commit**: Commissioners may write ACL entries without a `fabricIndex` field (Matter spec allows this). On `commitFabric`, rebuild staged ACLs with the real `fabricIndex` so fabric-scoped reads work correctly post-commissioning.

- **`compressedFabricID()` mismatch breaks CASE destination ID**: The CFID is embedded in the operational mDNS instance name and used in the CASE `destinationId` computation. If the device computes a different CFID than Apple Home expects, Sigma1 will fail to match any fabric.

- **Message counters are per-session**: Each session maintains its own monotonic message counter. Counters must never wrap within a session.

- **MRP idle vs active intervals**: Devices in idle mode use longer retransmission intervals (typically 500ms) than active mode (typically 300ms). The intervals are negotiated during session establishment.

- **SPAKE2+ uses W0 and W1**: The verifier computation from passcode requires PBKDF2 with a specific salt and iteration count. W0 is used in the protocol exchange, W1 is the verifier stored on the device.

- **Setup passcode restrictions**: Certain passcodes are invalid (00000000, 11111111, ..., 99999999, 12345678, 87654321). The spec lists exactly which ones.

- **Discriminator is 12 bits**: Values 0-4095. Used to distinguish between multiple commissionable devices. The long discriminator (12 bits) is in the QR code; a short discriminator (4 bits, top 4 of long) is in mDNS/BLE advertisements.

- **Subscription max interval floor**: The Matter spec mandates a minimum max-interval of 60 seconds for subscriptions. Controllers may request shorter, but devices should enforce this floor.

- **Fabric-scoped data**: Many attributes (ACLs, bindings, group keys) are fabric-scoped — they have different values per fabric. The Interaction Model includes fabric filtering for reads/subscribes.

- **Timed writes/invokes**: Security-sensitive operations (door locks, garage doors) require a timed flow where the client first requests a timeout window, then sends the actual write/invoke within that window.

- **Bridge PartsList updates**: When dynamic endpoints are added/removed, the aggregator's Descriptor.PartsList attribute must be updated and subscription reports must be sent to all subscribers.

- **CASE nonce uses session node IDs, not message header**: For encrypted CASE messages, the AES-CCM nonce includes the sender's node ID. But this node ID is NOT taken from the message header — for secured unicast, the source node ID field is absent from the wire format. Instead: encryption uses `session.localNodeID`, decryption uses `session.peerNodeID`. For PASE sessions, use 0 (kUndefinedNodeId). The CHIP SDK implements this in `SessionManager.cpp` lines ~297 (encrypt) and ~998 (decrypt).

- **Secured unicast messages omit source node ID from wire header**: Unlike unsecured messages (PASE, Sigma), encrypted CASE messages do NOT include the source node ID in the message header. The CHIP SDK calls `SetSourceNodeId` only for group and unauthenticated sessions, not for CASE unicast. Both sides use the session's stored node IDs for nonce construction.

- **Pake1 retransmit must resend stored Pake2, not regenerate**: Same pattern as PBKDFParamRequest and Sigma1 retransmit handling. If the server regenerates a new Pake2 with fresh SPAKE2+ random values on a Pake1 retransmit, any in-flight Pake3 (computed against the original Pake2) will fail `verifierStep2`. Store the Pake2 TLV payload in the handshake state and resend it.

- **AddNOC must create an admin ACL from caseAdminSubject**: Per Matter spec §11.17.6.8, the device SHALL create an initial ACL entry granting Administer privilege to the `CaseAdminSubject` field from AddNOC. Without this, the CASE session carrying CommissioningComplete is denied access (the ACLs written during PASE are only committed by CommissioningComplete itself — chicken-and-egg).

- **Staged ACLs must be available during fail-safe for CASE**: During commissioning, the CASE CommissioningComplete arrives before ACLs are committed. The server must use staged ACLs for ACL checks when the fail-safe is armed and committed ACLs are empty. This matches the CHIP SDK's behavior of allowing the commissioning node access before CommissioningComplete.

- **Verhoeff checksum inverse table for D5**: The dihedral group D5 inverse for the Verhoeff algorithm is `[0,4,3,2,1,5,6,7,8,9]` — only values 1-4 are inverted (5 - val), while 0 and 5-9 map to themselves. A common mistake is to invert 5-9 as well (`[0,4,3,2,1,9,8,7,6,5]`), which produces valid-looking but incorrect checksums.

- **Empty event request paths should not return all events**: `EventStore.query(paths: [])` must return an empty array, not all events. When a ReadRequest contains only attribute paths with no event paths, the device must not include unrequested events in the ReportData. Including them causes chip-tool's TLV parser to fail with "End of TLV" when trying to decode event data.

- **Attestation credentials must be generated on server startup**: `MatterDeviceServer.start()` must generate test DAC credentials (PAA→PAI→DAC chain) if `attestationCredentials` is nil. Without these, CertificateChainRequest and AttestationRequest handlers return empty responses that block commissioning at the attestation stage.

- **AttributeDataIB container type: spec says LIST, matter.js uses STRUCTURE — use STRUCTURE**: The Matter spec §10.6.4 defines AttributeDataIB as LIST (0x17), and the CHIP SDK uses LIST. However, matter.js (a complete, Apple Home-certified Matter implementation) uses STRUCTURE (0x15) for AttributeDataIB, AttributeStatusIB, EventDataIB, and EventStatusIB — and Apple Home works with STRUCTURE. Switching to LIST caused Apple Home to abort commissioning during ReadCommissioningInfo (sends ArmFailSafe(0) cleanup without proceeding). Keep STRUCTURE. The `fromTLVElement()` decoders accept both LIST and STRUCTURE for interop with CHIP SDK peers. Note: chip-tool's `ListParser::Init` rejects STRUCTURE with `CHIP_ERROR_WRONG_TLV_TYPE`, causing misleading "Key not found" in `ClusterStateCache` — this is a chip-tool interop issue, not a spec compliance blocker for Apple Home.
