# MatterSwift Status

Current implementation status against the Matter specification.

## Specification Version

- **Matter spec:** 1.4
- **Cluster definitions source:** [connectedhomeip](https://github.com/project-chip/connectedhomeip) v1.4.0.0 XML data model
- **Code-generated clusters:** 110 cluster definitions, 72 device types

## Test Coverage

- **127 test suites**, **861 individual tests** across 10 test targets
- Uses Swift Testing framework (`@Suite`, `@Test`)
- Reference tests validate against the CHIP SDK's `chip-cert` and `chip-tool` binaries
- Integration tests run end-to-end commissioning (PASE → CASE → attribute read/write)

| Test Target | Suites | Focus |
|-------------|--------|-------|
| MatterTypesTests | TLV | TLV encoding/decoding, tag formats |
| MatterModelTests | 2 | TLV codability, device type registry |
| MatterCryptoTests | 5 | CASE, SPAKE2+, certificates, CSR, resumption |
| MatterProtocolTests | 6 | MRP, sessions, Interaction Model, report chunking |
| MatterDeviceTests | 38 | Cluster handlers, subscriptions, commissioning, ACLs, events |
| MatterControllerTests | 9 | Commissioning flow, sessions, fabric management |
| MatterAppleTests | 2 | Apple transport, discovery |
| MatterLinuxTests | 1 | Linux transport |
| IntegrationTests | 5 | Loopback, chip-tool end-to-end |
| ReferenceTests | 3 | chip-cert conformance, crypto vectors |

## Working Features

### Session Establishment and Commissioning
- [x] PASE (SPAKE2+ password-authenticated key exchange)
- [x] CASE (Certificate Authenticated Session Establishment) with Sigma1/2/3
- [x] Full commissioning flow: ArmFailSafe → CSR → AddNOC → CASE → CommissioningComplete
- [x] Device attestation credentials (test DAC/PAI/PAA chain, CMS-wrapped Certification Declaration)
- [x] Enhanced commissioning windows (AdminCommissioning, PAKE verifier injection)
- [x] Multi-admin support (multiple fabrics per device)
- [x] Session resumption infrastructure (ResumptionTicket, Sigma2Resume)
- [x] PBKDF salt persistence across restarts
- [x] Matter Operational Certificates (TLV ↔ X.509 DER conversion, chain validation)

### Interaction Model
- [x] Read requests (single and wildcard endpoint/cluster/attribute)
- [x] Write requests (single and chunked)
- [x] Subscribe requests with priming reports
- [x] Invoke (command execution, single and chunked)
- [x] Timed writes and timed invokes for security-sensitive operations
- [x] Report chunking (respects ~1280 byte UDP MTU)
- [x] Data version filtering (skip unchanged clusters in reports)
- [x] Subscription management (min/max intervals, dirty tracking, urgent events)
- [x] Fabric-scoped attribute filtering

### Security and Access Control
- [x] AES-128-CCM message encryption/decryption
- [x] HKDF / PBKDF2 / HMAC-SHA256 key derivation
- [x] ACL enforcement on all IM operations
- [x] Fabric-scoped data isolation
- [x] Timed request enforcement for security-sensitive clusters

### Events and Groups
- [x] Event system (EventStore ring buffer, priority levels, event numbers)
- [x] Event reporting in subscriptions (with catch-up via eventMin filter)
- [x] Urgent events (bypass minInterval)
- [x] Group Key Management cluster (KeySetWrite/Read, key derivation)
- [x] Groups cluster (AddGroup, RemoveGroup, GetGroupMembership)
- [x] Group communication routing (fan-out to member endpoints, response suppression)

### Transport and Discovery
- [x] UDP transport (Apple Network.framework, Linux SwiftNIO)
- [x] mDNS/DNS-SD for commissionable and operational advertisement
- [x] MRP (Message Reliability Protocol) with retransmission and deduplication
- [x] Interface-restricted mDNS for dual-homed hosts
- [x] Link-local IPv6 AAAA record registration

### Code Generation
- [x] 110 cluster definitions auto-generated from Matter spec XML
- [x] 72 device types with required/optional cluster mappings
- [x] CI-enforced generated code freshness

## Implemented Cluster Handlers

28 hand-written cluster handlers with full attribute read/write and command processing:

| Cluster | ID | Key Features |
|---------|-----|-------------|
| Access Control | 0x001F | ACL entries, fabric-scoped filtering |
| Admin Commissioning | 0x003C | Open/close commissioning windows, PAKE verifier injection |
| Basic Information | 0x0028 | Device identity, StartUp/ShutDown/Leave events |
| Binding | 0x001E | Target binding list, fabric-scoped write |
| Boolean State | 0x0045 | Contact/binary state (contact sensors) |
| Bridged Device Basic Info | 0x0039 | Bridged device identity and reachability |
| Color Control | 0x0300 | Hue/saturation, color temperature (mireds), XY color |
| Descriptor | 0x001D | Server/client lists, PartsList, dynamic updates |
| Door Lock | 0x0101 | Lock/unlock commands, timed invoke required |
| Fan Control | 0x0202 | Fan mode, speed percent, wind support |
| Fixed Label | 0x0040 | Read-only label pairs (room, zone metadata) |
| General Commissioning | 0x0030 | ArmFailSafe, SetRegulatoryConfig, CommissioningComplete |
| General Diagnostics | 0x0033 | Network interfaces, uptime, reboot count, BootReason event |
| Group Key Management | 0x003F | Key set storage, group key derivation, fabric-scoped filtering |
| Groups | 0x0004 | AddGroup, RemoveGroup, GetGroupMembership, AddGroupIfIdentifying |
| Identify | 0x0003 | Identify command, identify query |
| Illuminance Measurement | 0x0400 | Measured value, min/max |
| Level Control | 0x0008 | MoveToLevel, current level, min/max |
| Network Commissioning | 0x0031 | Ethernet feature, interface status |
| Occupancy Sensing | 0x0406 | Occupancy state, sensor type |
| On/Off | 0x0006 | On, Off, Toggle commands, StateChange events |
| Operational Credentials | 0x003E | AddNOC, CSRRequest, AttestationRequest, CertificateChain |
| Relative Humidity | 0x0405 | Measured value, min/max |
| Temperature Measurement | 0x0402 | Measured value, min/max |
| Thermostat | 0x0201 | Setpoints, system mode, running state |
| Time Synchronization | 0x0038 | UTCTime, granularity, SetUTCTime command |
| Window Covering | 0x0102 | Position, lift/tilt percent |

## Bridge Device Types

15 convenience methods for adding bridged devices:

| Method | Device Type | ID |
|--------|------------|-----|
| `addOnOffLight` | On/Off Light | 0x0100 |
| `addDimmableLight` | Dimmable Light | 0x0101 |
| `addColorTemperatureLight` | Color Temperature Light | 0x0102 |
| `addExtendedColorLight` | Extended Color Light | 0x010D |
| `addOnOffPlugInUnit` | On/Off Plug-in Unit | 0x010A |
| `addThermostat` | Thermostat | 0x0301 |
| `addDoorLock` | Door Lock | 0x000A |
| `addWindowCovering` | Window Covering | 0x0202 |
| `addFan` | Fan | 0x002B |
| `addContactSensor` | Contact Sensor | 0x0015 |
| `addOccupancySensor` | Occupancy Sensor | 0x0107 |
| `addTemperatureSensor` | Temperature Sensor | 0x0302 |
| `addHumiditySensor` | Humidity Sensor | 0x0307 |
| `addLightSensor` | Light Sensor | 0x0106 |
| `addGenericEndpoint` | Any device type | Custom |

## Not Yet Implemented

### Clusters
- [ ] OTA Software Update Provider / Requestor
- [ ] ICD Management (battery-powered devices)
- [ ] Scenes Management
- [ ] Software Diagnostics
- [ ] Wi-Fi / Thread / Ethernet Network Diagnostics
- [ ] Power Source
- [ ] Mode clusters (Laundry Washer, Dishwasher, Refrigerator, etc.)
- [ ] Energy Management clusters (EVSE, Device Energy Management)
- [ ] Media clusters (Media Playback, Content Launcher, etc.)

### Transport
- [ ] BLE commissioning transport (BTP framing, CoreBluetooth)
- [ ] Thread border router integration

### Commissioning
- [ ] Wi-Fi network scanning (ScanNetworks command)
- [ ] Thread network provisioning
- [ ] User Directed Commissioning (UDC)

### Protocol
- [ ] Full group key encryption for multicast
- [ ] CASE resumption MIC verification (infrastructure complete, AES-CCM MIC pending)
- [ ] BDX (Bulk Data Exchange) for OTA

## Platform Support

| Platform | Transport | Status |
|----------|-----------|--------|
| macOS 15+ | Network.framework + mDNS | Full support, tested with Apple Home and chip-tool |
| iOS 18+ | Network.framework + mDNS | Builds, limited testing |
| Linux (Ubuntu 24.04) | SwiftNIO + pure-Swift mDNS | Full support, CI tested |
| tvOS 18+ | Network.framework | Builds, untested |
| watchOS 11+ | — | Builds, no networking |
| visionOS 2+ | Network.framework | Builds, untested |
