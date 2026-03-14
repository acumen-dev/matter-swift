# Matter Compliance TODO

Tracks gaps between the current implementation and the Matter specification.
Updated after each phase — completed items move to the bottom.

**Current state:** 737 tests across 110 suites. 28 cluster handlers (added Groups cluster),
full PASE/CASE with session resumption infrastructure
(ResumptionTicket, ResumptionTicketStore, CASEResumption key derivation, Sigma2ResumeMessage,
CASESession resumption methods), Identify, Binding, FixedLabel,
full PASE/CASE, end-to-end commissioning, subscriptions, ACL enforcement, wildcard reads, multi-admin
commissioning windows, fabric management, fabric-scoped attribute filtering, timed request enforcement,
event system (EventStore ring buffer, EventDataIB/EventReportIB, event generation in cluster handlers,
urgent event subscriptions), GroupKeyManagement cluster (key sets, fabric-scoped filtering, group key derivation),
Groups cluster (AddGroup/ViewGroup/GetGroupMembership/RemoveGroup/RemoveAllGroups/AddGroupIfIdentifying,
integrated with GroupMembershipTable, registered on all bridged endpoints),
group communication routing (group-addressed message detection in MatterDeviceServer, fan-out to member endpoints,
response suppression per spec §4.16.2),
report chunking (ReportDataChunker, ChunkedWriteBuffer, IMHandleResult),
data version filtering (DataVersionFilter, ReadRequest/SubscribeRequest parsing, EndpointManager filtering),
proper PKCS#10 CSR generation (PKCS10CSRBuilder, real RFC 2986 DER encoding, OID encoding),
device attestation (DeviceAttestationCredentials, DAC/PAI X.509 DER certificates, CD TLV,
AttestationRequest/CertificateChainRequest handlers, attestation challenge from PASE session),
enhanced commissioning window (PAKE verifier injection, InjectedPAKEVerifier, openEnhancedWindow),
descriptor cluster dynamic updates (serverList auto-populated from registered handlers, PartsList auto-updated,
clientList documented as spec-compliant empty for server-only bridge),
group membership table (GroupMembershipTable, per-fabric endpoint-to-group mapping),
BasicInformation extended attributes (manufacturingDate, partNumber, productURL, productLabel) and events
(StartUp, ShutDown, Leave), GeneralCommissioning location capability validation and CommissioningComplete event,
SoftwareVersionString format "X.Y.Z" (default "1.0.0" in BasicInformationHandler).

---

## Critical — Required for Spec Compliance

### Fabric-Scoped Attribute Filtering
- [x] Track which attributes are fabric-scoped (ACLs, NOCs, fabrics list)
- [x] Filter fabric-scoped attributes in read responses based on session fabric
- [x] Filter fabric-scoped attributes in subscription reports
- [x] Ensure AccessControl cluster only returns ACLs for the requesting fabric
- [x] Ensure OperationalCredentials fabrics list is fabric-filtered
- [x] Pass `isFabricFiltered` flag through to EndpointManager read logic

**Spec ref:** §8.4.4, §8.5.3 — fabric-sensitive data elements
**Status:** Complete. `ClusterHandler` protocol extended with `isFabricScoped` and `filterFabricScopedAttribute`.
`AccessControlHandler` and `OperationalCredentialsHandler` override both methods.
`EndpointManager.readAttributes` accepts `fabricIndex` and applies filtering.
`SubscriptionManager` stores `isFabricFiltered` per subscription; `MatterBridge.buildReport` retrieves it.

### Timed Request Enforcement
- [x] Track outstanding timed requests per exchange with timeout
- [x] Reject writes/invokes that require timed interaction but arrive without one
- [x] Enforce timeout window — reject if timed window expired
- [x] Mark security-sensitive commands as requiring timed interaction (DoorLock, AdminCommissioning)
- [x] Return `TimedRequestMismatch` (0xC6) status on violation

**Spec ref:** §8.7 — Timed Interaction
**Status:** Complete. `TimedRequestTracker` actor tracks per-exchange windows. `InteractionModelHandler`
enforces timed windows on write and invoke. `DoorLockHandler` and `AdminCommissioningHandler` mark
their commands as requiring timed interaction. `MatterBridge` owns the tracker; `MatterDeviceServer`
forwards `exchangeID` and purges expired windows in the report loop.

### Event System
- [x] Define `EventReportIB` and `EventDataIB` TLV structures
- [x] Define `EventStatusIB` for event error reporting
- [x] Add event number tracking per node (monotonic counter)
- [x] Add event priority levels (Debug, Info, Critical)
- [x] Wire event generation in cluster handlers (StateChange on OnOff, etc.)
- [x] Support event subscriptions (eventRequests in SubscribeRequest)
- [x] Support event filters (eventMin field for catch-up)
- [x] Include events in subscription reports alongside attributes
- [x] Support urgent event marking (triggers immediate report)

**Spec ref:** §8.5.3.2, §8.9 — Event Reporting
**Status:** Complete. `IMEventMessages.swift` defines all event IB types. `EventStore` actor provides
ring-buffer storage with wildcard queries. `ClusterHandler` protocol extended with `generatedEvents`.
`OnOffHandler` emits StateChange (info), `DoorLockHandler` emits LockOperation (critical, urgent).
`EndpointManager.handleCommand` is now async and wires events to EventStore. `SubscriptionManager`
tracks eventPaths, lastEventNumber, urgentPending. Urgent events bypass minInterval. `MatterBridge`
creates and owns the EventStore. 24 new tests across 2 suites (EventStore, EventSystem).

### Group Key Management Cluster
- [x] Implement GroupKeyManagement cluster handler (0x003F)
- [x] Group key set storage and retrieval
- [x] Key derivation for group messaging (AES-CCM with group key)
- [x] GroupKeyMap attribute (maps GroupID → KeySetID)
- [x] KeySetRead/KeySetWrite commands
- [x] Required on root endpoint per spec

**Spec ref:** §11.2 — Group Key Management Cluster
**Status:** Complete. `GroupKeyManagementCluster` enum in MatterModel defines attributes, commands,
`GroupKeySetStruct`, `GroupKeyMapStruct`, `GroupInfoMapStruct` with TLV encode/decode. `GroupKeySetStorage`
stores key sets keyed by fabric index. `GroupKeyManagementHandler` implements KeySetWrite, KeySetRead
(with epoch key redaction), KeySetRemove, KeySetReadAllIndices, fabric-scoped filtering for groupKeyMap
and groupTable. `KeyDerivation.deriveGroupOperationalKey` added (HKDF-SHA256, Matter §4.16.2.2.1).
`MatterBridge` root endpoint registers the handler. 5 tests in `GroupKeyManagementTests`.

---

## High Priority — Needed for Interoperability

### Report Chunking
- [x] Enforce maximum message size (~1280 bytes for UDP)
- [x] Split large read/subscribe reports across multiple ReportData messages
- [x] Set `moreChunkedMessages` flag on intermediate chunks
- [x] Set `suppressResponse` = false on final chunk only
- [x] Handle chunked write requests (reassemble before processing)
- [x] Handle chunked invoke requests

**Spec ref:** §8.5.3, §8.6.3 — Chunked Messages
**Status:** Complete. `ReportDataChunker` splits reads and subscription reports.
`ChunkedWriteBuffer` reassembles write chunks. `ChunkedInvokeBuffer` reassembles invoke chunks.
`InteractionModelHandler` returns `IMHandleResult` (`.responses` or `.chunkedReport`).
`MatterDeviceServer` sends chunks one at a time on StatusResponse acks.
`InvokeRequest` now has `moreChunkedMessages` field (tag 3). 3 new tests in `ChunkedInvokeBufferTests`.

### Data Version Filtering
- [x] Define `DataVersionFilter` structure (path + dataVersion)
- [x] Parse `dataVersionFilters` from ReadRequest (tag 4)
- [x] Track dataVersion per cluster instance in AttributeStore (already incremented on write)
- [x] Skip unchanged clusters in subscription reports when dataVersion matches
- [x] Include dataVersion in ReportData attribute reports (already in AttributeDataIB)

**Spec ref:** §8.5.1 — Data Version Filtering
**Status:** Complete. `DataVersionFilter` struct in `IMMessages.swift` with TLV encode/decode.
`ReadRequest` and `SubscribeRequest` parse `dataVersionFilters` (tags 4 and 6 respectively).
`EndpointManager.readAttributes` accepts `dataVersionFilters` and skips clusters whose server-side
`dataVersion` matches the client's cached value. `SubscriptionManager.ActiveSubscription` stores
filters per subscription; `MatterBridge.buildReport` passes them to `readAttributes`. 4 new tests
in `DataVersionFilteringTests`.

### Group Communication
- [x] Distinguish group-addressed messages from unicast in message processing
- [x] Group membership table per endpoint
- [x] Route group messages to member endpoints
- [x] Apply group ACL evaluation (AuthMode = Group)
- [x] Support GroupID in message header destination
- [x] Suppress responses for group-cast messages (per spec) — `isGroupMessage` flag on IMRequestContext

**Spec ref:** §4.16 — Group Communication
**Status:** Complete. `MatterDeviceServer.handleDatagram` detects group-addressed messages
(DSIZ=0x02, session type=group) and routes to `handleGroupMessage`. That method looks up member
endpoints via `GroupMembershipTable`, dispatches the IM operation to each, and suppresses responses
(fire-and-forget per spec §4.16.2.1). `ACLChecker.RequestContext` extended with `isGroupMessage`
and `groupID` fields; `check()` evaluates ACEs with `authMode == .group` for group messages.
Full group-key decryption (matching GroupID to key set via GroupKeyMap) is not yet implemented —
currently uses the first CASE session for decryption, which covers the single-fabric bridge case.

### Proper PKCS#10 CSR Generation
- [x] Generate real DER-encoded PKCS#10 CSR in OperationalCredentialsHandler
- [x] Include proper Subject Distinguished Name
- [x] Sign CSR with the operational key (currently signs with op key but minimal DER structure)
- [x] Remove simplified "bridge use" CSR builder

**Spec ref:** §11.17.6.5 — CSRRequest Command
**Status:** Complete. `PKCS10CSRBuilder` in MatterCrypto builds a proper RFC 2986 PKCS#10 CSR using
manual DER encoding. `OperationalCredentialsHandler.handleCSRRequest` now calls
`PKCS10CSRBuilder.buildCSR(privateKey:)` and signs `nocsrElements || attestationChallenge` with the
DAC key (or operational key as fallback for test use). Old `buildSimpleCSR`/`buildDERCSR` stubs removed.

### Device Attestation
- [x] Support AttestationRequest command (0x00) in OperationalCredentialsHandler
- [x] Generate attestation information (Certification Declaration, DAC, PAI)
- [x] Sign attestation elements with DAC key
- [x] Support test/development attestation credentials
- [x] Controller-side: validate attestation during commissioning

**Spec ref:** §11.17.6.1 — AttestationRequest, §6.2 — Device Attestation
**Status:** Complete. `DeviceAttestationCredentials` in MatterCrypto generates test DAC, PAI
(DER-encoded X.509), and a TLV-encoded Certification Declaration. `CommissioningState` holds
`attestationCredentials` and `attestationChallenge`. `MatterDeviceServer` extracts the attestation
challenge from PASE session keys and stores it on `CommissioningState`.
`OperationalCredentialsHandler` handles AttestationRequest (0x00), CertificateChainRequest (0x02),
and builds proper AttestationResponse / CertificateChainResponse TLV structures.
`CommissioningController` now provides `buildCertificateChainRequest`, `buildAttestationRequest`,
`handleCertificateChainResponse`, `validateAttestationResponse`, and `extractPublicKeyFromCertificate`.
`CommissioningContext` stores `attestationChallenge` from PASE session keys. `ControllerError` gains
`attestationValidationFailed`. 2 new tests in `AttestationValidationTests`.

### Enhanced Commissioning Window (PAKE Verifier Injection)
- [x] Implement OpenCommissioningWindow (0x00) command
- [x] Accept PAKE verifier, discriminator, iterations, salt from command
- [x] Store injected verifier in CommissioningState
- [x] Use injected verifier for PASE sessions during enhanced window
- [x] Revert to default verifier when window closes

**Spec ref:** §11.18.8.1 — OpenCommissioningWindow
**Status:** Complete. `AdminCommissioningHandler.handleOpenCommissioningWindow` parses all 5 fields
(timeout, PAKEPasscodeVerifier 97 bytes, discriminator, iterations, salt). `InjectedPAKEVerifier` struct
added to `CommissioningState`. `CommissioningState.openEnhancedWindow` stores the verifier and sets
`enhancedWindowOpen` status. `closeWindow` clears the injected verifier on revoke/expiry. PASE handler
can check `commissioningState.injectedPAKEVerifier` to use the injected W0/L instead of the device's
default passcode-derived verifier. 5 tests in `EnhancedCommissioningWindowTests`.

### Descriptor Cluster — Dynamic Updates
- [x] Auto-update PartsList when endpoints are added/removed from aggregator
- [x] Auto-update ServerClusterList when cluster handlers change
- [x] Populate ClientClusterList (acceptable empty — see comment)

**Spec ref:** §9.5 — Descriptor Cluster
**Status:** Complete. `EndpointManager.addEndpoint` now calls `updateServerClusterList`
after writing initial attributes — the Descriptor `serverList` attribute is set to the sorted list
of all registered handler cluster IDs, overriding any static list from `DescriptorHandler`.
`updateAggregatorPartsList` (existing) is called on add and remove. `ClientClusterList` is
intentionally empty — the Matter spec (§9.5.4.3) defines it as clusters the endpoint uses as a
*client* (initiating reads/writes/invokes to other nodes). This bridge acts purely as a server;
all communication is inbound, so an empty client list is spec-compliant. This is documented in
`DescriptorHandler.swift`. 5 tests in `DescriptorDynamicTests`.

---

## Medium Priority — Important for Completeness

### Session Resumption (CASE Sigma2Resume)
- [x] Generate resumption tickets during CASE establishment
- [x] Store tickets server-side with session context
- [x] Check for valid ticket in Sigma1 processing
- [x] Generate Sigma2Resume (abbreviated response) when ticket valid
- [ ] Verify resumeMIC on initiator side (stub — TODO: implement AES-128-CCM MIC)
- [x] Fall back to full Sigma if ticket invalid/expired

**Spec ref:** §4.13.2.3 — Session Resumption
**Status:** Core infrastructure complete. `ResumptionTicket` struct stores shared secret, peer IDs,
and expiry. `ResumptionTicketStore` actor manages tickets with single-use consumption, LRU eviction,
and expiry purge. `CASEResumption` enum provides `deriveResumeKey` (HKDF-SHA256, "Sigma2_Resume"),
`deriveResumedSessionKeys` (HKDF-SHA256, "SessionResumptionKeys", 48 bytes), and `Sigma2ResumeMessage`
TLV encode/decode. `CASESession` gains `storeResumptionTicket`, `tryResponderResumption`,
`initiatorHandleResume`, and `initiatorStep1WithResumption`. MIC computation stubbed pending
AES-128-CCM API access. 9 tests in `CASEResumptionTests`.

### Network Commissioning Cluster
- [x] Implement NetworkCommissioning cluster handler (0x0031)
- [x] Ethernet/Wi-Fi/Thread feature map
- [ ] ScanNetworks command (for Wi-Fi/Thread)
- [ ] AddOrUpdateWiFiNetwork / AddOrUpdateThreadNetwork
- [ ] ConnectNetwork / RemoveNetwork
- [x] Network status attributes (LastNetworkingStatus, LastNetworkID)
- [x] Required on root endpoint per spec (Ethernet feature at minimum for bridge)

**Spec ref:** §11.8 — Network Commissioning Cluster
**Status:** `NetworkCommissioningCluster` enum in MatterModel with attribute IDs and `NetworkInfoStruct`
(TLV encode/decode). `NetworkCommissioningHandler` exposes a single Ethernet interface with Ethernet
feature flag (0x04). Nullable attributes (lastNetworkingStatus, lastNetworkID, lastConnectErrorValue)
default to null. `interfaceEnabled` attribute is writable. Added to root endpoint in `MatterBridge`.
11 tests in `NetworkCommissioningHandlerTests`.

### General Diagnostics Cluster
- [x] Implement GeneralDiagnostics cluster handler (0x0033)
- [x] NetworkInterfaces attribute (list of active network interfaces)
- [x] RebootCount attribute
- [x] UpTime attribute (seconds since boot)
- [x] ActiveHardwareFaults / ActiveRadioFaults / ActiveNetworkFaults
- [x] TestEventTrigger command (for certification testing)
- [x] BootReason event

**Spec ref:** §11.11 — General Diagnostics Cluster
**Status:** `GeneralDiagnosticsCluster` enum in MatterModel with attribute IDs, `InterfaceType`,
`BootReasonEnum`, `NetworkInterface` (TLV encode), and `TestEventTriggerRequest` (TLV encode/decode).
`GeneralDiagnosticsHandler` exposes all required attributes, handles TestEventTrigger command (guarded
by `testEventTriggersEnabled`), and provides `bootReasonEvent` factory method. Added to root endpoint
in `MatterBridge`. 8 tests in `GeneralDiagnosticsHandlerTests`.

### Identify Cluster
- [x] Implement Identify cluster handler (0x0003)
- [x] IdentifyTime attribute
- [x] Identify command (start identification)
- [x] IdentifyQuery (check if identifying)
- [ ] Required on every endpoint per some device types — not yet auto-added

**Spec ref:** §1.2 — Identify Cluster
**Status:** Complete. `IdentifyCluster` enum in MatterModel. `IdentifyHandler` implements Identify (0x00)
and IdentifyQuery (0x01) commands, identifyTime writable validation, identifyType read-only. 8 tests.

### Binding Cluster
- [x] Implement Binding cluster handler (0x001E)
- [x] Binding attribute (list of target bindings)
- [x] Write support for binding list
- [ ] Used by switches/buttons for direct device-to-device control — integration pending

**Spec ref:** §9.6 — Binding Cluster
**Status:** Complete. `BindingCluster` enum in MatterModel. `BindingHandler` implements fabric-scoped
binding list with write support and fabric filtering by tag 0xFE. 10 tests.

### Fixed Label Cluster
- [x] Implement FixedLabel cluster handler (0x0040)
- [x] LabelList attribute (read-only list of string label pairs)
- [x] Used on bridged endpoints for metadata (room, zone assignments)

**Spec ref:** §9.8 — Fixed Label Cluster
**Status:** Complete. `FixedLabelCluster` enum in MatterModel. `FixedLabelHandler` builds labelList
from init-time label pairs as TLV structures (tag 0 = label, tag 1 = value). Entirely read-only. 7 tests.

### Basic Information — Missing Attributes
- [x] Add ManufacturingDate attribute (optional)
- [x] Add PartNumber attribute (optional)
- [x] Add ProductLabel attribute (optional)
- [x] Add ProductURL attribute (optional)
- [x] Add UniqueID attribute (persistent across factory resets)
- [x] Proper SoftwareVersionString format (spec: "X.Y.Z" or similar)
- [x] StartUp / ShutDown / Leave events

**Spec ref:** §11.1 — Basic Information Cluster
**Status:** Complete. Attributes 0x000B-0x000E added to `BasicInformationCluster.Attribute`. `BasicInformationHandler`
accepts optional init params and includes them when non-empty. `Event` enum added with startUp (0x00),
shutDown (0x01), leave (0x02). Three event factory methods added to `BasicInformationHandler`.
`softwareVersionString` defaults to `"1.0.0"` (X.Y.Z format) per spec.

### General Commissioning — Missing Pieces
- [x] SupportsConcurrentConnection attribute (required)
- [x] LocationCapability enforcement (Indoor/Outdoor/IndoorOutdoor)
- [x] Regulatory location validation before accepting SetRegulatoryConfig
- [x] CommissioningComplete event

**Spec ref:** §11.9 — General Commissioning Cluster
**Status:** Complete. `SetRegulatoryConfig` handler now reads `locationCapability` from store and
validates the requested config is within capability bounds (Indoor-only rejects Outdoor, etc.).
`GeneralCommissioningCluster.Event.commissioningComplete` (0x02) added. `GeneralCommissioningHandler`
overrides `generatedEvents` to emit the event when CommissioningComplete command runs.

### Time Synchronization Cluster
- [x] Implement TimeSynchronization cluster handler (0x0038)
- [x] UTCTime attribute
- [x] Granularity attribute
- [x] TimeSource attribute
- [x] SetUTCTime command
- [x] Optional but commonly expected by controllers

**Spec ref:** §11.16 — Time Synchronization Cluster
**Status:** `TimeSynchronizationCluster` enum in MatterModel with attribute IDs, `Granularity`
(noTime/minutes/seconds/milliseconds/microseconds), `TimeSource` (none/unknown/admin),
`SetUTCTimeRequest` (TLV encode/decode). `TimeSynchronizationHandler` initializes all attributes to
safe defaults (utcTime=null, granularity=noTimeGranularity), handles `SetUTCTime` writing utcTime,
granularity, and optional timeSource to the attribute store. `ClusterID.timeSynchronization` added
to `ClusterDefinitions`. Added to root endpoint in `MatterBridge`. 8 tests in
`TimeSynchronizationHandlerTests`.

---

## Lower Priority — Advanced Features

### OTA Software Update
- [ ] OTA Software Update Provider cluster (server-side)
- [ ] OTA Software Update Requestor cluster (device-side)
- [ ] BDX (Bulk Data Exchange) protocol for image transfer
- [ ] Image verification and installation callbacks
- [ ] Version comparison and update policy

**Spec ref:** §11.19, §11.20 — OTA Software Update

### Groups Cluster
- [x] Implement Groups cluster handler (0x0004)
- [x] AddGroup / ViewGroup / RemoveGroup commands
- [x] GetGroupMembership command
- [x] Group name management (nameSupport=0, names not stored — spec-compliant minimum)
- [x] Integration with GroupMembershipTable (per-fabric endpoint membership)
- [ ] Integration with GroupKeyManagement (verify group key before accepting AddGroup)

**Spec ref:** §1.3 — Groups Cluster
**Status:** Complete (core). `GroupsCluster` enum in MatterModel defines attribute IDs, command IDs,
response command IDs, and `GroupStatus` codes. `GroupsHandler` implements all 6 commands using
`GroupMembershipTable` for storage and `CommissioningState.invokingFabricIndex` for fabric scoping.
`AddGroupIfIdentifying` checks the Identify cluster's `identifyTime` attribute on the same endpoint.
`GroupsHandler` registered on all bridged device endpoints in `MatterBridge`. `DescriptorDynamicTests`
updated to include Groups cluster ID. 16 new tests in `GroupsHandlerTests`.

### ICD Management
- [ ] Implement ICDManagement cluster (0x0046)
- [ ] IdleModeDuration / ActiveModeDuration / ActiveModeThreshold
- [ ] RegisterClient / UnregisterClient
- [ ] Check-in protocol (opcode 0x50)
- [ ] Only relevant for battery-powered devices

**Spec ref:** §9.17 — ICD Management Cluster

### Scenes Management
- [ ] Implement ScenesManagement cluster (0x0062)
- [ ] Scene storage per group
- [ ] AddScene / ViewScene / RemoveScene / RecallScene
- [ ] Scene transition time support

**Spec ref:** §1.4 — Scenes Management Cluster

### Software Diagnostics Cluster
- [ ] Implement SoftwareDiagnostics cluster (0x0034)
- [ ] ThreadMetrics attribute (thread stack usage)
- [ ] CurrentHeapUsed / CurrentHeapHighWatermark
- [ ] ResetWatermarks command

**Spec ref:** §11.12 — Software Diagnostics Cluster

### Wi-Fi / Thread Network Diagnostics
- [ ] WiFiNetworkDiagnostics cluster (0x0036)
- [ ] ThreadNetworkDiagnostics cluster (0x0035)
- [ ] EthernetNetworkDiagnostics cluster (0x0037)
- [ ] Connection status, signal strength, error counters

**Spec ref:** §11.13–11.15 — Network Diagnostics Clusters

### BLE Commissioning Transport
- [ ] BLE GATT service for Matter commissioning
- [ ] BTP (BLE Transport Protocol) framing
- [ ] iOS/macOS CoreBluetooth integration
- [ ] BLE advertisement for commissioning discovery

**Spec ref:** §4.17 — BLE Transport

### Linux Transport
- [ ] SwiftNIO UDP transport implementation
- [ ] Avahi mDNS/DNS-SD integration
- [ ] Alternative to MatterApple for non-Apple platforms

**Status:** Protocol abstractions exist (`MatterUDPTransport`, `MatterDiscovery`).
Apple implementations in MatterApple module. Linux stubs mentioned in comments.

### User Directed Commissioning (UDC)
- [ ] UDC protocol messages (opcode defined, flow not implemented)
- [ ] Commissioner discovery
- [ ] Commissioning intent broadcast

**Spec ref:** §5.8 — User Directed Commissioning

### Power Source Cluster
- [ ] Implement PowerSource cluster (0x002F)
- [ ] Status, Order, Description attributes
- [ ] Battery-related attributes (voltage, percentage, charge level)
- [ ] Wired/battery/solar feature map

**Spec ref:** §11.7 — Power Source Cluster

---

## Completed

- [x] TLV codec (encode/decode all Matter TLV types)
- [x] Message framing (MessageHeader, ExchangeHeader, StatusReport)
- [x] MRP (Message Reliability Protocol) with retransmission
- [x] SPAKE2+ (PASE password-authenticated key exchange)
- [x] CASE (Certificate Authenticated Session Establishment)
- [x] AES-128-CCM message encryption/decryption
- [x] HKDF / PBKDF2 key derivation
- [x] Matter Operational Certificates (TLV-encoded P-256 ECDSA)
- [x] Session management (SessionTable, counters, deduplication)
- [x] PASE commissioning flow (device + controller)
- [x] CASE operational session establishment
- [x] Full commissioning sequence (PASE → ArmFailSafe → CSR → AddNOC → CASE)
- [x] Interaction Model: Read (single + wildcard endpoint/cluster/attribute)
- [x] Interaction Model: Write (single + multi-attribute)
- [x] Interaction Model: Invoke (single + multi-command)
- [x] Interaction Model: Subscribe (min/max interval, change + keepalive reports)
- [x] ACL enforcement on all IM operations
- [x] 19 cluster handlers (OnOff, LevelControl, ColorControl, Thermostat, etc.)
- [x] Bridge architecture (root endpoint + aggregator + dynamic bridged endpoints)
- [x] mDNS/DNS-SD advertisement and discovery
- [x] Operational mDNS with compressed fabric ID
- [x] Multi-admin commissioning windows (open/close/expiry/admin tracking)
- [x] RemoveFabric + UpdateFabricLabel commands
- [x] Persistence (controller state, device state, attribute store)
- [x] Apple transport (NWConnection UDP, NWBrowser mDNS)
- [x] Controller: CommissioningController, OperationalController
- [x] Controller: FabricManager, DeviceRegistry, SubscriptionClient
- [x] Fabric-scoped attribute filtering (ACLs, NOCs, fabrics list) in reads and subscription reports
