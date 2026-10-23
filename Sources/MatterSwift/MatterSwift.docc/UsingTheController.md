# Using the Controller

Commission Matter devices and interact with them programmatically.

## Overview

MatterSwift's controller role lets you act as a Matter commissioner and controller — the same role that Apple Home, Google Home, or Amazon Alexa plays. Use it to commission new devices onto your fabric, read and write attributes, invoke commands, and subscribe to state changes.

## Creating a Controller

```swift
import MatterSwift

let controller = try MatterController(
    transport: AppleUDPTransport(),
    discovery: AppleDiscovery(),
    configuration: .init(
        fabricID: FabricID(rawValue: 1),
        controllerNodeID: NodeID(rawValue: 1),
        vendorID: .test
    )
)
```

The controller generates a root CA key pair automatically and manages fabric credentials for all commissioned devices.

### Configuration Options

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `fabricID` | Required | Identifies your fabric (trust domain) |
| `controllerNodeID` | 1 | This controller's node ID within the fabric |
| `vendorID` | `.test` | Vendor ID for NOC issuance |
| `rootKey` | Generated | Root CA private key (provide for persistence) |
| `attestationTrustStore` | `nil` | The PAAs and Certification Declaration signing keys attestation is checked against; `nil` uses the bundled production store |
| `operationTimeout` | 30s | Timeout for individual messages |
| `commissioningTimeout` | 120s | Timeout for the full commissioning flow |
| `discoveryTimeout` | 30s | How long to search for a commissionable device when commissioning from a setup code; also `discoverDevice(nodeID:timeout:)`'s default |
| `commissionableResolveTimeout` | 5s | How long that search waits for any one advertisement to resolve before skipping it |
| `addressRefreshTimeout` | 5s | How long a CASE attempt that got no answer waits to re-resolve the device's address (see below) |
| `interfaces` | `.automatic` | Which network interfaces Matter traffic may use on a multi-homed host (see Multi-homed hosts) |
| `retryClock` | `ContinuousClock()` | The clock a CASE `busy` wait runs on; a test seam |
| `metricsLabelPrefix` | `matter` | Prefix of every metric label (`<prefix>_controller_messages_total`, ...) |
| `metricsFactory` | `nil` | Metrics backend; `nil` uses `MetricsSystem.factory` as it is when the controller is created |
| `tracer` | `nil` | Tracer for spans; `nil` uses `InstrumentationSystem.tracer` as it is when the controller is created |

## Commissioning a Device

To commission a device at a known address, you need the address and the numeric setup passcode:

```swift
let device = try await controller.commission(
    address: MatterAddress(host: "192.0.2.100", port: 5540),
    setupCode: 20202021
)
```

The host is an IP literal. Any text for an address works — an IPv6 host with or without brackets, uncompressed or uppercase — and the device is recorded under the canonical form (`"fd00::1"`). Addresses from discovery are always canonical, and never carry an IPv6 `%zone`: a zone names an interface of this host, which a stored address cannot rely on.

The commissioning flow handles:
1. PASE session establishment (SPAKE2+ with the setup code)
2. Fail-safe arming
3. Device attestation (see <doc:UsingTheController#Attestation>)
4. CSR and certificate issuance (NOC signed by your fabric's root CA)
5. Access control setup
6. CASE session establishment (operational encrypted session)
7. Commissioning completion

After commissioning, the device is part of your fabric and all further communication uses encrypted CASE sessions.

### Commissioning from a setup code

With the manual pairing code or the `MT:` QR payload, the controller finds the device on the network by its discriminator, so no address is needed:

```swift
let device = try await controller.commission(setupCode: "34970112332")
```

The device must have its commissioning window open. The controller uses the device's advertised retransmission timing and records it with the device; pass `mrp:` to override it, or `discoveryTimeout:` to change how long it searches (`Configuration.discoveryTimeout`, 30 seconds by default). A code that cannot be parsed throws `ControllerError.invalidSetupCode` before anything is sent; its message never repeats the code. A manual code carries only a short discriminator, so if two nearby devices share it the first one found is commissioned.

### When a device moves

A device's address can change — a new DHCP lease, a restart on another port. When a CASE handshake with a commissioned device gets no answer, the controller re-resolves the device's operational advertisement (`_matter._tcp`) once, bounded by `Configuration.addressRefreshTimeout` (5 seconds by default). If it names a different address, the controller records and persists it, and retries the handshake there. The timing in the operational TXT record replaces the device's stored retransmission timing, including an explicit `mrp:` override; an operational advertisement with an empty TXT keeps what was stored. If nothing resolves in time, or it resolves to the address just tried, the original error (`ControllerError.peerUnreachable`) is thrown. Addresses from discovery are stored as bare IP literals; one that resolves only to a host name is not adopted.

## Attestation

Before it issues a certificate, the controller checks that the device is what it claims to be. Every certified Matter device carries a Device Attestation Certificate (DAC), issued by its manufacturer's Product Attestation Intermediate (PAI), which chains to a Product Attestation Authority (PAA) published by the Connectivity Standards Alliance. The controller asks the device to prove it holds the DAC's private key, and only then commissions it.

### How verification works

During commissioning, after the fail-safe is armed and before any credentials are issued, the controller:

1. Reads the device's Basic Information VendorID and ProductID.
2. Fetches the DAC and PAI (CertificateChainRequest).
3. Sends a fresh nonce and receives the signed attestation elements (AttestationRequest).
4. Verifies them with `DeviceAttestationVerifier`.
5. Requests the CSR, and checks that the NOCSR is signed by the DAC's key. This binds the key being certified to the device that was attested.

The verifier covers the whole attestation procedure except revocation:

- The DAC and PAI chain to a PAA in the trust store, with valid signatures, key identifiers and validity windows.
- The vendor and product identifiers in the DAC, the PAI and (where present) the PAA agree.
- The Certification Declaration is signed by a CSA Certification Declaration key the trust store holds, lists the device's vendor and product, and, if it names authorized PAAs, names this one. Basic Information is compared only against the Certification Declaration, not against the DAC.
- The attestation signature verifies under the DAC key and the elements echo the nonce.
- The NOCSR signature verifies under the DAC key.

Revocation (the DCL's revocation lists) and the DCL's live certificate and firmware checks are not performed.

### Trust stores

An `AttestationTrustStore` is a plain value: the PAAs to trust, the Certification Declaration signing keys, and a provenance note saying where it came from. Nothing in swift-matter refreshes or applies one on its own. swift-matter ships mechanisms, not policy; when and how a store is updated is the embedding application's decision.

Pass the store you want in the configuration:

```swift
let store = try AttestationTrustStore.bundledProduction()

let controller = try MatterController(
    transport: AppleUDPTransport(),
    discovery: AppleDiscovery(),
    configuration: .init(
        fabricID: FabricID(rawValue: 1),
        attestationTrustStore: store
    )
)
```

There are three ways to get one:

- **Bundled.** `AttestationTrustStore.bundledProduction()` is a snapshot of the production Distributed Compliance Ledger (DCL) PAAs and the CSA Certification Declaration keys, shipped as a resource of MatterCrypto with an integrity manifest. It is a starting point, dated by its provenance. One legacy PAA does not parse under the rules the runtime applies and is excluded; the manifest records it. Leaving `attestationTrustStore` as `nil` uses this store. It is read through `Bundle.module`, so an executable must ship MatterCrypto's resource bundle next to it, or the process traps the first time the bundle is read. A bundle that is present but damaged makes the controller's initialiser throw `ControllerError.attestationTrustStoreUnavailable`. A deployment that cannot ship the bundle must pass a store.
- **A directory.** `AttestationTrustStore(directory:)` loads every `.der` and `.pem` certificate in a directory (the same layout `chip-tool` uses for `--paa-trust-store-path`) and is strict: one bad file fails the load. `write(to:)` saves a store's PAAs to a directory atomically, and `diff(from:)` compares two stores.
- **Explicit.** `AttestationTrustStore(paas:cdSigningKeys:provenance:)` builds one from certificates you already hold.

### Updating from the DCL

`DCLTrustStoreFetcher` fetches the current production PAAs from the DCL, validates each one, and returns a candidate store together with a `TrustStoreDiff` against the store you pass in. It never writes a file and never applies anything:

```swift
let fetcher = DCLTrustStoreFetcher()
let (candidate, diff) = try await fetcher.fetchProduction(current: store, now: Date())

if !diff.isEmpty {
    // diff.added, .removed, .changed list the roots by subject, vendor and SHA-256;
    // diff.excluded says why any certificate the DCL returned was left out.
    try candidate.write(to: trustStoreDirectory)
}
```

What to do with the diff is policy, and it is yours. A locked deployment never fetches. An on-demand one fetches when an administrator asks and shows the diff for approval. An automatic one applies a candidate unattended. swift-matter supports all three because it applies none of them.

### When attestation fails

A device that does not verify is not commissioned. The controller throws `ControllerError.attestationFailed` carrying an `AttestationFailure`, and leaves the device untouched: its fail-safe is disarmed and no node ID has been consumed, so the device can be commissioned again immediately.

The failure's `reason` says what went wrong (an untrusted root, an expired certificate, a vendor and product mismatch, a bad signature, and so on). For an approval prompt it also carries `dacFingerprint` (the SHA-256 of the DAC) and the unverified `dacPublicKey`, `dacVendorID` and `dacProductID`.

Development and test devices carry attestation certificates that do not chain to a production PAA, so they fail against the production store. That is correct. A person can look at what the device claims to be and decide to trust it anyway, by retrying with `approvingUnverifiedDevice:` set to the failure's fingerprint:

```swift
func commissionWithApproval(
    _ controller: MatterController,
    address: MatterAddress,
    setupCode: UInt32
) async throws -> CommissionedDevice {
    do {
        return try await controller.commission(address: address, setupCode: setupCode)
    } catch ControllerError.attestationFailed(let failure) {
        guard let fingerprint = failure.dacFingerprint,
              await userApproves(
                  fingerprint: fingerprint,
                  vendorID: failure.dacVendorID,
                  productID: failure.dacProductID,
                  reason: failure.reason
              )
        else { throw ControllerError.attestationFailed(failure) }

        return try await controller.commission(
            address: address,
            setupCode: setupCode,
            approvingUnverifiedDevice: fingerprint
        )
    }
}
```

The retry succeeds if and only if the fingerprint matches the device's DAC exactly and the DAC's public key could be read. Approving one fingerprint never approves a device presenting a different DAC. Devices presenting byte-identical DACs (clones, or every instance of a CHIP example app) share a fingerprint, so approving it approves all of them. If the key cannot be read, the controller throws `ControllerError.attestationApprovalRefused` instead, because nothing could bind the device to the approval. The check that the NOCSR is signed by the DAC key still runs on an approved device, so an override means "trust this DAC", not "skip the proof of key possession".

Tests that commission development devices should not use approval. Build a store that trusts the test device's credentials explicitly and pass it as `attestationTrustStore`:

```swift
let creds = try DeviceAttestationCredentials.testCredentials()
let trustStore = try AttestationTrustStore(
    paas: [creds.paaCertificate],
    cdSigningKeys: [CDSigningKey(certificateDER: creds.cdSigningCertificate!)],
    provenance: TrustStoreProvenance(source: "explicit")
)
```

(This package's own tests do the same through `TestAttestation` in `MatterTestSupport`, which is not a product.)

### What is recorded

Every commissioned device carries an `attestation` record, saved with the device registry:

- `.verified` names the PAA the chain ended at and the DAC's vendor and product identifiers.
- `.overridden` holds the DAC fingerprint that was approved, the `AttestationFailureReason` that was overridden, and the time of approval.

A device commissioned before attestation was recorded has `nil`. The device's `vendorID` and `productID` are the product's, as it reports them in Basic Information. On a `.verified` device the Certification Declaration lists them, so they are verified; on an `.overridden` device they are the device's unverified claim. A white-label product's DAC can name a different vendor (the OEM's); the DAC's identifiers are the ones in the `.verified` record.

## Reading Attributes

```swift
// Read a single attribute
let onOffValue = try await controller.readAttribute(
    nodeID: device.nodeID,
    endpointID: EndpointID(rawValue: 1),
    clusterID: .onOff,
    attributeID: OnOffCluster.Attribute.onOff
)

// The returned TLV value can be inspected
if case .bool(let isOn) = onOffValue {
    print("Light is \(isOn ? "on" : "off")")
}
```

## Writing Attributes

```swift
try await controller.writeAttribute(
    nodeID: device.nodeID,
    endpointID: EndpointID(rawValue: 1),
    clusterID: .levelControl,
    attributeID: LevelControlCluster.Attribute.currentLevel,
    value: .unsignedInt(200)
)
```

## Invoking Commands

```swift
// Toggle a light
_ = try await controller.invokeCommand(
    nodeID: device.nodeID,
    endpointID: EndpointID(rawValue: 1),
    clusterID: .onOff,
    commandID: OnOffCluster.Command.toggle
)
```

For commands with parameters, provide them as TLV fields:

```swift
// Move to a specific level with transition time
_ = try await controller.invokeCommand(
    nodeID: device.nodeID,
    endpointID: EndpointID(rawValue: 1),
    clusterID: .levelControl,
    commandID: LevelControlCluster.Command.moveToLevel,
    commandFields: .structure([
        TLVElement.TLVField(tag: .contextSpecific(0), value: .unsignedInt(200)),  // level
        TLVElement.TLVField(tag: .contextSpecific(1), value: .unsignedInt(10)),   // transitionTime (tenths of seconds)
    ])
)
```

## Subscribing to Changes

Subscribe to receive reports when attributes change:

```swift
let subscription = try await controller.subscribe(
    nodeID: device.nodeID,
    attributePaths: [
        AttributePath(
            endpointID: EndpointID(rawValue: 1),
            clusterID: .onOff,
            attributeID: OnOffCluster.Attribute.onOff
        )
    ],
    minInterval: 1,
    maxInterval: 60
)

// Receive reports
for await report in subscription.reports {
    for attribute in report.attributes {
        print("Changed: \(attribute.path) = \(attribute.value)")
    }
}
```

## Stopping the Controller

`stop()` is terminal. Requests still in flight, and any made afterwards, fail with `MessagingError.stopped`, or with the error the controller maps it to: a `ControllerError.transportError` from an operational request, or a `ControllerError.commissioningFailed` from commissioning. `ControllerError.isStopped(_:)` is true for those three forms, so a caller can treat a stopped request as abandoned rather than failed. It is false for every other error, including one whose message only mentions `stopped`:

```swift
do {
    _ = try await controller.invokeCommand(nodeID: nodeID, endpointID: endpoint, clusterID: .onOff, commandID: OnOffCluster.Command.toggle)
} catch where ControllerError.isStopped(error) {
    // Shutting down: not a device failure.
}
```

## Observability

The controller reports through three standard Swift server ecosystem APIs: swift-log, swift-metrics and swift-distributed-tracing. Metrics and tracing are no-ops until you bootstrap a backend or pass one in.

### Logging

The controller logs through the `Logger` you pass to `MatterController(…logger:)`. Every component keeps that logger's label and handler and adds one metadata key, `matter.subsystem`, which is one of `messenger`, `mrp`, `exchange`, `session`, `case`, `pase`, `im`, `subscription`, `discovery` or `transport`. A level table keyed by label and subsystem can therefore turn on, say, `mrp` at trace without the rest. (`case` carries CASE establishment lines only. Commissioning progress and attestation lines are on `pase`; persistence and restore lines are on `session`.)

As a rule, info is lifecycle, debug is per interaction and trace is per message. Per-datagram drops that signal a fault rather than normal protocol behaviour (`undecodable`, `decrypt_failed`) are logged at debug.

| Level | What |
|---|---|
| info | CASE / PASE session established or failed (latency, outcome); commissioning started, complete, failed; device attestation verified; session invalidated (why); session peer address changed; controller restored from persisted state; subscription established, lost or closed (reason); re-subscribing (attempt, backoff); operational address changed (old, new); CASE retry at a re-resolved address; peer unreachable (transmissions); a final message on a closed exchange that went unacknowledged |
| notice, warning, error | Unusual conditions, for example: a commissionable instance skipped, attestation failed and continuing on the caller's approval, an operational re-resolve failed (notice); a failed state save, commissioning failed and the fail-safe could not be disarmed, a transport send failure, a full inbound queue, "Cannot encode standalone ack", a subscription report that could not be decoded, recorded or answered, a chunk carrying a wrong subscription ID, a broken chunk chain (warning); the transport receive stream ending under a running messenger, and an encrypted frame larger than the UDP payload limit, reported by `SecureMessageCodec` through the messenger's `transport` logger (error) |
| debug | IM invoke / read / write request and response (status, latency, and the decoded command fields or written value); timed-request steps; subscribe request, response and refusal; each ReportData chunk; mDNS resolve start / result / failure; exchange response timeout; an unsolicited message with no handler; undecodable and undecryptable datagrams; establishments and IM calls that were cancelled or stopped |
| trace | Every frame sent and received (session, exchange, protocol, opcode, counter, ack); MRP retransmit, ack received, standalone ack; dropped duplicate, out-of-window, stale-exchange and unknown-session frames; attribute values in reports and reads; liveness deadline recomputation |

#### Metadata keys

The keys are public constants in `MatterLogKey`; spans use the same names for their attributes.

| Key | Value |
|---|---|
| `matter.subsystem` | One of the ten subsystems above |
| `matter.node` | Node ID, hex. On an operational session it is carried on send, receive, drop and standalone-ack lines; never on a PASE session. Retransmit, give-up, ack-received and response-timeout lines never carry it |
| `matter.session` | Local session ID, hex; the literal `unsecured` for an unsecured scope |
| `matter.exchange` | Exchange ID, hex |
| `matter.protocol` | Protocol ID, hex |
| `matter.opcode` | Protocol opcode, hex |
| `matter.counter` | Message counter, decimal |
| `matter.ack` | Acknowledged message counter, decimal |
| `matter.endpoint`, `matter.cluster`, `matter.command`, `matter.attribute` | Path components, hex |
| `matter.im_status` | IM status code, hex |
| `matter.subscription` | Subscription ID, hex |
| `matter.latency_ms` | Whole milliseconds (truncated), as a decimal string |
| `matter.attempt` | Retransmit, re-subscribe or transmission count, decimal |
| `matter.reason` | Why a frame was dropped, a session ended or a subscription was lost (see below) |
| `matter.instance` | mDNS instance name (span attribute of `matter.resolve`) |
| `matter.timed` | `true` on a timed invoke's `matter.im.invoke` span |
| `matter.paths` | The `endpoint/cluster/attribute` paths of a report (span attribute of `matter.report`) |

Ids are `0x` plus upper-case hex with no padding (session `0xA`, cluster `0x102`). Counters, acks and attempts are decimal. Every metadata value is a string, numbers included.

#### Reasons

`matter.reason` is a closed vocabulary; it is safe to filter and group on:

- Messenger drops and failures: `duplicate`, `out_of_window`, `unknown_session`, `stale_exchange`, `undecodable`, `decrypt_failed`, `queue_full`, `send_failed` (a failed send of a message MRP tracks is retransmitted; a failed send of a standalone ack is not), `no_handler` (an unsolicited message nothing handles: acknowledged and closed).
- Session invalidation: `caller_request` (`invalidateSession(for:)`), `device_removed`, `peer_unreachable`, `dead_session` (a subscription could not be established on it). The line's message gives the same reason as a phrase.
- Subscription end: `liveness` (no report within the negotiated maximum interval plus the liveness margin), `resubscribe_failed`, `session` (the session it ran on is gone, or its record was removed), `closed` (cancelled by its owner, including `stop()` and `removeDevice`).
- CASE / PASE: the outcome of a failed establishment (`refused`, `timeout`, `unreachable`, `error`), or `cancelled` / `stopped` on the debug line of an aborted one.
- mDNS resolve: `timeout` (the resolve outlived its bound), `failed` (any other error; its text is in the message only), or `aborted` on the debug line of a cancelled or stopped resolve.

The `SubscriptionEvent.lost` text is unchanged and is separate from `matter.reason`.

### Metrics

Metrics use swift-metrics. Every label is `<prefix>_<name>`; the prefix is `metricsLabelPrefix` (default `matter`). Dimensions are bounded enums only; a node, session or subscription is never a dimension.

| Metric | Type | Dimensions |
|---|---|---|
| `matter_controller_messages_total` | counter | `direction` (`in`, `out`), `protocol` (`secure_channel`, `interaction_model`, `bdx`, `udc`, `echo`, `other`) |
| `matter_mrp_retransmits_total` | counter | none |
| `matter_mrp_give_ups_total` | counter | none |
| `matter_exchange_timeouts_total` | counter | none |
| `matter_im_requests_total` | counter | `kind` (`invoke`, `read`, `write`, `timed`), `outcome` (`success`, `im_status`, `timeout`, `unreachable`, `error`) |
| `matter_im_request_duration` | timer | `kind` |
| `matter_sessions_established_total` | counter | `type` (`case`, `pase`), `outcome` (`success`, `refused`, `timeout`, `unreachable`, `error`) |
| `matter_case_duration` | timer | none |
| `matter_subscription_lost_total` | counter | `reason` (`liveness`, `resubscribe_failed`, `session`, `closed`) |
| `matter_resubscribes_total` | counter | none. Counts re-subscribe attempts, successful or not |
| `matter_report_interval` | timer | none |

What the durations cover:

- A timed invoke is counted and timed under `kind="timed"`.
- `matter_controller_messages_total` counts accepted inbound frames, outbound frames at their first send, and standalone acks. It does not count retransmits or dropped duplicates.
- `matter_im_request_duration` runs from the start of the call to its result. On a cold node that includes establishing the session (CASE), and any address-refresh retry.
- `matter_case_duration` records successful CASE establishments only, handshake through registration. After an address-refresh retry it includes the failed attempt, the re-resolve and the second handshake.
- `matter_report_interval` is the time between the first chunks of consecutive reports on a subscription; it restarts at each (re-)establishment.

A call or establishment that is cancelled, or ended by `stop()`, is not counted and not timed. It gets a debug line, and its span ends without error status.

### Tracing

Spans use swift-distributed-tracing. The public IM methods, `subscribe` and `session(for:)` take `context: ServiceContext = .current ?? .topLevel`, so a caller's span parents the controller's:

```swift
try await withSpan("apply cover target") { span in
    _ = try await controller.invokeCommand(
        nodeID: node, endpointID: endpoint, clusterID: windowCovering, commandID: goToLift,
        commandFields: fields, context: span.context
    )
}
```

| Span | Notes |
|---|---|
| `matter.im.invoke`, `matter.im.read`, `matter.im.write` | One per public IM call. A timed invoke is a `matter.im.invoke` span with `matter.timed` set |
| `matter.exchange` | Child of the span that opened it: `matter.case` or `matter.pase` for handshake exchanges, `matter.subscribe` for subscribe exchanges, the IM span for IM calls. Events: `send` (with `matter.counter`), `retransmit` (with `matter.attempt`), `ack` (with `matter.ack`); all three values are integers. A span the tracer does not record is ended at once and gets no events. Error status on give-up, response timeout or session closed |
| `matter.case`, `matter.pase` | Session establishment; `matter.case` parents the address-refresh `matter.resolve` |
| `matter.resolve` | An mDNS resolve, with `matter.instance`. Only `findCommissionable`, `discoverDevice(nodeID:)` and the CASE address-refresh are instrumented (span and `mDNS resolve` debug lines). The public `resolve(_:)` on a browse record has neither. `findCommissionable` and `discoverDevice` parent it on the task's current context |
| `matter.subscribe` | One establishment round (initial or re-subscribe), child of the caller's context |
| `matter.report` | One per ReportData chunk, a root span linked to the round's `matter.subscribe` span; `matter.paths` is an array of `endpoint/cluster/attribute` path strings |
| `matter.subscription.lost` | One per loss or close, a root span linked to the round's `matter.subscribe` span, with `matter.reason`. Error status for a loss, none for a close |

There is no long-lived subscription span. A subscription can live for days, and a trace that long cannot be exported, sampled or viewed, so each report and loss is its own short root trace that links back to the `matter.subscribe` span that established the subscription.

`openExchange(..., context:)` on the messenger defaults to `nil`, which creates no `matter.exchange` span. Cancelled and stopped operations end their spans without error status. Commissioning, which has no `context` parameter, parents its PASE and CASE spans on the task's current context.

### Bootstrapping

Bootstrap `MetricsSystem` and `InstrumentationSystem` before creating the controller, or pass `metricsFactory` and `tracer` in its configuration. The controller resolves them once, at creation; one created first keeps the no-op backends.

### Secrets and redaction

These never appear in a log message, metadata value, span attribute or span event: the root key; NOC and DAC private keys; IPK and epoch keys; session encrypt, decrypt and attestation keys; CASE ephemeral keys and the shared secret; the PASE passcode; SPAKE2+ contexts; setup codes; the PBKDF salt; and the raw payload bytes of secure-channel and decrypted IM messages.

- The types that hold secrets describe themselves redacted in `description`, `debugDescription` and reflection:
  - MatterController: `FabricManager`, `PASESession` and its `PBKDFParamRequestContext` and `Pake1Context`, `CommissioningController.CommissioningContext`, `ControllerSession.HandshakeContext`, and `MatterController.Configuration` (it renders `rootKey: <redacted>`).
  - MatterProtocol: `SecureSession`, `CASEProtocolHandler` and its initiator and responder handshake contexts.
  - MatterCrypto: `SessionKeys`, `FabricInfo`, `ResumptionTicket`, `ResumptionTicketStore`, `DeviceAttestationCredentials`, `CASESession.InitiatorContext` and `.ResponderContext`, `Spake2pProverContext`, `Spake2pVerifierContext`, `Spake2pVerifier`.
  - MatterTypes: `SetupCode`, `StoredFabric`, `StoredControllerIdentity`.
- The internal IM request path never logs payloads. Only the public IM API logs decoded command fields and values.
- Fields and values of the clusters in `MatterLogValue.sensitiveClusters` are always `<redacted>`: 0x0031 (Network Commissioning), 0x003C (Administrator Commissioning), 0x003E (Operational Credentials), 0x003F (Group Key Management), 0x0046 (ICD Management), 0x0101 (Door Lock), 0x0452 (Thread Border Router Management), 0x0453 (Thread Network Directory) and 0x050E (Account Login). The redaction fails closed: a path whose cluster is unknown, such as a wildcard, is redacted too.
- `MatterLogValue.value(_:clusterID:)`, `MatterLogValue.path(_:)` and `MatterLogValue.reportEntry(_:)` are the controller's own renderers for IM values, paths and report entries. A consumer that logs IM values under `matter.*` keys, or in its own lines, should render them with these, so they are redacted by the same rule.
- TLV values elsewhere are rendered with `String(describing:)`, which is module-qualified, so debug lines that carry values are noisy.

### Limits

- Controller CASE session resumption is not implemented, so every `matter_sessions_established_total{type="case"}` is a full handshake.
- Device-side logging (the bridge and its handlers) is unchanged and does not use these keys, metrics or spans. The device path through `SecureMessageCodec` uses its default `matter.protocol.codec` logger.
- The UDP transports (`matter.apple.udp`, `matter.linux.udp`) and mDNS keep their own loggers, with no `matter.subsystem`.

## Multi-homed hosts

A host with more than one interface on the same network (Ethernet and Wi-Fi, say) lets the kernel choose the source address and interface of every datagram. If the route to a device moves between interfaces mid-handshake, the device sees a message from an address it is not expecting and ignores it. The controller avoids this by pinning each exchange to one path.

Set `Configuration.interfaces` to an `InterfacePolicy`:

```swift
let controller = try MatterController(
    configuration: .init(
        fabricID: FabricID(rawValue: 1),
        interfaces: InterfacePolicy(preferred: ["en0"], excluded: ["utun3"])
    )
)
```

The policy is an order, not an allow-list: the controller uses the first preferred interface that has a route to the device, falls through to the route table's choice when it has none, and logs that it did. Interfaces you do not name stay usable. Only `excluded` is a hard limit. See <doc:PlatformTransport> for the full selection rules.

### What is pinned, and when it moves

- A PASE or CASE handshake is pinned to the path its first message chose. Every later frame on it (Sigma3, acknowledgements, retransmissions) uses that path, and unauthenticated traffic never moves it.
- The session that handshake establishes inherits the path.
- A session re-pins only when a message that decrypted and passed counter de-duplication arrives on a different allowed interface. A datagram arriving on an excluded interface never moves the pin.
- If the pinned path loses its route (`TransportPathError.pathUnavailable`), a session re-selects and resends. A handshake in flight fails at once, because changing source mid-handshake breaks it anyway, and a CASE attempt that hit it is retried once straight away on a fresh selection.
- If no allowed interface has a route (`noAllowedRoute`), the controller treats the device as unreachable: the session is invalidated and the device's address re-resolved.

Device-side, `MatterDeviceServer.Config.interfaces` applies the same rules as a responder: a handshake is pinned to the arrival path of its first message, the session inherits it, and replies leave from the address the peer sent to.

### What an operator sees

| Signal | Level / type | Meaning |
|---|---|---|
| `en1 preferred, no route to fdf3:...; using en0` style line (`Path to <host>: ...; using <interface> (<address>)`) | info, `transport` | A send passed over a preferred interface |
| `Interface <name> named in the Matter interface policy is down` / `missing` / `available again` | warning / info, `transport` | A named interface's state; logged when the policy is applied and when it changes, never per send |
| `Session 0x1a2b re-pinned en1 → en0 (traffic arrived on en0)` | info, `session` | Re-pin on authenticated arrival |
| `Session 0x1a2b: en1 lost its route to <address>; re-selecting`, then `re-pinned to ...` | info, `session` | Route lost; the session moved |
| `CASE path en1 lost its route to <address>; retrying on a fresh selection` | info, `case` | A handshake restarted after losing its path |
| `matter_transport_path_selections_total{outcome}` | counter | Sends that chose their path: `preferred`, `fallthrough` or `route_table` |
| `matter_transport_path_repins_total{reason}` | counter | Sessions moved: `arrival` or `route_lost` |
| `matter_case_busy_waits_total` | counter | CASE attempts the peer answered `busy` and that were waited out |

The chosen path is also recorded as `matter.interface` and `matter.local_address` on the CASE span and in trace-level send and receive logs. The metric labels use `metricsLabelPrefix`.

### CASE busy

A device that is already running a CASE handshake may answer Sigma1 with a StatusReport of `busy`, carrying a minimum wait in milliseconds. The controller waits at least that long on `Configuration.retryClock`, then retries with a fresh Sigma1. It waits at most three times per establishment, and that budget, with the `operationTimeout` deadline, is shared with the address-refresh retry. A wait that would pass `operationTimeout` fails instead with `ControllerError.caseSessionFailed("peer busy; asked to wait N ms")`. A StatusReport with no wait time is treated as a wait of zero. Each wait is logged at info. Tests inject a manual clock as `retryClock`; production code leaves the default.

## Device Discovery

Before commissioning, you can browse for commissionable devices on the network. Browse records carry the instance name and TXT record, but no address; resolve one to reach it:

```swift
for await record in await controller.discoverCommissionable() {
    let address = try await controller.resolve(record)
    print("Found: \(record.name) at \(address.host):\(address.port), discriminator \(record.txtRecords["D"] ?? "?")")
}
```

To find the device a setup code refers to, use `findCommissionable(_:timeout:)`, which matches the code's discriminator (and vendor/product, where both sides carry them) and returns a `CommissionableDevice` with its address and advertised timing:

```swift
let device = try await controller.findCommissionable(try SetupCode(parsing: "34970112332"))
print("Found \(device.instanceName) at \(device.address.host), discriminator \(device.discriminator)")
```

## Multi-Fabric (Adding to Existing Devices)

A device that's already commissioned to another fabric (e.g., Apple Home) can be added to your fabric too — this is multi-admin. The existing controller must first open a commissioning window on the device, then you commission using the provided setup code.

See <doc:DirectPairing> for details on working with devices already in other ecosystems.
