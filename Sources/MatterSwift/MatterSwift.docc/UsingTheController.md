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

The retry succeeds if and only if the fingerprint matches the device's DAC exactly and the DAC's public key could be read. Approving one device's fingerprint never approves another. If the key cannot be read, the controller throws `ControllerError.attestationApprovalRefused` instead, because nothing could bind the device to the approval. The check that the NOCSR is signed by the DAC key still runs on an approved device, so an override means "trust this DAC", not "skip the proof of key possession".

Tests that commission development devices should not use approval. Build a store that trusts the test device with `TestAttestation` from `MatterTestSupport` and pass it as `attestationTrustStore`.

### What is recorded

Every commissioned device carries an `attestation` record, saved with the device registry:

- `.verified` names the PAA the chain ended at and the vendor and product identifiers.
- `.overridden` holds the DAC fingerprint that was approved, the `AttestationFailureReason` that was overridden, and the time of approval.

A device commissioned before attestation was recorded has `nil`. The device's `vendorID` and `productID` come from its verified DAC, not from what the device reports about itself.

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
try await controller.invoke(
    nodeID: device.nodeID,
    endpointID: EndpointID(rawValue: 1),
    clusterID: .onOff,
    commandID: OnOffCluster.Command.toggle
)
```

For commands with parameters, provide them as TLV fields:

```swift
// Move to a specific level with transition time
try await controller.invoke(
    nodeID: device.nodeID,
    endpointID: EndpointID(rawValue: 1),
    clusterID: .levelControl,
    commandID: LevelControlCluster.Command.moveToLevel,
    fields: TLVElement.structure([
        TLVElement(tag: .contextSpecific(0), value: .unsignedInt(200)),  // level
        TLVElement(tag: .contextSpecific(1), value: .unsignedInt(10)),   // transitionTime (tenths of seconds)
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
