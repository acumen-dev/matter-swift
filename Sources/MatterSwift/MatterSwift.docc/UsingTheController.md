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
| `operationTimeout` | 30s | Timeout for individual messages |
| `commissioningTimeout` | 120s | Timeout for the full commissioning flow |
| `discoveryTimeout` | 30s | How long to search for a commissionable device when commissioning from a setup code; also `discoverDevice(nodeID:timeout:)`'s default |
| `commissionableResolveTimeout` | 5s | How long that search waits for any one advertisement to resolve before skipping it |
| `addressRefreshTimeout` | 5s | How long a CASE attempt that got no answer waits to re-resolve the device's address (see below) |

## Commissioning a Device

To commission a device at a known address, you need the address and the numeric setup passcode:

```swift
let device = try await controller.commission(
    address: MatterAddress(host: "192.168.1.100", port: 5540),
    setupCode: 20202021
)
```

The commissioning flow handles:
1. PASE session establishment (SPAKE2+ with the setup code)
2. Fail-safe arming
3. CSR and certificate issuance (NOC signed by your fabric's root CA)
4. Access control setup
5. CASE session establishment (operational encrypted session)
6. Commissioning completion

After commissioning, the device is part of your fabric and all further communication uses encrypted CASE sessions.

### Commissioning from a setup code

With the manual pairing code or the `MT:` QR payload, the controller finds the device on the network by its discriminator, so no address is needed:

```swift
let device = try await controller.commission(setupCode: "34970112332")
```

The device must have its commissioning window open. The controller uses the device's advertised retransmission timing and records it with the device; pass `mrp:` to override it, or `discoveryTimeout:` to change how long it searches (`Configuration.discoveryTimeout`, 30 seconds by default). A code that cannot be parsed throws `ControllerError.invalidSetupCode` before anything is sent; its message never repeats the code. A manual code carries only a short discriminator, so if two nearby devices share it the first one found is commissioned.

### When a device moves

A device's address can change — a new DHCP lease, a restart on another port. When a CASE handshake with a commissioned device gets no answer, the controller re-resolves the device's operational advertisement (`_matter._tcp`) once, bounded by `Configuration.addressRefreshTimeout` (5 seconds by default). If it names a different address, the controller records and persists it, and retries the handshake there. The timing in the operational TXT record replaces the device's stored retransmission timing, including an explicit `mrp:` override; an operational advertisement with an empty TXT keeps what was stored. If nothing resolves in time, or it resolves to the address just tried, the original error (`ControllerError.peerUnreachable`) is thrown. Addresses from discovery are stored as bare IP literals; one that resolves only to a host name is not adopted.

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
for await record in controller.discoverCommissionable() {
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
