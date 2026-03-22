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

## Commissioning a Device

To commission a device, you need its network address and setup code (from the QR code or manual pairing code):

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

Before commissioning, you can discover commissionable devices on the network:

```swift
let discovery = AppleDiscovery()
let devices = discovery.browse(type: .commissionable)

for await device in devices {
    print("Found: \(device.name) at \(device.address)")
}
```

## Multi-Fabric (Adding to Existing Devices)

A device that's already commissioned to another fabric (e.g., Apple Home) can be added to your fabric too — this is multi-admin. The existing controller must first open a commissioning window on the device, then you commission using the provided setup code.

See <doc:DirectPairing> for details on working with devices already in other ecosystems.
