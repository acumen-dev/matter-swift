# Direct Pairing

Pair MatterSwift as a controller with physical Matter devices and existing ecosystems.

## Overview

MatterSwift can act as a standalone controller, commissioning physical Matter devices directly. This works alongside existing ecosystems — a device can be paired to Apple Home, Google Home, *and* your MatterSwift controller simultaneously via multi-admin.

## Setup Codes

Every Matter device has a setup code used for commissioning, available in two forms:

- **QR code**: Contains the full setup payload (discriminator, passcode, vendor/product IDs, discovery capabilities)
- **Manual pairing code**: An 11-digit or 21-digit numeric code printed on the device

The passcode from either format is what you pass to `controller.commission(setupCode:)`.

For testing, the default test passcode is `20202021` with discriminator `3840`.

## Discovering Devices

### Commissionable Devices

Devices in commissioning mode advertise via mDNS (`_matterc._udp`):

```swift
let discovery = AppleDiscovery()
let commissionable = discovery.browse(type: .commissionable)

for await device in commissionable {
    print("Found commissionable device: \(device.name)")
    print("  Address: \(device.address)")
    print("  Discriminator: \(device.discriminator)")
}
```

### Operational Devices

Devices already commissioned on a fabric advertise via `_matter._tcp`. These are only accessible if you have the fabric credentials.

## Commissioning a New Device

```swift
let controller = try MatterController(
    transport: AppleUDPTransport(),
    discovery: AppleDiscovery(),
    configuration: .init(fabricID: FabricID(rawValue: 1))
)

// Commission using the device's setup code
let device = try await controller.commission(
    address: MatterAddress(host: "192.168.1.100", port: 5540),
    setupCode: 20202021
)

print("Commissioned device: node \(device.nodeID)")
```

## Working with Existing Ecosystems

### Adding Your Controller to an Apple Home Device

If a device is already in Apple Home, you can add your MatterSwift controller as an additional admin:

1. In the Apple Home app, go to the device's settings
2. Select "Turn On Pairing Mode" (this opens an enhanced commissioning window)
3. Apple Home provides a new setup code
4. Commission with your MatterSwift controller using that code

### Adding Your Controller to a Google Home Device

Similar process via the Google Home app:
1. Device settings → "Linked Matter apps & services"
2. "Link new app or service"
3. Commission with the provided code

### How Multi-Admin Works

Each ecosystem creates its own **fabric** on the device. The device maintains separate:
- Node Operational Certificates per fabric
- Access Control Lists per fabric
- Subscription state per fabric
- Group keys per fabric

All fabrics can control the device simultaneously. When Apple Home turns a light on, Google Home sees the state change too (if subscribed).

## Persisting Controller State

For your controller to reconnect to devices after restart, you must persist the fabric credentials. See <doc:PersistentStorage> for details on implementing a `MatterControllerStore`.

Without persistence, you'll need to recommission all devices after each restart.

## Limitations

- **BLE commissioning** is not yet supported — devices must be on the IP network and discoverable via mDNS
- **Thread devices** require a Thread border router to be reachable via IP
- **Wi-Fi provisioning** (ScanNetworks, AddWiFiNetwork) is not yet implemented — devices must already be on the network
