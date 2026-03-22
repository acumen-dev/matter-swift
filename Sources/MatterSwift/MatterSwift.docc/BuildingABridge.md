# Building a Bridge

Create a Matter bridge that exposes non-Matter devices to any Matter controller.

## Overview

A Matter bridge is the most common use case for MatterSwift. It translates between your existing device protocol (HTTP APIs, MQTT, Zigbee, proprietary protocols) and the Matter standard, making your devices visible in Apple Home, Google Home, and Amazon Alexa.

## Bridge Architecture

A Matter bridge has a fixed endpoint layout:

```
Endpoint 0: Root Node
├── Basic Information (device identity)
├── General Commissioning (commissioning state machine)
├── Operational Credentials (certificates)
├── Access Control (ACLs)
├── Network Commissioning (network status)
└── ... other utility clusters

Endpoint 1: Aggregator
└── Descriptor (PartsList → [2, 3, 4, ...])

Endpoint 2: Bridged Device (e.g., Dimmable Light)
├── OnOff
├── LevelControl
├── BridgedDeviceBasicInformation
└── Descriptor

Endpoint 3: Bridged Device (e.g., Temperature Sensor)
├── TemperatureMeasurement
├── BridgedDeviceBasicInformation
└── Descriptor
```

`MatterBridge` creates the root endpoint and aggregator automatically. You only need to add bridged devices.

## Creating the Bridge

```swift
import MatterSwift

let bridge = MatterBridge(config: .init(
    vendorName: "MyCompany",
    productName: "Smart Hub",
    vendorId: 0xFFF1,        // Use 0xFFF1-0xFFF4 for testing
    productId: 0x8000
))
```

The vendor and product IDs appear in the device's Basic Information cluster. For production use, obtain a vendor ID from the Connectivity Standards Alliance.

## Adding Devices

### Convenience Methods

MatterSwift provides convenience methods for common device types:

```swift
// Lights
let light = bridge.addDimmableLight(name: "Kitchen Pendant")
let colorLight = bridge.addColorTemperatureLight(name: "Living Room")
let rgbLight = bridge.addExtendedColorLight(name: "Bedroom Strip")

// Sensors
let tempSensor = bridge.addTemperatureSensor(name: "Office Temp")
let humiditySensor = bridge.addHumiditySensor(name: "Basement Humidity")
let contactSensor = bridge.addContactSensor(name: "Front Door")
let occupancySensor = bridge.addOccupancySensor(name: "Hallway Motion")

// Other devices
let plug = bridge.addOnOffPlugInUnit(name: "Desk Plug")
let thermostat = bridge.addThermostat(name: "Main Thermostat")
let lock = bridge.addDoorLock(name: "Front Door Lock")
let fan = bridge.addFan(name: "Ceiling Fan")
let blinds = bridge.addWindowCovering(name: "Bedroom Blinds")
```

Each method returns a `BridgedEndpoint` handle for updating state.

### Generic Endpoints

For device types without a convenience method, use `addGenericEndpoint`:

```swift
let smokeSensor = bridge.addGenericEndpoint(
    name: "Kitchen Smoke Detector",
    deviceTypeID: .smokeCOAlarm,
    clusters: [
        (.smokeCoAlarm, SmokeCoAlarmHandler()),
    ]
)
```

### Unique IDs

Pass a `uniqueID` to ensure stable endpoint assignment across restarts:

```swift
let light = bridge.addDimmableLight(
    name: "Kitchen Pendant",
    uniqueID: "kitchen-pendant-001"
)
```

Without a unique ID, endpoint numbering depends on the order devices are added.

## Updating Device State

When your bridge receives state updates from the underlying device protocol, push them to Matter using the `BridgedEndpoint` handle:

```swift
// Lights
await light.setOnOff(true)
await light.setLevel(200)                  // 0-254
await colorLight.setColorTemperature(350)  // Mireds

// Sensors
await tempSensor.setTemperature(2150)      // 21.50°C (hundredths)
await humiditySensor.setHumidity(6500)     // 65.00% (hundredths)
await contactSensor.setStateValue(false)   // false = closed

// Reachability
await light.setReachable(false)  // Mark device as offline
```

These methods update the attribute store and automatically notify any active Matter subscriptions, triggering reports to controllers.

## Receiving Commands from Controllers

When a user taps a light in Apple Home or says "Hey Siri, turn on the kitchen light", the controller sends a command to your bridge. Handle these by providing callbacks when adding devices:

```swift
let light = bridge.addDimmableLight(
    name: "Kitchen Pendant",
    onOffChanged: { isOn in
        // Forward to your device protocol
        try await myDevice.setPower(isOn)
    },
    levelChanged: { level in
        try await myDevice.setBrightness(level)
    }
)
```

## Starting the Server

Once your bridge is configured, create a `MatterDeviceServer` and start it:

```swift
let server = MatterDeviceServer(
    bridge: bridge,
    transport: AppleUDPTransport(),
    discovery: AppleDiscovery(),
    config: .init(
        discriminator: 3840,      // 12-bit, 0-4095
        passcode: 20202021,       // Setup code for commissioning
        port: 5540,               // UDP listen port
        deviceName: "My Bridge"   // Shown during commissioning
    )
)

try await server.start()
```

After starting, the server:
1. Advertises via mDNS as a commissionable device (`_matterc._udp`)
2. Accepts PASE sessions using the setup passcode
3. Handles the full commissioning flow (certificates, ACLs, CASE)
4. Begins operational mDNS advertisement (`_matter._tcp`)
5. Serves Interaction Model requests (reads, writes, subscribes, commands)

## Setup Codes

To commission your bridge, you need a setup code derived from the discriminator and passcode. MatterSwift can generate the QR code payload and manual pairing code:

```swift
let setupPayload = SetupPayload(
    discriminator: 3840,
    passcode: 20202021,
    vendorId: 0xFFF1,
    productId: 0x8000
)

print("Manual code: \(setupPayload.manualPairingCode)")
print("QR payload:  \(setupPayload.qrCodePayload)")
```

## Dynamic Endpoints

Devices can be added and removed at runtime:

```swift
// Add a new device
let newLight = bridge.addDimmableLight(name: "New Light")

// Remove a device
bridge.removeEndpoint(newLight.endpointID)
```

The aggregator's PartsList attribute updates automatically, and subscription reports are sent to connected controllers.

## Complete Example

```swift
import MatterSwift

@main
struct MyBridge {
    static func main() async throws {
        let bridge = MatterBridge(config: .init(
            vendorName: "MyCompany",
            productName: "Smart Hub",
            vendorId: 0xFFF1,
            productId: 0x8000
        ))

        // Add devices
        let kitchenLight = bridge.addDimmableLight(name: "Kitchen Light")
        let officeTemp = bridge.addTemperatureSensor(name: "Office Temp")
        let frontDoor = bridge.addContactSensor(name: "Front Door")

        // Start the server
        let server = MatterDeviceServer(
            bridge: bridge,
            transport: AppleUDPTransport(),
            discovery: AppleDiscovery(),
            config: .init(discriminator: 3840, passcode: 20202021)
        )
        try await server.start()

        // Simulate state updates
        await kitchenLight.setOnOff(true)
        await kitchenLight.setLevel(180)
        await officeTemp.setTemperature(2250)  // 22.5°C
        await frontDoor.setStateValue(true)     // Open

        // Keep running
        try await Task.sleep(for: .seconds(.max))
    }
}
```
