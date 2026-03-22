# Getting Started

Install MatterSwift and run your first Matter device.

## Overview

MatterSwift is distributed as a Swift package. Add it to your project, import the umbrella module, and you're ready to create Matter devices or controllers.

## Installation

Add MatterSwift to your `Package.swift` dependencies:

```swift
dependencies: [
    .package(url: "https://github.com/user/matter-swift.git", from: "0.1.0")
]
```

Then add the target dependency:

```swift
.target(name: "MyApp", dependencies: [
    .product(name: "MatterSwift", package: "matter-swift"),
])
```

## Import Patterns

Import everything via the umbrella module:

```swift
import MatterSwift
```

Or import individual modules for fine-grained control:

```swift
import MatterDevice      // Bridge/device role only
import MatterController  // Controller role only
import MatterTypes       // Just TLV and core types
import MatterApple       // Apple platform transport
```

## Your First Bridge

The most common use case is creating a Matter bridge that exposes non-Matter devices. Here's a minimal example:

```swift
import MatterSwift

@main
struct MyBridge {
    static func main() async throws {
        // 1. Create the bridge
        let bridge = MatterBridge(config: .init(
            vendorName: "MyCompany",
            productName: "Smart Hub",
            vendorId: 0xFFF1,
            productId: 0x8000
        ))

        // 2. Add devices
        let light = bridge.addDimmableLight(name: "Desk Lamp")
        let sensor = bridge.addTemperatureSensor(name: "Office Temp")

        // 3. Create and start the server
        let server = MatterDeviceServer(
            bridge: bridge,
            transport: AppleUDPTransport(),
            discovery: AppleDiscovery(),
            config: .init(discriminator: 3840, passcode: 20202021)
        )
        try await server.start()

        // 4. Update state from your bridge logic
        await light.setOnOff(true)
        await light.setLevel(200)
        await sensor.setTemperature(2150) // 21.50 degrees C (hundredths)

        // Keep running
        try await Task.sleep(for: .seconds(.max))
    }
}
```

After starting, the server advertises via mDNS and accepts commissioning from any Matter controller (Apple Home, Google Home, etc.) using the setup code derived from the discriminator and passcode.

## Your First Controller

To commission and interact with existing Matter devices:

```swift
import MatterSwift

let controller = try MatterController(
    transport: AppleUDPTransport(),
    discovery: AppleDiscovery(),
    configuration: .init(fabricID: FabricID(rawValue: 1))
)

// Commission using the device's setup code
let device = try await controller.commission(
    address: deviceAddress,
    setupCode: 20202021
)

// Read the on/off state
let value = try await controller.readAttribute(
    nodeID: device.nodeID,
    endpointID: EndpointID(rawValue: 1),
    clusterID: .onOff,
    attributeID: OnOffCluster.Attribute.onOff
)
```

## Next Steps

- <doc:MatterConcepts> — Understand endpoints, clusters, attributes, and the Matter data model
- <doc:BuildingABridge> — Detailed guide to building a full-featured bridge
- <doc:UsingTheController> — Commission devices and read/write attributes
- <doc:PersistentStorage> — Keep credentials and state across restarts
