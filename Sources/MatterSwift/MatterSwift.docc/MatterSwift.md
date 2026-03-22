# ``MatterSwift``

A native Swift implementation of the Matter smart home protocol.

## Overview

MatterSwift provides a complete Matter protocol stack in pure Swift, supporting both **device/bridge** and **controller** roles. Use it to build Matter bridges that expose non-Matter devices to Apple Home, Google Home, and Amazon Alexa, or to build controllers that commission and interact with Matter devices.

The library targets Matter specification version 1.4, with 110 cluster definitions code-generated from the official specification XML. It runs on Apple platforms (via Network.framework) and Linux (via SwiftNIO) with Swift 6 strict concurrency throughout.

```swift
import MatterSwift

let bridge = MatterBridge(config: .init(
    vendorName: "MyCompany", productName: "Hub",
    vendorId: 0xFFF1, productId: 0x8000
))

let light = bridge.addDimmableLight(name: "Kitchen Pendant")

let server = MatterDeviceServer(
    bridge: bridge,
    transport: AppleUDPTransport(),
    discovery: AppleDiscovery(),
    config: .init(discriminator: 3840, passcode: 20202021)
)
try await server.start()
```

## Topics

### Getting Started

- <doc:GettingStarted>
- <doc:MatterConcepts>

### Building Devices

- <doc:BuildingABridge>
- <doc:PersistentStorage>

### Controlling Devices

- <doc:UsingTheController>
- <doc:DirectPairing>

### Architecture

- <doc:ModuleArchitecture>
- <doc:PlatformTransport>
