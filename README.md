# MatterSwift

A native Swift implementation of the [Matter](https://csa-iot.org/all-solutions/matter/) smart home protocol.

[![Swift 6.1+](https://img.shields.io/badge/Swift-6.1+-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-macOS%20|%20iOS%20|%20Linux-blue.svg)](https://swift.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE.md)

## Overview

MatterSwift is a pure-Swift Matter protocol stack that implements both **device/bridge** and **controller** roles. It enables you to:

- **Build Matter bridges** that expose non-Matter devices to Apple Home, Google Home, and Amazon Alexa
- **Build controllers** that commission and interact with Matter devices on your network
- **Run cross-platform** on Apple platforms (via Network.framework) and Linux (via SwiftNIO)

The library targets Matter specification version 1.4 with cluster definitions code-generated from the [connectedhomeip](https://github.com/project-chip/connectedhomeip) v1.4.0.0 XML data model. It has no C++ dependencies — the entire protocol stack is implemented in Swift with strict concurrency (Swift 6).

## Quick Start

Add MatterSwift to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/user/matter-swift.git", from: "0.1.0")
]
```

### Create a Matter Bridge

```swift
import MatterSwift

// Configure the bridge
let bridge = MatterBridge(config: .init(
    vendorName: "MyCompany",
    productName: "Smart Hub",
    vendorId: 0xFFF1,
    productId: 0x8000
))

// Add a dimmable light
let light = bridge.addDimmableLight(name: "Kitchen Pendant")

// Create and start the server
let server = MatterDeviceServer(
    bridge: bridge,
    transport: AppleUDPTransport(),
    discovery: AppleDiscovery(),
    config: .init(discriminator: 3840, passcode: 20202021)
)
try await server.start()

// Update device state from your bridge logic
await light.setOnOff(true)
await light.setLevel(200)
```

### Use as a Controller

```swift
import MatterSwift

let controller = try MatterController(
    transport: AppleUDPTransport(),
    discovery: AppleDiscovery(),
    configuration: .init(fabricID: FabricID(rawValue: 1))
)

// Commission a device using its setup code
let device = try await controller.commission(
    address: deviceAddress,
    setupCode: 20202021
)

// Read an attribute
let value = try await controller.readAttribute(
    nodeID: device.nodeID,
    endpointID: .root,
    clusterID: .onOff,
    attributeID: OnOffCluster.Attribute.onOff
)
```

## Module Architecture

MatterSwift is split into focused modules that can be imported individually or together via the `MatterSwift` umbrella module.

| Module | Purpose |
|--------|---------|
| **MatterTypes** | Core types, TLV encoding/decoding, identifiers, status codes. Zero external dependencies. |
| **MatterModel** | Cluster definitions, device types, attribute schemas. Code-generated from Matter spec XML. |
| **MatterCrypto** | SPAKE2+, CASE/Sigma, AES-128-CCM session encryption, Matter Operational Certificates. |
| **MatterTransport** | Platform-agnostic transport protocol abstractions (UDP, mDNS/DNS-SD). |
| **MatterProtocol** | Wire protocol: message framing, MRP (reliability), session management, Interaction Model. |
| **MatterDevice** | Device/bridge role: endpoint management, attribute storage, subscription reports, commissioning. |
| **MatterController** | Controller role: commissioning, operational communication, device management. |
| **MatterApple** | Apple platform transport using Network.framework and CryptoKit. |
| **MatterLinux** | Linux platform transport using SwiftNIO and pure-Swift mDNS. |
| **MatterSwift** | Convenience umbrella that re-exports all modules. |

```
MatterTypes
    ↑
MatterModel ← MatterCrypto
    ↑              ↑
MatterProtocol ────┘
    ↑
├── MatterDevice
└── MatterController

MatterTransport
    ↑
├── MatterApple
└── MatterLinux
```

## Installation

Add the dependency to your `Package.swift`:

```swift
.package(url: "https://github.com/user/matter-swift.git", from: "0.1.0")
```

Then add the target dependency:

```swift
.target(name: "MyApp", dependencies: [
    .product(name: "MatterSwift", package: "matter-swift"),  // Everything
    // Or import individual modules:
    // .product(name: "MatterDevice", package: "matter-swift"),
    // .product(name: "MatterController", package: "matter-swift"),
])
```

## Platform Requirements

| Platform | Minimum Version |
|----------|----------------|
| macOS | 15.0 |
| iOS | 18.0 |
| tvOS | 18.0 |
| watchOS | 11.0 |
| visionOS | 2.0 |
| Linux | Swift 6.1+ (Ubuntu 24.04 tested) |

## Dependencies

- [swift-crypto](https://github.com/apple/swift-crypto) 4.0+
- [swift-certificates](https://github.com/apple/swift-certificates) 1.0+
- [swift-asn1](https://github.com/apple/swift-asn1) 1.0+
- [swift-log](https://github.com/apple/swift-log) 1.0+
- [swift-collections](https://github.com/apple/swift-collections) 1.1+
- [swift-nio](https://github.com/apple/swift-nio) 2.65+ (Linux only)

## Documentation

- **[STATUS.md](STATUS.md)** — What's working, what's not, supported clusters and device types
- **[MAINTENANCE.md](MAINTENANCE.md)** — Contributing guide: code generation, testing, CI
- **[API Documentation](https://swiftpackageindex.com/user/matter-swift/documentation/matterswift)** — Full DocC reference and tutorials

## License

Licensed under the Apache License, Version 2.0. See [LICENSE.md](LICENSE.md) for details.
