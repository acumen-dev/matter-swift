# Matter Concepts

Understand the Matter data model: nodes, endpoints, clusters, attributes, and more.

## Overview

Matter is a smart home connectivity standard developed by the Connectivity Standards Alliance (CSA). It provides a unified protocol for devices from different manufacturers to communicate, regardless of whether the controller is Apple Home, Google Home, Amazon Alexa, or Samsung SmartThings.

This article covers the key concepts you need to understand when working with MatterSwift.

## Nodes and Endpoints

A **node** is a single Matter device on the network. Each node has one or more **endpoints**, which are logical sub-devices within the node.

- **Endpoint 0** is always the **root node**. It contains utility clusters for device identity, commissioning, access control, and diagnostics.
- **Endpoints 1+** contain the actual device functionality (lights, sensors, locks, etc.).

For a **bridge**, the layout is:
- **Endpoint 0**: Root node (identity, commissioning, credentials)
- **Endpoint 1**: Aggregator — its Descriptor cluster's PartsList enumerates all bridged endpoints
- **Endpoints 2+**: Bridged devices, each with its own device type and clusters

## Clusters, Attributes, and Commands

A **cluster** is a collection of related functionality. Think of it as an interface or protocol that an endpoint implements.

Each cluster contains:
- **Attributes**: Persistent state values (e.g., `OnOff.onOff`, `LevelControl.currentLevel`)
- **Commands**: Actions that can be invoked (e.g., `OnOff.toggle`, `LevelControl.moveToLevel`)
- **Events**: Asynchronous notifications (e.g., `DoorLock.lockOperation`, `OnOff.stateChange`)

Common clusters include:

| Cluster | ID | Purpose |
|---------|----|---------|
| On/Off | 0x0006 | Binary on/off state and toggle |
| Level Control | 0x0008 | Brightness or intensity level (0-254) |
| Color Control | 0x0300 | Hue, saturation, color temperature, XY color |
| Temperature Measurement | 0x0402 | Temperature in hundredths of a degree Celsius |
| Door Lock | 0x0101 | Lock/unlock state and operations |
| Descriptor | 0x001D | Lists which clusters and device types an endpoint supports |

MatterSwift includes 110 cluster definitions code-generated from the Matter specification and 28 hand-written cluster handlers with full attribute and command support.

## Device Types

A **device type** is a specification-defined template that prescribes which clusters an endpoint must implement. For example:

| Device Type | ID | Required Clusters |
|---|---|---|
| On/Off Light | 0x0100 | OnOff, Descriptor |
| Dimmable Light | 0x0101 | OnOff, LevelControl, Descriptor |
| Color Temperature Light | 0x0102 | OnOff, LevelControl, ColorControl, Descriptor |
| Temperature Sensor | 0x0302 | TemperatureMeasurement, Descriptor |
| Door Lock | 0x000A | DoorLock, Descriptor |

MatterSwift's `MatterBridge` convenience methods (`addDimmableLight`, `addTemperatureSensor`, etc.) automatically configure the correct clusters for each device type.

## Fabrics and Multi-Admin

A **fabric** is a trust domain. Each fabric has a root certificate authority (CA), and all nodes in the fabric have Node Operational Certificates (NOCs) signed by that CA.

A single device can belong to **multiple fabrics** simultaneously. This is how a light can be controlled by both Apple Home and Google Home at the same time — each ecosystem creates its own fabric on the device.

Each fabric has its own:
- Access Control List (ACL) entries
- Operational certificates
- Group keys
- Subscription state

MatterSwift supports multi-admin with per-fabric ACL enforcement and fabric-scoped attribute filtering.

## Sessions

Matter uses two types of secure sessions:

### PASE (Password-Authenticated Session Establishment)

Used during **commissioning**. The controller and device perform a SPAKE2+ key exchange using the device's setup passcode (the number from the QR code or manual pairing code). This establishes an encrypted session for provisioning credentials.

### CASE (Certificate-Authenticated Session Establishment)

Used for all **operational communication** after commissioning. Both sides authenticate using their Node Operational Certificates (mutual TLS-like handshake over the Sigma protocol). CASE sessions are long-lived and can be resumed using session tickets.

All messages after session establishment are encrypted with AES-128-CCM.

## Subscriptions and Reports

Controllers **subscribe** to attributes and events to receive updates when device state changes. A subscription defines:

- Which attributes/events to monitor (can use wildcards)
- **MinInterval**: Minimum seconds between reports (prevents flooding)
- **MaxInterval**: Maximum seconds between reports (keepalive)

The device sends a **priming report** immediately upon subscription with current values, then sends delta reports when attributes change. Urgent events (e.g., a door lock alarm) bypass the minInterval.

## TLV Encoding

All Matter protocol messages use **TLV (Tag-Length-Value)** binary encoding. TLV is similar to CBOR but simpler. It supports:

- Signed/unsigned integers (1-8 bytes, auto-sized)
- Booleans, null, UTF-8 strings, octet strings
- IEEE 754 floats and doubles
- Structures, arrays, and lists (container types)
- Context-specific tags (1 byte, used in most protocol messages)

MatterSwift's `MatterTypes` module provides complete TLV encoding and decoding. You generally don't need to work with TLV directly — the cluster handlers and Interaction Model layer handle serialisation automatically.

## Message Reliability Protocol (MRP)

Matter runs over UDP with its own reliability layer called MRP. Features include:

- Message counters for deduplication
- Acknowledgement piggyback (ACK the previous message in the next response)
- Standalone ACKs for one-way messages
- Retransmission with exponential backoff
- Exchange tracking (request/response pairs)

MRP is handled transparently by MatterSwift's protocol layer.
