// swift-tools-version:6.1
import PackageDescription

let package = Package(
    name: "matter-swift",
    platforms: [
        .macOS(.v15),
        .iOS(.v18),
        .tvOS(.v18),
        .watchOS(.v11),
        .visionOS(.v2),
    ],
    products: [
        // Core types and TLV encoding — zero external dependencies
        .library(name: "MatterTypes", targets: ["MatterTypes"]),
        // Cluster definitions, device types, attribute schemas
        .library(name: "MatterModel", targets: ["MatterModel"]),
        // SPAKE2+, CASE/Sigma, AES-128-CCM, certificates
        .library(name: "MatterCrypto", targets: ["MatterCrypto"]),
        // Wire protocol: MRP, sessions, Interaction Model
        .library(name: "MatterProtocol", targets: ["MatterProtocol"]),
        // Device/bridge role: endpoint management, attribute storage
        .library(name: "MatterDevice", targets: ["MatterDevice"]),
        // Conformance suite for MatterControllerStore implementations. Link ONLY from test targets.
        .library(name: "MatterStoreConformance", targets: ["MatterStoreConformance"]),
        // Controller role: commissioning, device management
        .library(name: "MatterController", targets: ["MatterController"]),
        // Platform-agnostic transport protocol abstractions
        .library(name: "MatterTransport", targets: ["MatterTransport"]),
        // Apple platform transport (Network.framework, CryptoKit)
        .library(name: "MatterApple", targets: ["MatterApple"]),
        // Linux platform transport (SwiftNIO, pure-Swift mDNS)
        .library(name: "MatterLinux", targets: ["MatterLinux"]),
        // Convenience: re-exports everything for typical use
        .library(name: "MatterSwift", targets: ["MatterSwift"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "5.0.3"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.21.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.0.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-collections.git", from: "1.1.0"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
        .package(url: "https://github.com/acumen-dev/mdns-swift.git", from: "1.2.0"),
        // Floors are the API minimums (factory-taking metric inits; InMemoryTracing). Their
        // 6.2-only releases (metrics 2.12, tracing 1.6+) resolve on Swift 6.2 toolchains.
        .package(url: "https://github.com/apple/swift-metrics.git", from: "2.7.0"),
        .package(url: "https://github.com/apple/swift-distributed-tracing.git", from: "1.3.0"),
    ],
    targets: [
        // MARK: - Core Types

        .target(
            name: "MatterTypes",
            dependencies: []
        ),

        // MARK: - Data Model

        .target(
            name: "MatterModel",
            dependencies: [
                "MatterTypes",
            ]
        ),

        // MARK: - Cryptography

        .target(
            name: "MatterCrypto",
            dependencies: [
                "MatterTypes",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ],
            resources: [.copy("Resources/Attestation")]
        ),

        // MARK: - Transport Abstractions

        // Thin C shim for sendmsg/recvmsg with PKTINFO control messages (per-peer
        // interface / source-address pinning). Not a product.
        .target(
            name: "CMatterSockets",
            dependencies: [],
            cSettings: [
                // Darwin's module build ignores an in-source define; pass it on the command line.
                .define("__APPLE_USE_RFC_3542", to: "1", .when(platforms: [.macOS, .iOS, .tvOS, .watchOS, .visionOS])),
                .define("_GNU_SOURCE", .when(platforms: [.linux])),
            ]
        ),

        .target(
            name: "MatterTransport",
            dependencies: [
                "MatterTypes",
                "CMatterSockets",
                .product(name: "Logging", package: "swift-log"),
                .product(name: "MDNSCore", package: "mdns-swift"),
            ]
        ),

        // MARK: - Wire Protocol

        .target(
            name: "MatterProtocol",
            dependencies: [
                "MatterTypes",
                "MatterModel",
                "MatterCrypto",
                "MatterTransport",
                .product(name: "Logging", package: "swift-log"),
                .product(name: "Collections", package: "swift-collections"),
            ]
        ),

        // MARK: - Device / Bridge Role

        .target(
            name: "MatterDevice",
            dependencies: [
                "MatterTypes",
                "MatterModel",
                "MatterCrypto",
                "MatterProtocol",
                "MatterTransport",
                .product(name: "Logging", package: "swift-log"),
            ]
        ),

        // MARK: - Controller Role

        .target(
            name: "MatterController",
            dependencies: [
                "MatterTypes",
                "MatterModel",
                "MatterCrypto",
                "MatterProtocol",
                "MatterTransport",
                .product(name: "Logging", package: "swift-log"),
                .product(name: "Metrics", package: "swift-metrics"),
                .product(name: "Tracing", package: "swift-distributed-tracing"),
            ]
        ),

        // MARK: - Platform: Apple
        // Note: MatterCrypto not needed here — crypto lives in the MatterCrypto module.

        .target(
            name: "MatterApple",
            dependencies: [
                "MatterTransport",
                .product(name: "Logging", package: "swift-log"),
                .product(name: "MDNSApple", package: "mdns-swift"),
            ]
        ),

        // MARK: - Platform: Linux
        // The UDP transport is POSIXUDPSocketCore (MatterTransport); mDNS discovery
        // (MDNSLinux) still runs on SwiftNIO.

        .target(
            name: "MatterLinux",
            dependencies: [
                "MatterTransport",
                .product(name: "Logging", package: "swift-log"),
                .product(name: "MDNSLinux", package: "mdns-swift"),
            ]
        ),

        // MARK: - Test Support

        // Deterministic clock, fault-injecting in-memory link and frame helpers
        // for messaging tests. Pure Swift: runs on Linux and Apple platforms.
        // Not a product.
        .target(
            name: "MatterTestSupport",
            dependencies: [
                "MatterTypes",
                "MatterCrypto",
                "MatterProtocol",
                "MatterTransport",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "MetricsTestKit", package: "swift-metrics"),
                .product(name: "Tracing", package: "swift-distributed-tracing"),
                .product(name: "InMemoryTracing", package: "swift-distributed-tracing"),
            ]
        ),

        // Store conformance suite: a library product, but link it only from
        // test targets (it imports Testing).
        .target(
            name: "MatterStoreConformance",
            dependencies: ["MatterTypes"]
        ),

        // MARK: - Convenience Re-export

        .target(
            name: "MatterSwift",
            dependencies: [
                "MatterTypes",
                "MatterModel",
                "MatterCrypto",
                "MatterProtocol",
                "MatterDevice",
                "MatterController",
                "MatterTransport",
                .target(name: "MatterApple",
                        condition: .when(platforms: [.macOS, .iOS, .tvOS, .watchOS, .visionOS])),
                .target(name: "MatterLinux",
                        condition: .when(platforms: [.linux])),
            ]
        ),

        // MARK: - Tests

        .testTarget(
            name: "MatterTypesTests",
            dependencies: ["MatterTypes"]
        ),
        .testTarget(
            name: "MatterModelTests",
            dependencies: ["MatterModel", "MatterTypes"]
        ),
        .testTarget(
            name: "MatterCryptoTests",
            dependencies: [
                "MatterCrypto",
                "MatterTypes",
                "MatterTestSupport",
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .testTarget(
            name: "MatterProtocolTests",
            dependencies: [
                "MatterProtocol", "MatterCrypto", "MatterTransport", "MatterTypes", "MatterTestSupport",
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .testTarget(
            name: "MatterDeviceTests",
            dependencies: [
                "MatterDevice", "MatterCrypto", "MatterModel", "MatterProtocol", "MatterTransport",
                "MatterTypes", "MatterTestSupport",
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .testTarget(
            name: "MatterControllerTests",
            dependencies: [
                "MatterController", "MatterModel", "MatterCrypto", "MatterTransport",
                "MatterProtocol", "MatterTypes", "MatterTestSupport", "MatterStoreConformance",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "Metrics", package: "swift-metrics"),
                .product(name: "MetricsTestKit", package: "swift-metrics"),
                .product(name: "Tracing", package: "swift-distributed-tracing"),
                .product(name: "InMemoryTracing", package: "swift-distributed-tracing"),
            ]
        ),
        .testTarget(
            name: "MatterTransportTests",
            dependencies: ["MatterTransport", "CMatterSockets", "MatterTestSupport"]
        ),
        .testTarget(
            name: "MatterAppleTests",
            dependencies: [
                .target(name: "MatterApple",
                        condition: .when(platforms: [.macOS, .iOS, .tvOS, .watchOS, .visionOS])),
                "MatterTransport",
                "MatterTestSupport",
            ]
        ),
        .testTarget(
            name: "MatterLinuxTests",
            dependencies: [
                "MatterLinux",
                "MatterTransport",
                "MatterTestSupport",
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "MDNSLinux", package: "mdns-swift"),
            ]
        ),
        .testTarget(
            name: "IntegrationTests",
            dependencies: [
                "MatterDevice",
                "MatterController",
                .target(name: "MatterApple",
                        condition: .when(platforms: [.macOS, .iOS, .tvOS, .watchOS, .visionOS])),
                .target(name: "MatterLinux",
                        condition: .when(platforms: [.linux])),
                "MatterCrypto",
                "MatterProtocol",
                "MatterTransport",
                "MatterModel",
                "MatterTypes",
                "MatterTestSupport",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ]
        ),
        .testTarget(
            name: "ReferenceTests",
            dependencies: [
                "MatterCrypto",
                "MatterDevice",
                "MatterTypes",
                "MatterTestSupport",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
            ],
            path: "Tests/ReferenceTests"
        ),
    ]
)
