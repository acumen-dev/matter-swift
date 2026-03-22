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
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.0.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.0.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.0.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.0.0"),
        .package(url: "https://github.com/apple/swift-collections.git", from: "1.1.0"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
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
            ]
        ),

        // MARK: - Transport Abstractions

        .target(
            name: "MatterTransport",
            dependencies: [
                "MatterTypes",
                .product(name: "Logging", package: "swift-log"),
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
            ]
        ),

        // MARK: - Platform: Apple
        // Note: MatterCrypto not needed here — crypto lives in the MatterCrypto module.

        .target(
            name: "MatterApple",
            dependencies: [
                "MatterTransport",
                .product(name: "Logging", package: "swift-log"),
            ]
        ),

        // MARK: - Platform: Linux (SwiftNIO)

        .target(
            name: "MatterLinux",
            dependencies: [
                "MatterTransport",
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "Logging", package: "swift-log"),
            ]
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
            dependencies: ["MatterCrypto"]
        ),
        .testTarget(
            name: "MatterProtocolTests",
            dependencies: ["MatterProtocol", "MatterCrypto", "MatterTransport"]
        ),
        .testTarget(
            name: "MatterDeviceTests",
            dependencies: ["MatterDevice", "MatterCrypto", "MatterProtocol", "MatterTransport"]
        ),
        .testTarget(
            name: "MatterControllerTests",
            dependencies: ["MatterController", "MatterModel", "MatterCrypto", "MatterTransport"]
        ),
        .testTarget(
            name: "MatterAppleTests",
            dependencies: [
                .target(name: "MatterApple",
                        condition: .when(platforms: [.macOS, .iOS, .tvOS, .watchOS, .visionOS])),
                "MatterTransport",
            ]
        ),
        .testTarget(
            name: "MatterLinuxTests",
            dependencies: ["MatterLinux", "MatterTransport"]
        ),
        .testTarget(
            name: "IntegrationTests",
            dependencies: [
                "MatterDevice",
                "MatterController",
                .target(name: "MatterApple",
                        condition: .when(platforms: [.macOS, .iOS, .tvOS, .watchOS, .visionOS])),
                "MatterCrypto",
                "MatterProtocol",
                "MatterTransport",
                "MatterModel",
                "MatterTypes",
            ]
        ),
        .testTarget(
            name: "ReferenceTests",
            dependencies: [
                "MatterCrypto",
                "MatterTypes",
            ],
            path: "Tests/ReferenceTests"
        ),
    ]
)
