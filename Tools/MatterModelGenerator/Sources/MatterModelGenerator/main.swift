// main.swift
// MatterModelGenerator
// Copyright 2026 Monagle Pty Ltd

import Foundation

// MARK: - CLI Argument Parsing

func printUsage() {
    print("""
    Usage: MatterModelGenerator --input <data_model_dir> --output <generated_dir>

    Arguments:
      --input   Path to the connectedhomeip data_model/1.4 directory
      --output  Path to the Generated/ output directory in MatterModel

    Example:
      MatterModelGenerator \\
        --input /tmp/swift-matter-refimpl/connectedhomeip-v1.4.0.0/data_model/1.4 \\
        --output ../../Sources/MatterModel/Generated
    """)
}

var inputDir: String?
var outputDir: String?

var args = CommandLine.arguments.dropFirst().makeIterator()
while let arg = args.next() {
    switch arg {
    case "--input":
        inputDir = args.next()
    case "--output":
        outputDir = args.next()
    case "--help", "-h":
        printUsage()
        exit(0)
    default:
        print("Unknown argument: \(arg)")
        printUsage()
        exit(1)
    }
}

guard let inputDir, let outputDir else {
    print("Error: --input and --output are required")
    printUsage()
    exit(1)
}

let inputURL = URL(fileURLWithPath: inputDir)
let outputURL = URL(fileURLWithPath: outputDir)
let clustersInputDir = inputURL.appendingPathComponent("clusters")
let deviceTypesInputDir = inputURL.appendingPathComponent("device_types")

// Validate input directories exist
guard FileManager.default.fileExists(atPath: clustersInputDir.path) else {
    print("Error: clusters directory not found at \(clustersInputDir.path)")
    exit(1)
}

// MARK: - Parse Clusters

print("Parsing cluster definitions from \(clustersInputDir.path)...")

let clusterFiles = try FileManager.default.contentsOfDirectory(
    at: clustersInputDir,
    includingPropertiesForKeys: nil
).filter { $0.pathExtension == "xml" }
.sorted(by: { $0.lastPathComponent < $1.lastPathComponent })

var clusters: [ClusterDefinition] = []
var parseErrors: [String] = []

for file in clusterFiles {
    do {
        if let cluster = try XMLClusterParser.parse(contentsOf: file) {
            clusters.append(cluster)
        }
    } catch {
        parseErrors.append("\(file.lastPathComponent): \(error)")
    }
}

print("  Parsed \(clusters.count) clusters from \(clusterFiles.count) XML files")
if !parseErrors.isEmpty {
    print("  Errors: \(parseErrors.count)")
    for err in parseErrors {
        print("    - \(err)")
    }
}

// MARK: - Parse Device Types

var deviceTypes: [DeviceTypeDefinition] = []

if FileManager.default.fileExists(atPath: deviceTypesInputDir.path) {
    print("Parsing device type definitions from \(deviceTypesInputDir.path)...")

    let deviceTypeFiles = try FileManager.default.contentsOfDirectory(
        at: deviceTypesInputDir,
        includingPropertiesForKeys: nil
    ).filter { $0.pathExtension == "xml" }
    .sorted(by: { $0.lastPathComponent < $1.lastPathComponent })

    for file in deviceTypeFiles {
        do {
            if let dt = try XMLDeviceTypeParser.parse(contentsOf: file) {
                deviceTypes.append(dt)
            }
        } catch {
            parseErrors.append("\(file.lastPathComponent): \(error)")
        }
    }

    print("  Parsed \(deviceTypes.count) device types from \(deviceTypeFiles.count) XML files")
}

// MARK: - Generate Swift Source

print("Generating Swift source to \(outputURL.path)...")

try FileManager.default.createDirectory(at: outputURL, withIntermediateDirectories: true)

let sourceRef = "data_model/\(inputURL.lastPathComponent)"

try SwiftCodeGenerator.generate(
    clusters: clusters,
    deviceTypes: deviceTypes,
    outputDir: outputURL,
    sourceDir: sourceRef
)

// Count generated files
let generatedFiles = try FileManager.default.contentsOfDirectory(
    at: outputURL.appendingPathComponent("Clusters"),
    includingPropertiesForKeys: nil
).filter { $0.pathExtension == "swift" }

let skippedCount = SwiftCodeGenerator.skipClusters.count
let generatedCount = generatedFiles.count

print("  Generated \(generatedCount) cluster files (skipped \(skippedCount) hand-written clusters)")
print("  Generated ClusterDefinitions.generated.swift (\(clusters.count) cluster IDs, \(deviceTypes.count) device type IDs)")
print("Done.")
