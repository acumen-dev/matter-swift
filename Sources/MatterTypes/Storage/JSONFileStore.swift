// JSONFileStore.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

/// JSON file-based fabric store.
///
/// Persists device-side fabric state to a JSON file with atomic writes.
///
/// ```swift
/// let store = JSONFileFabricStore(
///     directory: URL(filePath: "~/.config/swift-matter")
/// )
/// ```
public actor JSONFileFabricStore: MatterFabricStore {

    private let fileURL: URL
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    /// Create a fabric store writing to the specified directory.
    ///
    /// - Parameters:
    ///   - directory: Directory for the JSON file. Created if it doesn't exist.
    ///   - filename: Name of the JSON file (default: "fabrics.json").
    public init(directory: URL, filename: String = "fabrics.json") {
        self.fileURL = directory.appendingPathComponent(filename)
        self.encoder = JSONEncoder()
        self.encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        self.decoder = JSONDecoder()
    }

    public func load() async throws -> StoredDeviceState? {
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return nil
        }
        let data = try Data(contentsOf: fileURL)
        return try decoder.decode(StoredDeviceState.self, from: data)
    }

    public func save(_ state: StoredDeviceState) async throws {
        let data = try encoder.encode(state)
        let dir = fileURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true
        )
        try data.write(to: fileURL, options: .atomic)
    }
}

/// JSON file-based controller store.
///
/// Persists controller-side identity and device registry to a JSON file.
///
/// ```swift
/// let store = JSONFileControllerStore(
///     directory: URL(filePath: "~/.config/swift-matter")
/// )
/// ```
public actor JSONFileControllerStore: MatterControllerStore {

    private let fileURL: URL
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    /// Create a controller store writing to the specified directory.
    ///
    /// - Parameters:
    ///   - directory: Directory for the JSON file. Created if it doesn't exist.
    ///   - filename: Name of the JSON file (default: "controller.json").
    public init(directory: URL, filename: String = "controller.json") {
        self.fileURL = directory.appendingPathComponent(filename)
        self.encoder = JSONEncoder()
        self.encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        self.decoder = JSONDecoder()
    }

    public func load() async throws -> StoredControllerState? {
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return nil
        }
        let data = try Data(contentsOf: fileURL)
        return try decoder.decode(StoredControllerState.self, from: data)
    }

    public func save(_ state: StoredControllerState) async throws {
        let data = try encoder.encode(state)
        let dir = fileURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true
        )
        try data.write(to: fileURL, options: .atomic)
    }
}

/// JSON file-based attribute store.
///
/// Persists device-side attribute values to a JSON file.
///
/// ```swift
/// let store = JSONFileAttributeStore(
///     directory: URL(filePath: "~/.config/swift-matter")
/// )
/// ```
public actor JSONFileAttributeStore: MatterAttributeStore {

    private let fileURL: URL
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    /// Create an attribute store writing to the specified directory.
    ///
    /// - Parameters:
    ///   - directory: Directory for the JSON file. Created if it doesn't exist.
    ///   - filename: Name of the JSON file (default: "attributes.json").
    public init(directory: URL, filename: String = "attributes.json") {
        self.fileURL = directory.appendingPathComponent(filename)
        self.encoder = JSONEncoder()
        self.encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        self.decoder = JSONDecoder()
    }

    public func load() async throws -> StoredAttributeData? {
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return nil
        }
        let data = try Data(contentsOf: fileURL)
        return try decoder.decode(StoredAttributeData.self, from: data)
    }

    public func save(_ data: StoredAttributeData) async throws {
        let encoded = try encoder.encode(data)
        let dir = fileURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true
        )
        try encoded.write(to: fileURL, options: .atomic)
    }
}
