// JSONFileStore.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

/// JSON file-based fabric store.
///
/// Persists device-side fabric state to a JSON file with atomic writes.
///
/// The file holds each fabric's operational private key and IPK epoch key, so it is written
/// owner-only (`0600`), exactly as ``JSONFileControllerStore`` does.
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
        try OwnerOnlyFile.replace(data, to: fileURL)
    }
}

/// JSON file-based controller store.
///
/// Persists controller-side identity and device registry to a JSON file.
///
/// The file holds the fabric root CA private key, the controller's operational key and
/// the IPK epoch key, so it is written owner-only (`0600`). A save creates a temporary
/// file in the same directory with mode `0600` before writing any bytes, then renames it
/// over the target: there is no moment at which the secrets are readable by others, and
/// a save also tightens an existing file that was more permissive. The containing
/// directory is created if missing but its permissions are the caller's concern.
///
/// The file is **plaintext JSON**: it is meant for standalone or development use. A
/// production embedder should supply its own ``MatterControllerStore`` (encrypted, in its
/// own secret store) rather than keep the root CA key in a file.
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
        try OwnerOnlyFile.replace(data, to: fileURL)
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

// MARK: - Owner-only writes

/// Writes a file readable by its owner only, with no window in which it is more open.
enum OwnerOnlyFile {

    /// Write `data` to a new `0600` file beside `url` and rename it into place.
    /// The temporary file is created `0600` (`O_EXCL`) before any byte is written.
    static func replace(_ data: Data, to url: URL) throws {
        let tempPath = url.deletingLastPathComponent()
            .appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp").path
        // O_EXCL: never write through a pre-existing (or planted) file; mode 0600 at creation.
        let fd = open(tempPath, O_WRONLY | O_CREAT | O_EXCL, 0o600)
        guard fd >= 0 else { throw posixError(errno, "create \(tempPath)") }
        do {
            // The umask can only remove bits, but be explicit about the final mode.
            guard fchmod(fd, 0o600) == 0 else { throw posixError(errno, "chmod \(tempPath)") }
            try data.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) in
                var offset = 0
                while offset < buffer.count {
                    let n = write(fd, buffer.baseAddress! + offset, buffer.count - offset)
                    if n < 0 {
                        if errno == EINTR { continue }
                        throw posixError(errno, "write \(tempPath)")
                    }
                    offset += n
                }
            }
            guard fsync(fd) == 0 else { throw posixError(errno, "fsync \(tempPath)") }
        } catch {
            close(fd)
            unlink(tempPath)
            throw error
        }
        guard close(fd) == 0 else {
            let code = errno
            unlink(tempPath)
            throw posixError(code, "close \(tempPath)")
        }
        guard rename(tempPath, url.path) == 0 else {
            let code = errno
            unlink(tempPath)
            throw posixError(code, "rename \(tempPath)")
        }
    }

    private static func posixError(_ code: Int32, _ what: String) -> any Error {
        NSError(
            domain: NSPOSIXErrorDomain, code: Int(code),
            userInfo: [NSLocalizedDescriptionKey: "\(what): \(String(cString: strerror(code)))"])
    }
}
