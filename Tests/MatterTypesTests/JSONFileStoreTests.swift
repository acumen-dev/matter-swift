// JSONFileStoreTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
@testable import MatterTypes

@Suite("JSON file stores are owner-only")
struct JSONFileStoreTests {

    static func tempDirectory() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("json-store-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    static func permissions(of url: URL) throws -> Int {
        let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs[.posixPermissions] as? NSNumber)?.intValue ?? -1
    }

    static let state = StoredDeviceState(
        fabrics: [StoredFabric(
            fabricIndex: 1, nocTLV: Data([1]), icacTLV: nil, rcacTLV: Data([2]),
            operationalKeyRaw: Data(repeating: 7, count: 32), ipkEpochKey: Data(repeating: 8, count: 16),
            caseAdminSubject: 1, adminVendorId: 0xFFF1)])

    @Test("a fabric store file is created 0600 and round-trips")
    func newFileIs0600() async throws {
        let dir = try Self.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = JSONFileFabricStore(directory: dir)
        try await store.save(Self.state)
        #expect(try Self.permissions(of: dir.appendingPathComponent("fabrics.json")) == 0o600)
        #expect(try await store.load() == Self.state)
        #expect(try FileManager.default.contentsOfDirectory(atPath: dir.path) == ["fabrics.json"])
    }

    @Test("a fabric store save tightens an existing 0644 file")
    func existingFileTightened() async throws {
        let dir = try Self.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("fabrics.json")
        try Data("{}".utf8).write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: file.path)
        let store = JSONFileFabricStore(directory: dir)
        try await store.save(Self.state)
        #expect(try Self.permissions(of: file) == 0o600)
        #expect(try await store.load() == Self.state)
    }
}
