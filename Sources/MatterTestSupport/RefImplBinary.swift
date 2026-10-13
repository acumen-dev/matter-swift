// RefImplBinary.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

// MARK: - RefImplBinary

/// Locates binaries built from the connectedhomeip reference implementation
/// under `Tools/RefImpl/bin`, relative to the package root.
public enum RefImplBinary {

    /// The URL of the named executable, or `nil` if it has not been built.
    ///
    /// Tests that need the binary skip silently when this returns `nil`.
    public static func find(_ name: String, sourceFile: String = #filePath) -> URL? {
        let packageRoot = URL(fileURLWithPath: sourceFile)
            .deletingLastPathComponent()  // MatterTestSupport/
            .deletingLastPathComponent()  // Sources/
            .deletingLastPathComponent()  // package root
        let url = packageRoot.appendingPathComponent("Tools/RefImpl/bin/\(name)")
        return FileManager.default.isExecutableFile(atPath: url.path) ? url : nil
    }
}
