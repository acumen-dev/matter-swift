// swift-tools-version:6.1
// Package.swift
// Copyright 2026 Monagle Pty Ltd

import PackageDescription

let package = Package(
    name: "MatterModelGenerator",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "MatterModelGenerator"
        )
    ]
)
