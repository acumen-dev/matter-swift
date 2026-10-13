// RealMDNSDiscriminators.swift
// Copyright 2026 Monagle Pty Ltd

/// The discriminators test suites advertise commissionable devices under on
/// the host's real mDNS, all with the CHIP test passcode, possibly while
/// other suites run. A suite that finds a device by setup code over real
/// mDNS must avoid these, and a manual code's *short* discriminator (the
/// top four bits) too, or it can find another suite's device first.
public enum RealMDNSDiscriminators {
    /// The CHIP SDK default: `ChipAppRunner`'s default, `LoopbackTests`,
    /// `AppleDiscoveryTests`.
    public static let chipDefault: UInt16 = 3840
    /// `ChipToolIntegrationTests`' device server.
    public static let chipToolBridge: UInt16 = 840
    /// `AppleDiscoveryTests`' browse record.
    public static let browseTest: UInt16 = 1234

    /// Every discriminator above.
    public static let all: [UInt16] = [chipDefault, chipToolBridge, browseTest]

    /// The short (manual-code) discriminators of `all`.
    public static var shortForms: Set<UInt16> { Set(all.map { $0 >> 8 }) }
}
