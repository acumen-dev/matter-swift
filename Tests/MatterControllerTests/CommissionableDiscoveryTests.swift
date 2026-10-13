// CommissionableDiscoveryTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
@testable import MatterController
import MatterProtocol
import MatterTransport
import MatterTypes
import MatterTestSupport

@Suite("CommissionableDiscovery")
struct CommissionableDiscoveryTests {

    // MARK: - Fixtures

    /// Each record maps to a distinct documentation-range port so a test can
    /// tell which one was chosen.
    private static func makeDiscovery() -> InMemoryDiscovery {
        InMemoryDiscovery { record in MatterAddress(host: "::1", port: record.port) }
    }

    private static func makeController(_ discovery: InMemoryDiscovery) throws -> MatterController {
        try MatterController(
            transport: MockUDPTransport(),
            discovery: discovery,
            configuration: .init(fabricID: FabricID(rawValue: 1))
        )
    }

    private static func record(_ name: String, port: UInt16, txt: [String: String]) -> MatterServiceRecord {
        MatterServiceRecord(name: name, serviceType: .commissionable, host: "", port: port, txtRecords: txt)
    }

    /// The 11-digit test code (passcode 20202021, short discriminator 15),
    /// with its fields overridden as a QR code would carry them.
    private static func code(
        _ discriminator: SetupCode.Discriminator,
        vendorID: UInt16? = nil,
        productID: UInt16? = nil
    ) throws -> SetupCode {
        var code = try SetupCode(parsing: "34970112332")
        code.discriminator = discriminator
        code.vendorID = vendorID
        code.productID = productID
        return code
    }

    /// Bounds a search that is expected to succeed quickly; a hang guard only.
    private static let hangGuard: Duration = .seconds(10)

    // MARK: - Matching

    @Test("short discriminator skips wrong D and CM=0, takes MRP timing from TXT")
    func shortDiscriminator() async throws {
        let discovery = Self.makeDiscovery()
        try await discovery.advertise(service: Self.record("wrong-d", port: 5541, txt: ["D": "1234", "CM": "1"]))
        try await discovery.advertise(service: Self.record("closed", port: 5542, txt: ["D": "3840", "CM": "0"]))
        try await discovery.advertise(service: Self.record(
            "open", port: 5543, txt: ["D": "3841", "CM": "1", "SII": "5000", "SAI": "300"]))
        let controller = try Self.makeController(discovery)

        let device = try await controller.findCommissionable(try Self.code(.short(15)), timeout: Self.hangGuard)

        #expect(device.instanceName == "open")
        #expect(device.address == MatterAddress(host: "::1", port: 5543))
        #expect(device.discriminator == 3841)
        #expect(device.commissioningMode == 1)
        #expect(device.mrp.sessionIdleInterval == .milliseconds(5000))
        #expect(device.mrp.sessionActiveInterval == .milliseconds(300))
        #expect(device.mrp.sessionActiveThreshold == MRPParameters.default.sessionActiveThreshold)
        #expect(device.vendorID == nil)
        #expect(device.productID == nil)
        // TXT was on the browse records: rejected records were never resolved.
        #expect(discovery.resolveCount(name: "wrong-d") == 0)
        #expect(discovery.resolveCount(name: "closed") == 0)
        #expect(discovery.resolveCount(name: "open") == 1)
    }

    @Test("long discriminator rejects a record sharing only the upper 4 bits")
    func longDiscriminator() async throws {
        let discovery = Self.makeDiscovery()
        try await discovery.advertise(service: Self.record("same-upper", port: 5541, txt: ["D": "3841", "CM": "1"]))
        try await discovery.advertise(service: Self.record("exact", port: 5542, txt: ["D": "3840", "CM": "2"]))
        let controller = try Self.makeController(discovery)

        let device = try await controller.findCommissionable(try Self.code(.long(3840)), timeout: Self.hangGuard)

        #expect(device.instanceName == "exact")
        #expect(device.commissioningMode == 2)
    }

    @Test("a D that is not a 12-bit value never matches, even when its low 12 bits would")
    func outOfRangeDiscriminator() async throws {
        let discovery = Self.makeDiscovery()
        // 0x1F00 masks to 0xF00 = 3840.
        try await discovery.advertise(service: Self.record("too-wide", port: 5541, txt: ["D": "7936", "CM": "1"]))
        try await discovery.advertise(service: Self.record("not-a-number", port: 5542, txt: ["D": "abc", "CM": "1"]))
        try await discovery.advertise(service: Self.record("negative", port: 5543, txt: ["D": "-256", "CM": "1"]))
        try await discovery.advertise(service: Self.record("max", port: 5544, txt: ["D": "4095", "CM": "1"]))
        let controller = try Self.makeController(discovery)

        let device = try await controller.findCommissionable(try Self.code(.long(4095)), timeout: Self.hangGuard)
        #expect(device.instanceName == "max")

        await #expect(throws: ControllerError.commissionableNotFound("no commissionable device with discriminator 3840")) {
            try await controller.findCommissionable(try Self.code(.long(3840)), timeout: .milliseconds(200))
        }
    }

    @Test("an advertised VID or PID that differs (or does not parse) is skipped; a matching VP is taken")
    func vendorProductFilter() async throws {
        let discovery = Self.makeDiscovery()
        try await discovery.advertise(service: Self.record(
            "other-vendor", port: 5541, txt: ["D": "3840", "CM": "1", "VP": "65522+32768"]))
        try await discovery.advertise(service: Self.record(
            "other-product", port: 5542, txt: ["D": "3840", "CM": "1", "VP": "65521+32769"]))
        try await discovery.advertise(service: Self.record(
            "other-vendor-no-pid", port: 5543, txt: ["D": "3840", "CM": "1", "VP": "65522"]))
        try await discovery.advertise(service: Self.record(
            "garbled", port: 5544, txt: ["D": "3840", "CM": "1", "VP": "x+32768"]))
        try await discovery.advertise(service: Self.record(
            "right", port: 5545, txt: ["D": "3840", "CM": "1", "VP": "65521+32768"]))
        let controller = try Self.makeController(discovery)

        let device = try await controller.findCommissionable(
            try Self.code(.long(3840), vendorID: 0xFFF1, productID: 0x8000), timeout: Self.hangGuard)

        #expect(device.instanceName == "right")
        #expect(device.vendorID == 0xFFF1)
        #expect(device.productID == 0x8000)
    }

    @Test(
        "an absent VP, or a VP without its PID part, is unknown and passes a code carrying VID+PID",
        arguments: [nil, "65521"] as [String?]
    )
    func absentVendorProductPasses(vp: String?) async throws {
        let discovery = Self.makeDiscovery()
        try await discovery.advertise(service: Self.record(
            "other-vendor", port: 5541, txt: ["D": "3840", "CM": "1", "VP": "65522+32768"]))
        var txt = ["D": "3840", "CM": "1"]
        txt["VP"] = vp
        try await discovery.advertise(service: Self.record("partial", port: 5542, txt: txt))
        let controller = try Self.makeController(discovery)

        let device = try await controller.findCommissionable(
            try Self.code(.long(3840), vendorID: 0xFFF1, productID: 0x8000), timeout: Self.hangGuard)

        #expect(device.instanceName == "partial")
        #expect(device.vendorID == vp.map { _ in 0xFFF1 })
        #expect(device.productID == nil)
    }

    @Test("a code without VID/PID does not filter on VP, but the device still reports it")
    func noVendorInCode() async throws {
        let discovery = Self.makeDiscovery()
        try await discovery.advertise(service: Self.record(
            "device", port: 5541, txt: ["D": "3840", "CM": "1", "VP": "65521"]))
        let controller = try Self.makeController(discovery)

        let device = try await controller.findCommissionable(try Self.code(.short(15)), timeout: Self.hangGuard)

        #expect(device.vendorID == 0xFFF1)
        #expect(device.productID == nil)
    }

    @Test("two devices matching a short discriminator: the first browsed wins, the other is never resolved")
    func shortDiscriminatorFirstWins() async throws {
        let discovery = Self.makeDiscovery()
        try await discovery.advertise(service: Self.record("first", port: 5541, txt: ["D": "3850", "CM": "1"]))
        try await discovery.advertise(service: Self.record("second", port: 5542, txt: ["D": "3860", "CM": "1"]))
        let controller = try Self.makeController(discovery)

        let device = try await controller.findCommissionable(try Self.code(.short(15)), timeout: Self.hangGuard)

        #expect(device.instanceName == "first")
        #expect(discovery.resolveCount(name: "second") == 0)
    }

    // MARK: - Browse Without TXT

    @Test("records browsed without TXT are matched through resolveService, resolved once")
    func browseWithoutTXT() async throws {
        let discovery = Self.makeDiscovery()
        discovery.setBrowseTXTHidden(true)
        try await discovery.advertise(service: Self.record("wrong-d", port: 5541, txt: ["D": "1234", "CM": "1"]))
        try await discovery.advertise(service: Self.record(
            "match", port: 5542, txt: ["D": "3840", "CM": "1", "SII": "5000"]))
        let controller = try Self.makeController(discovery)

        let device = try await controller.findCommissionable(try Self.code(.long(3840)), timeout: Self.hangGuard)

        #expect(device.instanceName == "match")
        #expect(device.address == MatterAddress(host: "::1", port: 5542))
        #expect(device.mrp.sessionIdleInterval == .milliseconds(5000))
        #expect(device.txtRecords["D"] == "3840")
        #expect(discovery.resolveCount(name: "match") == 1)
    }

    // MARK: - Timing

    @Test("no match within the timeout throws commissionableNotFound naming the discriminator")
    func notFound() async throws {
        let discovery = Self.makeDiscovery()
        try await discovery.advertise(service: Self.record("other", port: 5541, txt: ["D": "1234", "CM": "1"]))
        let controller = try Self.makeController(discovery)

        do {
            _ = try await controller.findCommissionable(try Self.code(.long(3840)), timeout: .milliseconds(200))
            Issue.record("expected commissionableNotFound")
        } catch let error as ControllerError {
            guard case .commissionableNotFound(let message) = error else {
                Issue.record("unexpected error \(error)")
                return
            }
            #expect(message.contains("3840"))
            #expect(!message.contains("::1"))
            #expect(!message.contains("20202021"))
        }
    }

    @Test("a browse that ends before a match throws discoveryFailed, not commissionableNotFound")
    func browseEnds() async throws {
        let discovery = Self.makeDiscovery()
        let controller = try Self.makeController(discovery)
        let code = try Self.code(.long(3840))

        let search = Task { try await controller.findCommissionable(code, timeout: Self.hangGuard) }
        try await Self.awaitBrowse(discovery)
        discovery.finishBrowsing()

        await #expect(throws: ControllerError.discoveryFailed("browse ended before a match")) {
            try await search.value
        }
    }

    @Test("the deadline cancels an in-flight resolve, and buffered records are not processed after it")
    func deadlineCancelsResolve() async throws {
        let inner = Self.makeDiscovery()
        try await inner.advertise(service: Self.record("slow", port: 5541, txt: ["D": "3840", "CM": "1"]))
        try await inner.advertise(service: Self.record("after", port: 5542, txt: ["D": "3840", "CM": "1"]))
        let discovery = SuspendingResolveDiscovery(inner: inner, suspending: "slow", hangGuard: Self.hangGuard)
        let controller = try MatterController(
            transport: MockUDPTransport(),
            discovery: discovery,
            configuration: .init(fabricID: FabricID(rawValue: 1))
        )

        // If the deadline did not cancel the resolve, it would complete after
        // the hang guard and "slow" would be returned instead.
        await #expect(throws: ControllerError.commissionableNotFound("no commissionable device with discriminator 3840")) {
            try await controller.findCommissionable(try Self.code(.long(3840)), timeout: .milliseconds(200))
        }
        #expect(discovery.resolveCancelled)
        #expect(inner.resolveCount(name: "after") == 0)
    }

    /// Wait (bounded by the hang guard) until a browse stream is open.
    private static func awaitBrowse(_ discovery: InMemoryDiscovery) async throws {
        let deadline = ContinuousClock.now + Self.hangGuard
        while discovery.activeBrowseCount == 0, ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(5))
        }
        try #require(discovery.activeBrowseCount == 1)
    }

    @Test("a record advertised after the browse starts is found")
    func lateAdvertisement() async throws {
        let discovery = Self.makeDiscovery()
        let controller = try Self.makeController(discovery)
        let code = try Self.code(.long(3840))

        let search = Task { try await controller.findCommissionable(code, timeout: Self.hangGuard) }
        // Advertise only once the browse is registered, so the live-yield path
        // (not the current-records path) is what finds it. Bounded by the
        // same hang guard as the search.
        try await Self.awaitBrowse(discovery)
        try await discovery.advertise(service: Self.record("late", port: 5541, txt: ["D": "3840", "CM": "1"]))

        let device = try await search.value
        #expect(device.instanceName == "late")
        #expect(discovery.activeBrowseCount == 0)
    }
}

// MARK: - Suspending Resolve

/// Delegates to an `InMemoryDiscovery`, except that resolving the instance
/// `suspending` waits until cancelled. If it is never cancelled, it resolves
/// normally after `hangGuard`, so a missed cancellation shows as a result.
private final class SuspendingResolveDiscovery: ServiceDiscovery, Sendable {
    private let inner: InMemoryDiscovery
    private let suspending: String
    private let hangGuard: Duration
    private let cancelled = LockedValue(false)

    init(inner: InMemoryDiscovery, suspending: String, hangGuard: Duration) {
        self.inner = inner
        self.suspending = suspending
        self.hangGuard = hangGuard
    }

    var resolveCancelled: Bool { cancelled.value }

    func advertise(service: ServiceRecord) async throws {
        try await inner.advertise(service: service)
    }

    func browse(serviceType: ServiceType) -> AsyncStream<ServiceRecord> {
        inner.browse(serviceType: serviceType)
    }

    func resolve(_ record: ServiceRecord) async throws -> NetworkAddress {
        try await resolveService(record).address
    }

    func resolveService(_ record: ServiceRecord) async throws -> ResolvedService {
        if record.name == suspending {
            do {
                try await Task.sleep(for: hangGuard)
            } catch {
                cancelled.withLock { $0 = true }
                throw error
            }
        }
        return try await inner.resolveService(record)
    }

    func stopAdvertising() async {
        await inner.stopAdvertising()
    }

    func stopAdvertising(name: String) async {
        await inner.stopAdvertising(name: name)
    }
}
