// CommissionableDiscoveryTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
@testable import MatterController
import MatterProtocol
import MatterTransport
import MatterTypes
import MatterTestSupport

/// Every search here runs on a `ManualClock`, so no deadline falls on a
/// host's schedule: a search expected to match runs on a clock that never
/// moves (its deadline cannot fire), and a test of a deadline advances the
/// clock once the controller is waiting on it. The suite's `.timeLimit` is
/// the only hang guard.
@Suite("CommissionableDiscovery", .timeLimit(.minutes(1)))
struct CommissionableDiscoveryTests {

    // MARK: - Fixtures

    /// Each record maps to a distinct documentation-range port so a test can
    /// tell which one was chosen.
    private static func makeDiscovery() -> InMemoryDiscovery {
        InMemoryDiscovery { record in MatterAddress(host: "::1", port: record.port) }
    }

    /// A controller whose discovery deadlines run on `clock` (by default one
    /// that never moves).
    private static func makeController(
        _ discovery: any ServiceDiscovery,
        clock: ManualClock = ManualClock(),
        commissionableResolveTimeout: Duration = .seconds(5)
    ) throws -> MatterController {
        try MatterController(
            transport: MockUDPTransport(),
            discovery: discovery,
            configuration: .init(
                fabricID: FabricID(rawValue: 1),
                commissionableResolveTimeout: commissionableResolveTimeout,
                discoveryClock: clock
            )
        )
    }

    /// A clock for a test that fires a one-shot deadline: after a step,
    /// `advance(by:)` would otherwise yield-wait for that sleeper to re-arm,
    /// which it never does.
    private static func oneShotClock() -> ManualClock {
        ManualClock(quiescenceYieldLimit: 0)
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

    // MARK: - Matching

    @Test("short discriminator skips wrong D and CM=0, takes MRP timing from TXT")
    func shortDiscriminator() async throws {
        let discovery = Self.makeDiscovery()
        try await discovery.advertise(service: Self.record("wrong-d", port: 5541, txt: ["D": "1234", "CM": "1"]))
        try await discovery.advertise(service: Self.record("closed", port: 5542, txt: ["D": "3840", "CM": "0"]))
        try await discovery.advertise(service: Self.record(
            "open", port: 5543, txt: ["D": "3841", "CM": "1", "SII": "5000", "SAI": "300"]))
        let controller = try Self.makeController(discovery)

        let device = try await controller.findCommissionable(try Self.code(.short(15)))

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

        let device = try await controller.findCommissionable(try Self.code(.long(3840)))

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
        let clock = Self.oneShotClock()
        let controller = try Self.makeController(discovery, clock: clock)

        let device = try await controller.findCommissionable(try Self.code(.long(4095)))
        #expect(device.instanceName == "max")

        await #expect(throws: ControllerError.commissionableNotFound("no commissionable device with discriminator 3840")) {
            try await Self.searchUntilDeadline(controller, clock, try Self.code(.long(3840)))
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
            "garbled-pid", port: 5546, txt: ["D": "3840", "CM": "1", "VP": "65521+y"]))
        try await discovery.advertise(service: Self.record(
            "right", port: 5545, txt: ["D": "3840", "CM": "1", "VP": "65521+32768"]))
        let controller = try Self.makeController(discovery)

        let device = try await controller.findCommissionable(
            try Self.code(.long(3840), vendorID: 0xFFF1, productID: 0x8000))

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
            try Self.code(.long(3840), vendorID: 0xFFF1, productID: 0x8000))

        #expect(device.instanceName == "partial")
        #expect(device.vendorID == vp.map { _ in 0xFFF1 })
        #expect(device.productID == nil)
    }

    @Test(
        "an empty VP part is absent, not unparseable, and passes a code carrying VID+PID",
        arguments: [
            ("", nil, nil),
            ("65521+", 0xFFF1, nil),
            ("+32768", nil, 0x8000),
        ] as [(String, UInt16?, UInt16?)]
    )
    func emptyVendorProductPartPasses(vp: String, vendorID: UInt16?, productID: UInt16?) async throws {
        let discovery = Self.makeDiscovery()
        try await discovery.advertise(service: Self.record(
            "other-vendor", port: 5541, txt: ["D": "3840", "CM": "1", "VP": "65522+32768"]))
        try await discovery.advertise(service: Self.record(
            "partial", port: 5542, txt: ["D": "3840", "CM": "1", "VP": vp]))
        let controller = try Self.makeController(discovery)

        let device = try await controller.findCommissionable(
            try Self.code(.long(3840), vendorID: 0xFFF1, productID: 0x8000))

        #expect(device.instanceName == "partial")
        #expect(device.vendorID == vendorID)
        #expect(device.productID == productID)
    }

    @Test("a code without VID/PID does not filter on VP, but the device still reports it")
    func noVendorInCode() async throws {
        let discovery = Self.makeDiscovery()
        try await discovery.advertise(service: Self.record(
            "device", port: 5541, txt: ["D": "3840", "CM": "1", "VP": "65521"]))
        let controller = try Self.makeController(discovery)

        let device = try await controller.findCommissionable(try Self.code(.short(15)))

        #expect(device.vendorID == 0xFFF1)
        #expect(device.productID == nil)
    }

    @Test("two devices matching a short discriminator: the first browsed wins, the other is never resolved")
    func shortDiscriminatorFirstWins() async throws {
        let discovery = Self.makeDiscovery()
        try await discovery.advertise(service: Self.record("first", port: 5541, txt: ["D": "3850", "CM": "1"]))
        try await discovery.advertise(service: Self.record("second", port: 5542, txt: ["D": "3860", "CM": "1"]))
        let controller = try Self.makeController(discovery)

        let device = try await controller.findCommissionable(try Self.code(.short(15)))

        #expect(device.instanceName == "first")
        #expect(discovery.resolveCount(name: "second") == 0)
    }

    // MARK: - Address Forms

    @Test(
        "an IPv6 host resolved in URL form is returned unbracketed, in canonical form",
        arguments: ["[fd00::1]", "[fd00:0:0:0:0:0:0:1]", "[FD00::0001]"]
    )
    func bracketedIPv6HostIsUnbracketed(resolvedHost: String) async throws {
        let discovery = InMemoryDiscovery { record in MatterAddress(host: resolvedHost, port: record.port) }
        try await discovery.advertise(service: Self.record("device", port: 5541, txt: ["D": "3840", "CM": "1"]))
        let controller = try Self.makeController(discovery)

        let device = try await controller.findCommissionable(try Self.code(.long(3840)))

        #expect(device.address == MatterAddress(host: "fd00::1", port: 5541))
    }

    @Test("a record that resolves to a host name, not an IP literal, is skipped; a later match is found")
    func hostNameAddressIsSkipped() async throws {
        let discovery = InMemoryDiscovery { record in
            MatterAddress(host: record.name == "named" ? "named.local" : "192.0.2.10", port: record.port)
        }
        try await discovery.advertise(service: Self.record("named", port: 5541, txt: ["D": "3840", "CM": "1"]))
        try await discovery.advertise(service: Self.record("literal", port: 5542, txt: ["D": "3840", "CM": "1"]))
        let controller = try Self.makeController(discovery)

        let device = try await controller.findCommissionable(try Self.code(.long(3840)))

        #expect(device.instanceName == "literal")
        #expect(device.address == MatterAddress(host: "192.0.2.10", port: 5542))
        #expect(discovery.resolveCount(name: "named") == 1)
    }

    @Test("resolve(_:) returns an IPv6 host unbracketed and canonical, and rejects a host name")
    func resolveNormalisesHost() async throws {
        let discovery = InMemoryDiscovery { record in
            MatterAddress(host: record.name == "named" ? "named.local" : "[fd00:0:0:0:0:0:0:1]", port: record.port)
        }
        try await discovery.advertise(service: Self.record("bracketed", port: 5541, txt: [:]))
        try await discovery.advertise(service: Self.record("named", port: 5542, txt: [:]))
        let controller = try Self.makeController(discovery)

        #expect(try await controller.resolve(Self.record("bracketed", port: 0, txt: [:]))
            == MatterAddress(host: "fd00::1", port: 5541))
        await #expect {
            _ = try await controller.resolve(Self.record("named", port: 0, txt: [:]))
        } throws: { error in
            guard case ControllerError.discoveryFailed(let message) = error else { return false }
            return !message.contains("named.local")
        }
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

        let device = try await controller.findCommissionable(try Self.code(.long(3840)))

        #expect(device.instanceName == "match")
        #expect(device.address == MatterAddress(host: "::1", port: 5542))
        #expect(device.mrp.sessionIdleInterval == .milliseconds(5000))
        #expect(device.txtRecords["D"] == "3840")
        #expect(discovery.resolveCount(name: "match") == 1)
    }

    // MARK: - Timing

    /// Search for `code` with a 200 ms timeout on `clock`, and advance the
    /// clock past it once the search is waiting on that deadline.
    private static func searchUntilDeadline(
        _ controller: MatterController,
        _ clock: ManualClock,
        _ code: SetupCode,
        beforeAdvancing: @Sendable () async throws -> Void = {}
    ) async throws -> CommissionableDevice {
        let timeout = Duration.milliseconds(200)
        let deadline = clock.now + timeout
        let search = Task { try await controller.findCommissionable(code, timeout: timeout) }
        do {
            try await clock.awaitSleeper(until: deadline)
            try await beforeAdvancing()
        } catch {
            search.cancel()
            throw error
        }
        await clock.advance(by: timeout)
        return try await search.value
    }

    @Test("no match within the timeout throws commissionableNotFound naming the discriminator")
    func notFound() async throws {
        let discovery = Self.makeDiscovery()
        try await discovery.advertise(service: Self.record("other", port: 5541, txt: ["D": "1234", "CM": "1"]))
        let clock = Self.oneShotClock()
        let controller = try Self.makeController(discovery, clock: clock)

        do {
            _ = try await Self.searchUntilDeadline(controller, clock, try Self.code(.long(3840)))
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

        let search = Task { try await controller.findCommissionable(code) }
        try await discovery.waitForActiveBrowse()
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
        let discovery = SuspendingResolveDiscovery(inner: inner, suspending: "slow")
        let clock = Self.oneShotClock()
        let controller = try Self.makeController(discovery, clock: clock)

        // The deadline falls only once the resolve is in flight. A resolve
        // that ignored the cancellation would hold the search open: a hang,
        // caught by the time limit.
        await #expect(throws: ControllerError.commissionableNotFound("no commissionable device with discriminator 3840")) {
            try await Self.searchUntilDeadline(controller, clock, try Self.code(.long(3840))) {
                try await discovery.awaitResolveEntered()
            }
        }
        #expect(discovery.resolveCancelled)
        #expect(inner.resolveCount(name: "after") == 0)
    }

    @Test("a record whose resolve never completes is skipped after commissionableResolveTimeout; a later match is found")
    func stuckResolveIsSkipped() async throws {
        // Measured against real mDNS: an instance being withdrawn was browsed
        // without TXT and its resolve never completed, so a search that took
        // records one at a time never reached the device it was looking for.
        let inner = Self.makeDiscovery()
        inner.setBrowseTXTHidden(true)
        try await inner.advertise(service: Self.record("stuck", port: 5541, txt: ["D": "3840", "CM": "1"]))
        try await inner.advertise(service: Self.record("match", port: 5542, txt: ["D": "3840", "CM": "1"]))
        // The stuck resolve never completes on its own: without the
        // per-record bound the search never reaches "match" (a hang, caught
        // by the time limit). The search's own deadline never falls.
        let discovery = SuspendingResolveDiscovery(inner: inner, suspending: "stuck")
        let clock = Self.oneShotClock()
        let resolveBound = Duration.milliseconds(200)
        let controller = try Self.makeController(discovery, clock: clock, commissionableResolveTimeout: resolveBound)
        let code = try Self.code(.long(3840))
        let boundDeadline = clock.now + resolveBound

        let search = Task { try await controller.findCommissionable(code) }
        do {
            try await discovery.awaitResolveEntered()
            try await clock.awaitSleeper(until: boundDeadline)
        } catch {
            search.cancel()
            throw error
        }
        await clock.advance(by: resolveBound)
        let device = try await search.value

        #expect(device.instanceName == "match")
        #expect(device.address == MatterAddress(host: "::1", port: 5542))
        #expect(discovery.resolveCancelled, "the stuck resolve was cancelled at its bound")
    }

    @Test("a matching record whose resolve fails is skipped, and the search continues to the next match")
    func failedResolveIsSkipped() async throws {
        // The address closure maps nothing for "broken": its resolve throws.
        let discovery = InMemoryDiscovery { record in
            record.name == "broken" ? nil : MatterAddress(host: "::1", port: record.port)
        }
        try await discovery.advertise(service: Self.record("broken", port: 5541, txt: ["D": "3840", "CM": "1"]))
        try await discovery.advertise(service: Self.record("match", port: 5542, txt: ["D": "3840", "CM": "1"]))
        let controller = try Self.makeController(discovery)

        let device = try await controller.findCommissionable(try Self.code(.long(3840)))

        #expect(device.instanceName == "match")
        #expect(device.address == MatterAddress(host: "::1", port: 5542))
        #expect(discovery.resolveCount(name: "broken") == 1)
    }

    @Test("cancelling the caller during a resolve ends the search with CancellationError")
    func callerCancelDuringResolve() async throws {
        let inner = Self.makeDiscovery()
        try await inner.advertise(service: Self.record("slow", port: 5541, txt: ["D": "3840", "CM": "1"]))
        let discovery = SuspendingResolveDiscovery(inner: inner, suspending: "slow")
        // Neither deadline can fall: the clock never moves.
        let controller = try Self.makeController(discovery)
        let code = try Self.code(.long(3840))

        let search = Task { try await controller.findCommissionable(code) }
        try await discovery.awaitResolveEntered()
        search.cancel()

        await #expect(throws: CancellationError.self) { try await search.value }
        #expect(discovery.resolveCancelled)
    }

    @Test("a record advertised after the browse starts is found")
    func lateAdvertisement() async throws {
        let discovery = Self.makeDiscovery()
        let controller = try Self.makeController(discovery)
        let code = try Self.code(.long(3840))

        let search = Task { try await controller.findCommissionable(code) }
        // Advertise only once the browse is registered, so the live-yield path
        // (not the current-records path) is what finds it.
        try await discovery.waitForActiveBrowse()
        try #require(discovery.activeBrowseCount == 1)
        try await discovery.advertise(service: Self.record("late", port: 5541, txt: ["D": "3840", "CM": "1"]))

        let device = try await search.value
        #expect(device.instanceName == "late")
        #expect(discovery.activeBrowseCount == 0)
    }
}

// MARK: - Suspending Resolve

/// Delegates to an `InMemoryDiscovery`, except that resolving the instance
/// `suspending` waits until it is cancelled, however long that takes: a
/// missed cancellation shows as a hang, which the suite's time limit fails.
private final class SuspendingResolveDiscovery: ServiceDiscovery, Sendable {
    private let inner: InMemoryDiscovery
    private let suspending: String
    private let cancelled = LockedValue(false)
    private let entered = LockedValue(false)
    /// Never set: the suspended resolve waits on it until cancelled.
    private let released = LockedValue(false)

    init(inner: InMemoryDiscovery, suspending: String) {
        self.inner = inner
        self.suspending = suspending
    }

    var resolveCancelled: Bool { cancelled.value }

    /// Returns once the suspending resolve has been entered (unbounded: the
    /// time limit is the hang guard).
    func awaitResolveEntered() async throws {
        try await entered.wait { $0 }
    }

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
            entered.withLock { $0 = true }
            do {
                try await released.wait { $0 }
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
