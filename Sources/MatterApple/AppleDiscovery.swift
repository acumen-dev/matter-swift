// AppleDiscovery.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(Network)
import Foundation
import Network
import dnssd
import Darwin
import MatterTransport
import Logging

/// Apple platform mDNS/DNS-SD discovery using Network.framework (browsing/resolving)
/// and the C-level `DNSServiceRegister` API (advertising).
///
/// **Advertising** uses `DNSServiceRegister` from the `dnssd` framework, which
/// natively supports comma-separated subtypes in the `regtype` parameter:
/// `"_matterc._udp,_CM,_L3840,_S15"`. This is required for Matter commissioning —
/// `NetService` with the same comma format does NOT register subtypes, it only
/// advertises the primary type.
///
/// **Browsing** and **resolving** use `NWBrowser` and `NWConnection` from
/// Network.framework, which are better suited for asynchronous discovery.
///
/// ```swift
/// let discovery = AppleDiscovery()
///
/// // Advertise as a commissionable device
/// try await discovery.advertise(service: MatterServiceRecord(
///     name: "My Device",
///     serviceType: .commissionable,
///     host: "",
///     port: 5540,
///     txtRecords: ["D": "3840", "VP": "65521+32769", "CM": "1"],
///     subtypes: ["_CM", "_L3840", "_S15"]
/// ))
///
/// // Browse for commissionable devices
/// for await record in discovery.browse(type: .commissionable) {
///     let address = try await discovery.resolve(record)
///     print("Found \(record.name) at \(address)")
/// }
/// ```
public final class AppleDiscovery: MatterDiscovery, @unchecked Sendable {

    // MARK: - Thread Safety
    //
    // `advertisedRefs` and `browsers` are guarded by `lock`.
    // Rules:
    //   • Always acquire `lock` before reading or writing either collection.
    //   • Never hold `lock` across an `await` or a callback.

    private let lock = NSLock()

    // MARK: - State

    /// Active advertisement `DNSServiceRef`s keyed by service name.
    /// Each ref keeps the DNS-SD SRV/TXT records (and subtypes) alive with
    /// mDNSResponder until `DNSServiceRefDeallocate` is called.
    private var advertisedRefs: [String: DNSServiceRef] = [:]
    /// Connection ref that owns all `matter-bridge.local.` AAAA records.
    /// Created when the first operational advertisement is registered.
    /// One `DNSServiceRefDeallocate` removes all records registered on this connection.
    private var bridgeAddressRef: DNSServiceRef?
    /// Custom hostname used as the SRV target for all operational advertisements.
    /// We register link-local IPv6 AAAA records for this hostname on EVERY LAN
    /// interface (each with its specific ifIndex), so homed cannot fall back to
    /// IPv4 for CASE and so queries arriving on any interface get answered.
    private let bridgeHostname = "matter-bridge.local."
    private var browsers: [NWBrowser] = []
    private let queue = DispatchQueue(label: "matter.discovery", qos: .userInitiated)
    private let logger: Logger

    // MARK: - Locking Helpers

    private func withLock<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }

    // MARK: - Init

    public init(logger: Logger = Logger(label: "matter.apple.discovery")) {
        self.logger = logger
    }

    // MARK: - MatterDiscovery

    public func advertise(service: MatterServiceRecord) async throws {
        // Cancel any existing advertisement for this name (under lock).
        let existing = withLock { () -> DNSServiceRef? in
            let ref = advertisedRefs[service.name]
            advertisedRefs.removeValue(forKey: service.name)
            return ref
        }
        if let ref = existing {
            DNSServiceRefDeallocate(ref)
        }

        // Build TXT record payload using the NetService helper for correct wire encoding.
        let txtDict = service.txtRecords.mapValues { $0.data(using: .utf8) ?? Data() }
        let txtData = NetService.data(fromTXTRecord: txtDict)

        // Build the regtype string.
        // DNSServiceRegister natively supports comma-separated subtypes:
        //   "_matterc._udp,_CM,_L3840,_S15"
        // Each comma-separated token after the primary type is registered as a
        // DNS-SD subtype (_CM._sub._matterc._udp, _L3840._sub._matterc._udp, etc.).
        // This is required for Apple Home to discover the device — NetService with the
        // same comma format only advertises the primary type and ignores subtypes.
        let typeString: String
        if service.subtypes.isEmpty {
            typeString = service.serviceType.rawValue
        } else {
            typeString = service.serviceType.rawValue + "," + service.subtypes.joined(separator: ",")
        }

        // Port must be in network byte order for DNSServiceRegister.
        let portBig = CFSwapInt16HostToBig(service.port)

        // Restrict advertisement to the primary LAN interface.
        // Both commissionable and operational use the system hostname (hostParam=nil)
        // so that mDNSResponder resolves SRV targets using the Mac's own Bonjour
        // records (DM-Mac-mini.local. → fe80:: + IPv4).  CHIP's address scorer picks
        // link-local IPv6 first, so CASE connects on the same address as PASE even
        // when VPN/Tailscale addresses are also present in the hostname's record set.
        //
        // A custom hostname (matter-bridge.local.) was tried but caused CASE to fail:
        // homed's DNSServiceGetAddrInfo for the custom hostname returned no result,
        // preventing operational discovery from completing.
        let lan = primaryLANInterface()
        let ifIndex = lan?.index ?? 0

        if let lan {
            logger.debug("mDNS advertising '\(service.name)' restricted to \(lan.name) (ifIndex=\(lan.index), \(lan.ipv4))")
        }
        if service.serviceType == .operational {
            logNetworkInterfaces()
        }

        // Both commissionable and operational use the system hostname (nil = default).
        let hostParam: String? = nil

        // Both commissionable and operational are scoped to the primary LAN interface.
        // Previously operational used ifIndex=0 (all interfaces) but that combined
        // with the custom hostname caused homed's mDNS resolution to time out.
        let serviceIfIndex: UInt32 = ifIndex

        var sdRef: DNSServiceRef?
        let err: DNSServiceErrorType = txtData.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
            DNSServiceRegister(
                &sdRef,
                0,              // flags
                serviceIfIndex,
                service.name,
                typeString,
                "local.",
                hostParam,      // nil = system hostname (DM-Mac-mini.local.)
                portBig,
                UInt16(txtData.count),
                ptr.baseAddress,
                nil,            // callback
                nil             // context
            )
        }

        guard err == kDNSServiceErr_NoError, let ref = sdRef else {
            throw DiscoveryError.registrationFailed(code: Int(err))
        }

        // Schedule the ref so mDNSResponder keeps the SRV/TXT records alive.
        // Without this, mDNSResponder's keepalive timer fires (~30–60 s after
        // registration) and evicts the record — causing homed's operational
        // discovery to time out during CASE session establishment.
        DNSServiceSetDispatchQueue(ref, queue)

        withLock { advertisedRefs[service.name] = ref }

        let subtypeDesc = service.subtypes.isEmpty ? "" : " subtypes=[\(service.subtypes.joined(separator: ","))]"
        let ifDesc = serviceIfIndex == 0 ? "all interfaces" : (lan.map { "\($0.name) (ifIndex=\($0.index))" } ?? "ifIndex=\(serviceIfIndex)")
        logger.info("Advertising '\(service.name)' as \(service.serviceType.rawValue)\(subtypeDesc) on port \(service.port) [\(ifDesc)]")
    }

    public func browse(type: MatterServiceType) -> AsyncStream<MatterServiceRecord> {
        let descriptor = NWBrowser.Descriptor.bonjour(type: type.rawValue, domain: "local.")
        let browser = NWBrowser(for: descriptor, using: .udp)

        return AsyncStream { continuation in
            browser.browseResultsChangedHandler = { [weak self] results, _ in
                guard let self else { return }
                for result in results {
                    if let record = self.serviceRecord(from: result, type: type) {
                        continuation.yield(record)
                    }
                }
            }

            browser.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .failed(let error):
                    self.logger.error("Browse failed: \(error)")
                    continuation.finish()
                case .cancelled:
                    continuation.finish()
                default:
                    break
                }
            }

            continuation.onTermination = { @Sendable [weak self] _ in
                browser.cancel()
                self?.withLock { self?.browsers.removeAll { $0 === browser } }
            }

            browser.start(queue: self.queue)
            withLock { browsers.append(browser) }
        }
    }

    public func resolve(_ record: MatterServiceRecord) async throws -> MatterAddress {
        // Create a connection to the browsed service to trigger resolution
        let endpoint = NWEndpoint.service(
            name: record.name,
            type: record.serviceType.rawValue,
            domain: "local.",
            interface: nil
        )
        let connection = NWConnection(to: endpoint, using: .udp)

        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<MatterAddress, Error>) in
            nonisolated(unsafe) var resumed = false
            connection.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                guard !resumed else { return }
                switch state {
                case .ready:
                    if let remoteEndpoint = connection.currentPath?.remoteEndpoint,
                       let address = MatterAddress(endpoint: remoteEndpoint) {
                        resumed = true
                        cont.resume(returning: address)
                    } else {
                        resumed = true
                        cont.resume(throwing: DiscoveryError.resolveFailed(record.name))
                    }
                    connection.cancel()
                case .failed(let error):
                    self.logger.error("Resolve failed for '\(record.name)': \(error)")
                    resumed = true
                    cont.resume(throwing: error)
                    connection.cancel()
                case .cancelled:
                    if !resumed {
                        resumed = true
                        cont.resume(throwing: CancellationError())
                    }
                default:
                    break
                }
            }
            connection.start(queue: self.queue)
        }
    }

    public func stopAdvertising() async {
        let (toStop, addrRef) = withLock { () -> ([DNSServiceRef], DNSServiceRef?) in
            let all = Array(advertisedRefs.values)
            advertisedRefs.removeAll()
            let addr = bridgeAddressRef
            bridgeAddressRef = nil
            return (all, addr)
        }
        for ref in toStop {
            DNSServiceRefDeallocate(ref)
        }
        if let addrRef {
            DNSServiceRefDeallocate(addrRef)
        }
    }

    public func stopAdvertising(name: String) async {
        let ref = withLock { () -> DNSServiceRef? in
            let r = advertisedRefs[name]
            advertisedRefs.removeValue(forKey: name)
            return r
        }
        if let ref {
            DNSServiceRefDeallocate(ref)
        }
    }

    // MARK: - Private

    /// Find the interface index for the primary local-area-network interface.
    ///
    /// Returns the index of the first `en*` interface (sorted by index, lowest first) that is:
    /// - UP and RUNNING
    /// - Not a loopback or point-to-point (VPN/PPP) interface
    /// - Has an assigned IPv4 address
    ///
    /// This covers Wi-Fi (`en0` on most Macs) and wired Ethernet (`en1`, `en2`, …).
    /// VPN tunnels (`utun*`), bridges (`bridge*`), and other virtual interfaces are
    /// excluded.  Restricting `DNSServiceRegister` to this interface ensures the iPhone
    /// resolves the SRV record to the LAN IP, not a VPN or global-IPv6 address.
    ///
    /// Returns `0` (all interfaces) if no suitable interface is found — preserving the
    /// previous behaviour and allowing the caller to proceed without an interface filter.
    /// Result of LAN interface detection.
    private struct LANInterface {
        let index: UInt32
        let name: String
        let ipv4: String
    }

    /// Find the primary LAN interface (lowest-indexed `en*` with an IPv4 address).
    private func primaryLANInterface() -> LANInterface? {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let head = ifaddr else { return nil }
        defer { freeifaddrs(head) }

        var best: (idx: UInt32, name: String, ip: String)? = nil

        var cursor: UnsafeMutablePointer<ifaddrs>? = head
        while let ifa = cursor {
            defer { cursor = ifa.pointee.ifa_next }

            guard let addr = ifa.pointee.ifa_addr else { continue }
            guard addr.pointee.sa_family == UInt8(AF_INET) else { continue }

            let flags = ifa.pointee.ifa_flags
            guard (flags & UInt32(IFF_UP))         != 0,
                  (flags & UInt32(IFF_RUNNING))     != 0,
                  (flags & UInt32(IFF_LOOPBACK))    == 0,
                  (flags & UInt32(IFF_POINTOPOINT)) == 0 else { continue }

            let name = String(cString: ifa.pointee.ifa_name)
            guard name.hasPrefix("en") else { continue }

            let idx = if_nametoindex(ifa.pointee.ifa_name)
            guard idx != 0 else { continue }
            if let b = best, idx >= b.idx { continue }

            // Extract dotted-decimal IPv4
            var sinCopy = UnsafeRawPointer(addr).load(as: sockaddr_in.self)
            var ipBuf   = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            Darwin.inet_ntop(AF_INET, &sinCopy.sin_addr, &ipBuf, socklen_t(INET_ADDRSTRLEN))
            let ip = String(decoding: ipBuf.prefix(while: { $0 != 0 }).map(UInt8.init), as: UTF8.self)

            best = (UInt32(idx), name, ip)
        }

        guard let b = best else { return nil }
        return LANInterface(index: b.idx, name: b.name, ipv4: b.ip)
    }

    /// Backwards-compat shim used by advertise().
    private func primaryLANInterfaceIndex() -> UInt32 {
        primaryLANInterface()?.index ?? 0
    }

    /// No-op callback for `DNSServiceRegisterRecord`.
    ///
    // MARK: - Address Record Helpers

    /// No-op callback required by `DNSServiceRegisterRecord` — a NULL callback pointer
    /// causes `kDNSServiceErr_BadParam`.  We don't need conflict notifications.
    private static let addressRecordCallback: DNSServiceRegisterRecordReply = { _, _, _, _, _ in }

    /// Register a link-local AAAA record for `hostname` on the interface identified by
    /// `ifIndex`, using a connection-based `DNSServiceRef` so a single dealloc removes it.
    ///
    /// **Why AAAA-only and why a specific interface index?**
    /// mDNSResponder can serve link-local (`fe80::`) AAAA records registered on a
    /// specific interface — it will NOT serve them when registered globally
    /// (`interfaceIndex=0`).  By registering only AAAA (no A record), CHIP's address
    /// scorer has no IPv4 candidate to prefer, so it uses the link-local IPv6 directly.
    ///
    /// - Returns: The owning `DNSServiceRef`, or `nil` on failure.
    private func registerAddressRecord(hostname: String, ifIndex: UInt32) -> DNSServiceRef? {
        guard let addr6 = getLinkLocalIPv6(ifIndex: ifIndex) else {
            logger.warning("No link-local IPv6 on ifIndex=\(ifIndex) — cannot register AAAA for \(hostname)")
            return nil
        }

        var connRef: DNSServiceRef?
        let connErr = DNSServiceCreateConnection(&connRef)
        guard connErr == kDNSServiceErr_NoError, let conn = connRef else {
            logger.error("DNSServiceCreateConnection failed: \(connErr)")
            return nil
        }
        // Schedule the connection so mDNSResponder keeps it alive.
        // Without this, mDNSResponder's keepalive timer fires (typically after
        // 30–60 s) and evicts all records registered on this connection.
        DNSServiceSetDispatchQueue(conn, queue)

        var recordRef: DNSRecordRef?
        let err: DNSServiceErrorType = withUnsafeBytes(of: addr6) { ptr in
            DNSServiceRegisterRecord(
                conn,
                &recordRef,
                DNSServiceFlags(kDNSServiceFlagsShared), // no probing delay
                ifIndex,                                 // specific interface — required for link-local
                hostname,
                UInt16(kDNSServiceType_AAAA),
                UInt16(kDNSServiceClass_IN),
                UInt16(MemoryLayout<in6_addr>.size),
                ptr.baseAddress,
                0,
                Self.addressRecordCallback,
                nil
            )
        }

        guard err == kDNSServiceErr_NoError else {
            logger.error("DNSServiceRegisterRecord AAAA failed: \(err) for \(hostname) on ifIndex=\(ifIndex)")
            DNSServiceRefDeallocate(conn)
            return nil
        }

        var ipBuf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        var addrCopy = addr6
        Darwin.inet_ntop(AF_INET6, &addrCopy, &ipBuf, socklen_t(INET6_ADDRSTRLEN))
        let ipStr = String(decoding: ipBuf.prefix(while: { $0 != 0 }).map(UInt8.init), as: UTF8.self)
        var ifNameBuf = [CChar](repeating: 0, count: Int(IF_NAMESIZE))
        Darwin.if_indextoname(ifIndex, &ifNameBuf)
        let ifName = String(decoding: ifNameBuf.prefix(while: { $0 != 0 }).map(UInt8.init), as: UTF8.self)
        logger.info("Registered \(hostname) AAAA → \(ipStr) on \(ifName) (ifIndex=\(ifIndex))")

        return conn
    }

    /// Return the interface index for a named interface, or `nil` if unknown.
    private func lookupIfIndex(forName name: String) -> UInt32? {
        let idx = Darwin.if_nametoindex(name)
        return idx != 0 ? UInt32(idx) : nil
    }

    // MARK: - Multi-Interface AAAA Registration

    /// Enumerate all active `en*` interfaces that are UP, RUNNING, non-loopback,
    /// non-point-to-point, and have a link-local IPv6 address.
    ///
    /// On a dual-homed Mac this typically returns both `en0` (Ethernet) and `en1`
    /// (Wi-Fi).  Registering `matter-bridge.local. AAAA` on each interface separately
    /// means a query arriving on any interface gets answered locally — no reliance on
    /// the router bridging multicast from one L2 segment to another.
    private func allActiveLANInterfaces() -> [(name: String, index: UInt32, linkLocalIPv6: in6_addr)] {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let head = ifaddr else { return [] }
        defer { freeifaddrs(head) }

        var results: [(name: String, index: UInt32, linkLocalIPv6: in6_addr)] = []
        var seen: Set<UInt32> = []

        var cursor: UnsafeMutablePointer<ifaddrs>? = head
        while let ifa = cursor {
            defer { cursor = ifa.pointee.ifa_next }

            guard let addr = ifa.pointee.ifa_addr else { continue }
            guard addr.pointee.sa_family == UInt8(AF_INET6) else { continue }

            let flags = ifa.pointee.ifa_flags
            guard (flags & UInt32(IFF_UP))         != 0,
                  (flags & UInt32(IFF_RUNNING))     != 0,
                  (flags & UInt32(IFF_LOOPBACK))    == 0,
                  (flags & UInt32(IFF_POINTOPOINT)) == 0 else { continue }

            let name = String(cString: ifa.pointee.ifa_name)
            guard name.hasPrefix("en") else { continue }

            let idx = UInt32(if_nametoindex(ifa.pointee.ifa_name))
            guard idx != 0, !seen.contains(idx) else { continue }

            let sin6 = addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
            let ipv6 = sin6.sin6_addr
            let b0 = ipv6.__u6_addr.__u6_addr8.0
            let b1 = ipv6.__u6_addr.__u6_addr8.1
            guard b0 == 0xFE && (b1 & 0xC0) == 0x80 else { continue } // fe80::/10 only

            seen.insert(idx)
            results.append((name: name, index: idx, linkLocalIPv6: ipv6))
        }

        return results.sorted { $0.index < $1.index }
    }

    /// Register `hostname` A + AAAA on **every** active LAN interface.
    ///
    /// - **A record** (IPv4): registered on all interfaces (`ifIndex=0`) using the
    ///   primary LAN interface's IPv4 address.  Apple Home's CHIP stack resolves the
    ///   operational SRV hostname to IPv4 when initiating CASE — without an A record
    ///   the address resolution times out and CASE never starts.
    /// - **AAAA records** (link-local IPv6): registered per-interface using each
    ///   interface's own `fe80::` address and its specific `ifIndex`.  mDNSResponder
    ///   only answers a query on the interface the record was registered for, so a
    ///   query on en0 gets en0's link-local, a query on en1 gets en1's link-local.
    ///
    /// All records share one connection-based `DNSServiceRef` so a single
    /// `DNSServiceRefDeallocate` removes all of them.
    ///
    /// Returns the owning connection ref, or `nil` if every registration fails.
    private func registerAddressRecords(hostname: String) -> DNSServiceRef? {
        let interfaces = allActiveLANInterfaces()
        guard !interfaces.isEmpty else {
            logger.warning("No active LAN interfaces with link-local IPv6 found — cannot register address records for \(hostname)")
            return nil
        }

        var connRef: DNSServiceRef?
        let connErr = DNSServiceCreateConnection(&connRef)
        guard connErr == kDNSServiceErr_NoError, let conn = connRef else {
            logger.error("DNSServiceCreateConnection failed: \(connErr)")
            return nil
        }
        // Schedule the connection so mDNSResponder keeps it alive.
        // Without this, mDNSResponder's keepalive timer fires (typically after
        // 30–60 s) and evicts all records registered on this connection.
        DNSServiceSetDispatchQueue(conn, queue)

        var registered = 0

        // ── A record (IPv4) ──────────────────────────────────────────────────
        // Apple Home resolves the operational SRV hostname to an IPv4 A record
        // before connecting for CASE.  Register on all interfaces (ifIndex=0)
        // using the primary LAN interface's IPv4 address.
        if let lan = primaryLANInterface() {
            var inAddr = in_addr()
            if Darwin.inet_pton(AF_INET, lan.ipv4, &inAddr) == 1 {
                var recordRef: DNSRecordRef?
                let err: DNSServiceErrorType = withUnsafeBytes(of: inAddr) { ptr in
                    DNSServiceRegisterRecord(
                        conn,
                        &recordRef,
                        DNSServiceFlags(kDNSServiceFlagsShared), // no probing delay
                        0,                                        // all interfaces for IPv4
                        hostname,
                        UInt16(kDNSServiceType_A),
                        UInt16(kDNSServiceClass_IN),
                        UInt16(MemoryLayout<in_addr>.size),
                        ptr.baseAddress,
                        0,
                        Self.addressRecordCallback,
                        nil
                    )
                }
                if err == kDNSServiceErr_NoError {
                    logger.info("Registered \(hostname) A → \(lan.ipv4) on all interfaces")
                    registered += 1
                } else {
                    logger.warning("DNSServiceRegisterRecord A failed: \(err)")
                }
            } else {
                logger.warning("inet_pton failed for \(lan.ipv4) — skipping A record for \(hostname)")
            }
        } else {
            logger.warning("No primary LAN interface found — skipping A record for \(hostname)")
        }

        // ── AAAA records (link-local IPv6, per interface) ─────────────────────
        for iface in interfaces {
            var ipBuf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            var addrCopy = iface.linkLocalIPv6
            Darwin.inet_ntop(AF_INET6, &addrCopy, &ipBuf, socklen_t(INET6_ADDRSTRLEN))
            let ipStr = String(decoding: ipBuf.prefix(while: { $0 != 0 }).map(UInt8.init), as: UTF8.self)

            var recordRef: DNSRecordRef?
            let err: DNSServiceErrorType = withUnsafeBytes(of: iface.linkLocalIPv6) { ptr in
                DNSServiceRegisterRecord(
                    conn,
                    &recordRef,
                    DNSServiceFlags(kDNSServiceFlagsShared), // no probing delay
                    iface.index,                             // specific interface — required for link-local
                    hostname,
                    UInt16(kDNSServiceType_AAAA),
                    UInt16(kDNSServiceClass_IN),
                    UInt16(MemoryLayout<in6_addr>.size),
                    ptr.baseAddress,
                    0,
                    Self.addressRecordCallback,
                    nil
                )
            }

            if err == kDNSServiceErr_NoError {
                logger.info("Registered \(hostname) AAAA → \(ipStr) on \(iface.name) (ifIndex=\(iface.index))")
                registered += 1
            } else {
                logger.warning("DNSServiceRegisterRecord AAAA failed on \(iface.name) (ifIndex=\(iface.index)): \(err)")
            }
        }

        if registered == 0 {
            logger.error("All address registrations failed for \(hostname)")
            DNSServiceRefDeallocate(conn)
            return nil
        }

        return conn
    }

    /// Find the link-local IPv6 address (`fe80::/10`) for the interface with the given index.
    private func getLinkLocalIPv6(ifIndex: UInt32) -> in6_addr? {
        var ifap: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifap) == 0, let head = ifap else { return nil }
        defer { freeifaddrs(head) }
        var cursor: UnsafeMutablePointer<ifaddrs>? = head
        while let ifa = cursor {
            defer { cursor = ifa.pointee.ifa_next }
            guard if_nametoindex(ifa.pointee.ifa_name) == ifIndex,
                  ifa.pointee.ifa_addr?.pointee.sa_family == UInt8(AF_INET6),
                  let sa = ifa.pointee.ifa_addr else { continue }
            let sin6 = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
            let addr = sin6.sin6_addr
            let b0 = addr.__u6_addr.__u6_addr8.0
            let b1 = addr.__u6_addr.__u6_addr8.1
            if b0 == 0xFE && (b1 & 0xC0) == 0x80 { // fe80::/10
                return addr
            }
        }
        return nil
    }

    /// Log a summary of all active non-loopback interfaces — useful for diagnosing
    /// hostname-resolution issues when a VPN is active.
    private func logNetworkInterfaces() {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let head = ifaddr else { return }
        defer { freeifaddrs(head) }

        var lines: [String] = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = head
        while let ifa = cursor {
            defer { cursor = ifa.pointee.ifa_next }
            guard let addr = ifa.pointee.ifa_addr else { continue }
            let family = addr.pointee.sa_family
            guard family == UInt8(AF_INET) || family == UInt8(AF_INET6) else { continue }
            let flags = ifa.pointee.ifa_flags
            guard (flags & UInt32(IFF_LOOPBACK)) == 0,
                  (flags & UInt32(IFF_UP))        != 0 else { continue }

            let ifname = String(cString: ifa.pointee.ifa_name)
            var ipBuf  = [CChar](repeating: 0, count: 64)
            let raw    = UnsafeRawPointer(addr)
            if family == UInt8(AF_INET) {
                var s = raw.load(as: sockaddr_in.self)
                Darwin.inet_ntop(AF_INET, &s.sin_addr, &ipBuf, 64)
            } else {
                var s = raw.load(as: sockaddr_in6.self)
                Darwin.inet_ntop(AF_INET6, &s.sin6_addr, &ipBuf, 64)
            }
            let ip   = String(decoding: ipBuf.prefix(while: { $0 != 0 }).map(UInt8.init), as: UTF8.self)
            let pptp = (flags & UInt32(IFF_POINTOPOINT)) != 0 ? " [point-to-point/VPN]" : ""
            lines.append("  \(ifname): \(ip)\(pptp)")
        }
        if !lines.isEmpty {
            logger.info("Network interfaces (may affect mDNS resolution):\n\(lines.joined(separator: "\n"))")
        }
    }

    /// Convert an `NWBrowser.Result` to a `MatterServiceRecord`.
    private func serviceRecord(
        from result: NWBrowser.Result,
        type: MatterServiceType
    ) -> MatterServiceRecord? {
        guard case .service(let name, _, _, _) = result.endpoint else {
            return nil
        }

        var txtRecords: [String: String] = [:]
        if case .bonjour(let txtRecord) = result.metadata {
            for (key, entry) in txtRecord {
                if case .string(let value) = entry {
                    txtRecords[key] = value
                }
            }
        }

        return MatterServiceRecord(
            name: name,
            serviceType: type,
            host: "",
            port: 0,
            txtRecords: txtRecords
        )
    }
}

// MARK: - Errors

/// Errors specific to Apple platform discovery.
public enum DiscoveryError: Error, Sendable {
    case resolveFailed(String)
    case registrationFailed(code: Int)
}
#endif
