// POSIXInterfaces.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(Darwin) || canImport(Glibc)
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import CMatterSockets

/// The host's network interfaces and the kernel's route check, for path
/// selection (see ``PathSelector``).
public enum POSIXInterfaces {

    /// Every interface `getifaddrs` lists, with its IPv4 and IPv6 addresses.
    /// Up means `IFF_UP` and `IFF_RUNNING`.
    public static func snapshot() -> [InterfaceSnapshot] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }

        let upFlags = UInt32(IFF_UP) | UInt32(IFF_RUNNING)
        var order: [String] = []
        var byName: [String: InterfaceSnapshot] = [:]
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }
            let name = String(cString: entry.pointee.ifa_name)
            if byName[name] == nil {
                order.append(name)
                byName[name] = InterfaceSnapshot(
                    name: name,
                    index: UInt32(if_nametoindex(name)),
                    isUp: entry.pointee.ifa_flags & upFlags == upFlags,
                    addresses: [])
            }
            if let address = entry.pointee.ifa_addr.flatMap(literal),
               byName[name]?.addresses.contains(address) == false {
                byName[name]?.addresses.append(address)
            }
        }
        return order.compactMap { byName[$0] }
    }

    /// Source address `interface` would use to reach `peer`; nil = no route. nil interface = unscoped.
    /// A scoped answer whose source is not one of `interface.addresses` is no route.
    public static func route(to peer: MatterAddress, via interface: InterfaceSnapshot?) -> (index: UInt32, source: String)? {
        route(to: peer, via: interface, interfaces: interface == nil ? snapshot() : [])
    }

    /// ``route(to:via:)`` resolving an unscoped answer against `interfaces`
    /// (the snapshot the caller already holds).
    ///
    /// The kernel answers an unscoped check with a source address only; its
    /// interface is the peer's zone for a link-local peer, otherwise the
    /// interface that holds that source address. A scoped check counts only
    /// when the source it gives belongs to that interface.
    static func route(
        to peer: MatterAddress,
        via interface: InterfaceSnapshot?,
        interfaces: [InterfaceSnapshot]
    ) -> (index: UInt32, source: String)? {
        guard let destination = Destination(peer.host), !destination.zoneMissing else { return nil }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let rc = cms_route_probe(
            destination.family, destination.literal, destination.scope,
            interface?.index ?? 0, &buffer, buffer.count)
        guard rc == 0 else { return nil }
        let source = String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)

        if let interface {
            // A scoped check can still answer with another interface's address (macOS 27
            // gives `::1` for `::1` scoped to any interface): the source selects the
            // interface, so that is no route by this one.
            return interface.addresses.contains(source) ? (interface.index, source) : nil
        }
        if destination.scope != 0 { return (destination.scope, source) }
        guard let owner = interfaces.first(where: { $0.addresses.contains(source) }) else { return nil }
        return (owner.index, source)
    }

    /// The canonical literal of an IPv4 or IPv6 socket address, link-local
    /// without zone; nil for any other family.
    static func literal(_ address: UnsafeMutablePointer<sockaddr>) -> String? {
        switch Int32(address.pointee.sa_family) {
        case AF_INET:
            var addr = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
            return presentation(AF_INET, &addr, length: Int(INET_ADDRSTRLEN))
        case AF_INET6:
            var addr = address.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_addr }
            #if canImport(Darwin)
            // The KAME stack embeds a link-local address's scope in bytes 2–3.
            withUnsafeMutableBytes(of: &addr) { bytes in
                if bytes[0] == 0xFE, bytes[1] & 0xC0 == 0x80 { bytes[2] = 0; bytes[3] = 0 }
            }
            #endif
            return presentation(AF_INET6, &addr, length: Int(INET6_ADDRSTRLEN))
        default:
            return nil
        }
    }

    static func presentation<Address>(_ family: Int32, _ address: inout Address, length: Int) -> String? {
        var buffer = [CChar](repeating: 0, count: length)
        let written = withUnsafeBytes(of: &address) { inet_ntop(family, $0.baseAddress, &buffer, socklen_t(length)) }
        guard written != nil else { return nil }
        return String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}

// MARK: - Destination

/// A peer host parsed for the socket APIs: family, bare literal (brackets and
/// zone removed, IPv4-mapped IPv6 as IPv4) and the zone's interface index.
struct Destination {
    let family: Int32
    let literal: String
    /// The `%zone` interface index for a scoped IPv6 literal, else 0.
    let scope: UInt32
    /// The literal names a `%zone` that is no interface of this host (any more).
    let zoneMissing: Bool

    /// nil when `host` is not an IP literal.
    init?(_ host: String) {
        let canonical = MatterAddress.canonicalHost(host)
        let parts = canonical.split(separator: "%", maxSplits: 1, omittingEmptySubsequences: false)
        let bare = String(parts[0])
        var v4 = in_addr()
        var v6 = in6_addr()
        if parts.count == 1, inet_pton(AF_INET, bare, &v4) == 1 {
            family = AF_INET
            scope = 0
            zoneMissing = false
        } else if inet_pton(AF_INET6, bare, &v6) == 1 {
            family = AF_INET6
            if parts.count == 2 {
                let zone = String(parts[1])
                let index = UInt32(if_nametoindex(zone))
                let resolved = index != 0 ? index : UInt32(zone) ?? 0
                scope = resolved
                zoneMissing = resolved == 0
            } else {
                scope = 0
                zoneMissing = false
            }
        } else {
            return nil
        }
        literal = bare
    }
}
#endif
