// IPLiteral.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif
import MDNSCore

// MARK: - IP Literal Hosts

extension MatterAddress {

    /// This address with its host as a bare IP literal in canonical form, or
    /// nil when the host is not one.
    ///
    /// Discovery returns an IPv6 host in brackets (`"[fd00::1]"`, the URL-host
    /// form), and may return a host name (`"<instance>.local"`) for an
    /// interface-scoped address; see `NetworkAddress`. Matter's transports
    /// take IP literals, so an address from discovery is normalised here
    /// before it is used or stored.
    public var withIPLiteralHost: MatterAddress? {
        Self.ipLiteral(host).map { MatterAddress(host: $0, port: port) }
    }

    /// This address with an IP-literal host in canonical form (see
    /// ``ipLiteral(_:)``), keeping an IPv6 `%<zone>` suffix as given; any
    /// other host (a host name) is returned unchanged.
    ///
    /// The controller keys exchanges and sessions by address, and the
    /// transports report a sender in `inet_ntop`'s canonical form, so an
    /// address a caller supplies passes through here before it is used as a
    /// key — one address, one text.
    public var canonicalised: MatterAddress {
        MatterAddress(host: Self.canonicalHost(host), port: port)
    }

    /// `host` as a bare IP literal in canonical form: an IPv4 dotted quad, or
    /// an IPv6 literal with any surrounding `[...]` removed, written as
    /// `inet_ntop` writes it (RFC 5952: lowercase, no leading zeros, the
    /// longest zero run as `::` — `"[FD00:0:0:0:0:0:0:05]"` becomes
    /// `"fd00::5"`). An IPv4-mapped IPv6 literal (`"::ffff:192.0.2.1"`)
    /// becomes the IPv4 address it maps (`"192.0.2.1"`). This is the text
    /// the platform transports report for a datagram's sender, so it is the
    /// text to key and store an address by.
    ///
    /// Nil for anything else: a host name, and an IPv6 literal with a
    /// `%<zone>` suffix — a zone names an interface of this host, which does
    /// not survive a restart or a move to another host, and `inet_pton`
    /// rejects it on Linux.
    public static func ipLiteral(_ host: String) -> String? {
        let bare = strippingBrackets(host)
        guard !bare.contains("%") else { return nil }
        return canonicalIPv4(bare) ?? canonicalIPv6(bare)
    }

    /// `host` without a surrounding `[...]`; any other host is unchanged.
    public static func strippingBrackets(_ host: String) -> String {
        guard host.count >= 2, host.hasPrefix("["), host.hasSuffix("]") else { return host }
        return String(host.dropFirst().dropLast())
    }

    /// `host` in canonical form when it is an IP literal (brackets removed,
    /// an IPv6 zone kept as given), otherwise unchanged. An IPv4-mapped
    /// literal becomes IPv4, without a zone: IPv4 has none.
    static func canonicalHost(_ host: String) -> String {
        let bare = strippingBrackets(host)
        if let literal = canonicalIPv4(bare) { return literal }
        // Split the zone off before parsing: see canonicalIPv6.
        let parts = bare.split(separator: "%", maxSplits: 1, omittingEmptySubsequences: false)
        guard let address = parts.first, let literal = canonicalIPv6(String(address)) else { return host }
        guard parts.count == 2, !isIPv4(literal) else { return literal }
        guard !parts[1].isEmpty else { return host }
        return literal + "%" + parts[1]
    }

    private static func canonicalIPv4(_ host: String) -> String? {
        var address = in_addr()
        guard inet_pton(AF_INET, host, &address) == 1 else { return nil }
        return presentation(AF_INET, &address, length: Int(INET_ADDRSTRLEN))
    }

    /// The canonical text of an IPv6 literal, or of the IPv4 address an
    /// IPv4-mapped one (`::ffff:a.b.c.d`) maps.
    ///
    /// `host` must not carry a `%<zone>`: callers split or reject it first.
    /// Darwin's `inet_pton` accepts a zone and silently embeds the scope in
    /// the parsed address (so `inet_ntop` writes back a different address),
    /// where glibc's rejects it.
    private static func canonicalIPv6(_ host: String) -> String? {
        var address = in6_addr()
        guard inet_pton(AF_INET6, host, &address) == 1 else { return nil }
        let bytes = withUnsafeBytes(of: &address) { Array($0) }
        if bytes.prefix(10).allSatisfy({ $0 == 0 }), bytes[10] == 0xFF, bytes[11] == 0xFF {
            return bytes.suffix(4).map(String.init).joined(separator: ".")
        }
        return presentation(AF_INET6, &address, length: Int(INET6_ADDRSTRLEN))
    }

    private static func isIPv4(_ literal: String) -> Bool {
        !literal.contains(":")
    }

    private static func presentation<Address>(_ family: Int32, _ address: inout Address, length: Int) -> String? {
        var buffer = [CChar](repeating: 0, count: length)
        guard inet_ntop(family, &address, &buffer, socklen_t(length)) != nil else { return nil }
        return String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}
