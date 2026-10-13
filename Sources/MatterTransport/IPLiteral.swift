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
    /// `"fd00::5"`). This is the text the platform transports report for a
    /// datagram's sender, so it is the text to key and store an address by.
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
    /// an IPv6 zone kept as given), otherwise unchanged.
    static func canonicalHost(_ host: String) -> String {
        let bare = strippingBrackets(host)
        if let literal = canonicalIPv4(bare) { return literal }
        let parts = bare.split(separator: "%", maxSplits: 1, omittingEmptySubsequences: false)
        guard let address = parts.first, let literal = canonicalIPv6(String(address)) else { return host }
        guard parts.count == 2 else { return literal }
        guard !parts[1].isEmpty else { return host }
        return literal + "%" + parts[1]
    }

    private static func canonicalIPv4(_ host: String) -> String? {
        var address = in_addr()
        guard inet_pton(AF_INET, host, &address) == 1 else { return nil }
        return presentation(AF_INET, &address, length: Int(INET_ADDRSTRLEN))
    }

    private static func canonicalIPv6(_ host: String) -> String? {
        var address = in6_addr()
        guard inet_pton(AF_INET6, host, &address) == 1 else { return nil }
        return presentation(AF_INET6, &address, length: Int(INET6_ADDRSTRLEN))
    }

    private static func presentation<Address>(_ family: Int32, _ address: inout Address, length: Int) -> String? {
        var buffer = [CChar](repeating: 0, count: length)
        guard inet_ntop(family, &address, &buffer, socklen_t(length)) != nil else { return nil }
        return String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}
