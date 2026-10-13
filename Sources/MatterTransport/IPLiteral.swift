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

    /// This address with its host as a bare IP literal, or nil when the host
    /// is not one.
    ///
    /// Discovery returns an IPv6 host in brackets (`"[fd00::1]"`, the URL-host
    /// form), and may return a host name (`"<instance>.local"`) for an
    /// interface-scoped address; see `NetworkAddress`. Matter's transports
    /// take IP literals, so an address from discovery is normalised here
    /// before it is used or stored.
    public var withIPLiteralHost: MatterAddress? {
        Self.ipLiteral(host).map { MatterAddress(host: $0, port: port) }
    }

    /// `host` as a bare IP literal: an IPv4 dotted quad, or an IPv6 literal
    /// with any surrounding `[...]` removed. An IPv6 literal may carry a
    /// `%<zone>` suffix, kept as is. Nil for anything else, a host name
    /// included.
    public static func ipLiteral(_ host: String) -> String? {
        let bare = strippingBrackets(host)
        if isIPv4Literal(bare) { return bare }
        let address = bare.split(separator: "%", maxSplits: 1, omittingEmptySubsequences: false)
        guard let first = address.first, isIPv6Literal(String(first)) else { return nil }
        guard address.count == 1 || !address[1].isEmpty else { return nil }
        return bare
    }

    /// `host` without a surrounding `[...]`; any other host is unchanged.
    public static func strippingBrackets(_ host: String) -> String {
        guard host.count >= 2, host.hasPrefix("["), host.hasSuffix("]") else { return host }
        return String(host.dropFirst().dropLast())
    }

    private static func isIPv4Literal(_ host: String) -> Bool {
        var buffer = [UInt8](repeating: 0, count: 4)
        return inet_pton(AF_INET, host, &buffer) == 1
    }

    private static func isIPv6Literal(_ host: String) -> Bool {
        var buffer = [UInt8](repeating: 0, count: 16)
        return inet_pton(AF_INET6, host, &buffer) == 1
    }
}
