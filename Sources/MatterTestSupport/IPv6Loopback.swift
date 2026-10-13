// IPv6Loopback.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

/// Whether this host can use the IPv6 loopback, for tests that send over it:
/// `.enabled(if: IPv6Loopback.isAvailable, "…")`. A container may run
/// without IPv6 on `lo`; such a test is then skipped, visibly, rather than
/// failing on the environment.
public enum IPv6Loopback {

    /// An `AF_INET6` UDP socket binds to `[::1]:0`. Probed once.
    public static let isAvailable: Bool = probe()

    private static func probe() -> Bool {
        #if canImport(Glibc) || canImport(Musl)
        let datagram = Int32(SOCK_DGRAM.rawValue)
        #else
        let datagram = SOCK_DGRAM
        #endif
        let fd = socket(AF_INET6, datagram, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var address = sockaddr_in6()
        address.sin6_family = sa_family_t(AF_INET6)
        address.sin6_port = 0
        address.sin6_addr = in6addr_loopback
        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        }
        return bound == 0
    }
}
