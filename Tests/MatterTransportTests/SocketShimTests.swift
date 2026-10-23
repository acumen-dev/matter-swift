// SocketShimTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import CMatterSockets

fileprivate func loopbackIndex() -> UInt32 {
    #if canImport(Darwin)
    if_nametoindex("lo0")
    #else
    if_nametoindex("lo")
    #endif
}

fileprivate extension sockaddr_in6 {
    static func loopback(port: UInt16) -> sockaddr_in6 {
        var a = sockaddr_in6()
        #if canImport(Darwin)
        a.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        #endif
        a.sin6_family = sa_family_t(AF_INET6)
        a.sin6_port = port.bigEndian
        a.sin6_addr = in6addr_loopback
        return a
    }
}

fileprivate extension sockaddr_in {
    static func loopback(port: UInt16) -> sockaddr_in {
        var a = sockaddr_in()
        #if canImport(Darwin)
        a.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        #endif
        a.sin_family = sa_family_t(AF_INET)
        a.sin_port = port.bigEndian
        a.sin_addr.s_addr = UInt32(0x7f00_0001).bigEndian
        return a
    }
}

fileprivate extension sockaddr_storage {
    var port: UInt16 {
        var copy = self
        return withUnsafePointer(to: &copy) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                switch Int32(sa.pointee.sa_family) {
                case AF_INET6:
                    return sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { UInt16(bigEndian: $0.pointee.sin6_port) }
                case AF_INET:
                    return sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt16(bigEndian: $0.pointee.sin_port) }
                default:
                    return 0
                }
            }
        }
    }
}

@Suite("C socket shim", .serialized, .timeLimit(.minutes(1)))
struct SocketShimTests {
    @Test("PKTINFO send keeps the bound source port and recv reports the arrival path (IPv6)")
    func pktinfoKeepsPortV6() throws {
        var err: Int32 = 0
        let rx = cms_open_udp(AF_INET6, 0, &err); try #require(rx >= 0)
        defer { close(rx) }
        let tx = cms_open_udp(AF_INET6, 0, &err); try #require(tx >= 0)
        defer { close(tx) }
        let lo = loopbackIndex()
        var dst = sockaddr_in6.loopback(port: cms_bound_port(rx))
        let sent = withUnsafePointer(to: &dst) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                cms_send(tx, [UInt8(1)], 1, $0, socklen_t(MemoryLayout<sockaddr_in6>.size), lo, "::1")
            }
        }
        #expect(sent == 1)
        var buf = [UInt8](repeating: 0, count: 16); var from = sockaddr_storage(); var ifindex: UInt32 = 0
        var dstText = [CChar](repeating: 0, count: 64)
        let n = cms_recv(rx, &buf, 16, &from, &ifindex, &dstText, 64, 0)
        #expect(n == 1)
        #expect(from.port == cms_bound_port(tx))      // the bound port, not an ephemeral one
        #expect(ifindex == lo)
        #expect(String(cString: dstText) == "::1")
    }

    @Test("PKTINFO send keeps the bound source port and recv reports the arrival path (IPv4)")
    func pktinfoKeepsPortV4() throws {
        var err: Int32 = 0
        let rx = cms_open_udp(AF_INET, 0, &err); try #require(rx >= 0)
        defer { close(rx) }
        let tx = cms_open_udp(AF_INET, 0, &err); try #require(tx >= 0)
        defer { close(tx) }
        let lo = loopbackIndex()
        var dst = sockaddr_in.loopback(port: cms_bound_port(rx))
        let sent = withUnsafePointer(to: &dst) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                cms_send(tx, [UInt8(1)], 1, $0, socklen_t(MemoryLayout<sockaddr_in>.size), lo, "127.0.0.1")
            }
        }
        #expect(sent == 1)
        var buf = [UInt8](repeating: 0, count: 16); var from = sockaddr_storage(); var ifindex: UInt32 = 0
        var dstText = [CChar](repeating: 0, count: 64)
        let n = cms_recv(rx, &buf, 16, &from, &ifindex, &dstText, 64, 0)
        #expect(n == 1)
        #expect(from.port == cms_bound_port(tx))
        #expect(ifindex == lo)
        #expect(String(cString: dstText) == "127.0.0.1")
    }

    @Test("A bogus interface index in the PKTINFO cmsg fails the send (IPv6)")
    func bogusIfindexV6() throws {
        var err: Int32 = 0
        let rx = cms_open_udp(AF_INET6, 0, &err); try #require(rx >= 0)
        defer { close(rx) }
        let tx = cms_open_udp(AF_INET6, 0, &err); try #require(tx >= 0)
        defer { close(tx) }
        var dst = sockaddr_in6.loopback(port: cms_bound_port(rx))
        let sent = withUnsafePointer(to: &dst) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                cms_send(tx, [UInt8(1)], 1, $0, socklen_t(MemoryLayout<sockaddr_in6>.size), 0x7fffffff, nil)
            }
        }
        #expect(sent == -1)
    }

    @Test("A bogus interface index in the PKTINFO cmsg fails the send (IPv4)")
    func bogusIfindexV4() throws {
        var err: Int32 = 0
        let rx = cms_open_udp(AF_INET, 0, &err); try #require(rx >= 0)
        defer { close(rx) }
        let tx = cms_open_udp(AF_INET, 0, &err); try #require(tx >= 0)
        defer { close(tx) }
        var dst = sockaddr_in.loopback(port: cms_bound_port(rx))
        let sent = withUnsafePointer(to: &dst) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                cms_send(tx, [UInt8(1)], 1, $0, socklen_t(MemoryLayout<sockaddr_in>.size), 0x7fffffff, nil)
            }
        }
        #expect(sent == -1)
    }

    @Test("Route probe answers unscoped and scoped on loopback, and reports errors for bad scope or literal")
    func routeProbe() {
        let lo = loopbackIndex()
        var src = [CChar](repeating: 0, count: 64)
        #expect(cms_route_probe(AF_INET6, "::1", 0, 0, &src, 64) == 0)
        #expect(String(cString: src) == "::1")
        src = [CChar](repeating: 0, count: 64)
        #expect(cms_route_probe(AF_INET6, "::1", 0, lo, &src, 64) == 0)
        #expect(String(cString: src) == "::1")
        src = [CChar](repeating: 0, count: 64)
        #expect(cms_route_probe(AF_INET, "127.0.0.1", 0, 0, &src, 64) == 0)
        #expect(String(cString: src) == "127.0.0.1")
        src = [CChar](repeating: 0, count: 64)
        #expect(cms_route_probe(AF_INET, "127.0.0.1", 0, lo, &src, 64) == 0)
        #expect(String(cString: src) == "127.0.0.1")
        #expect(cms_route_probe(AF_INET6, "::1", 0, 0x7fffffff, &src, 64) != 0)
        #expect(cms_route_probe(AF_INET, "127.0.0.1", 0, 0x7fffffff, &src, 64) != 0)
        #expect(cms_route_probe(AF_INET6, "not-an-address", 0, 0, &src, 64) != 0)
        #expect(cms_route_probe(AF_INET, "not-an-address", 0, 0, &src, 64) != 0)
    }
}
