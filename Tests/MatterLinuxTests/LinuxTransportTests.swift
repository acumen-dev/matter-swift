// LinuxTransportTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
@testable import MatterLinux
import MatterTransport
import NIOCore

@Suite("MatterLinux Tests")
struct MatterLinuxTests {

    // MARK: - DNS Name Encoding

    @Test("DNS name encoding produces correct label wire format")
    func dnsNameEncoding() {
        // Build a message with a known name so we can inspect the encoded bytes.
        var msg = DNSMessage(isResponse: false)
        msg.questions.append(DNSQuestion(name: "_matterc._udp.local", type: .ptr))
        let data = msg.encode()

        // After the 12-byte header, the question section begins with the encoded name.
        // "_matterc" = 8 chars, "_udp" = 4 chars, "local" = 5 chars
        // Wire: 0x08 + "_matterc" + 0x04 + "_udp" + 0x05 + "local" + 0x00
        let nameStart = 12
        #expect(data.count > nameStart + 1)
        #expect(data[nameStart] == 8)  // length of "_matterc"
        let label1 = String(bytes: data[(nameStart+1)..<(nameStart+9)], encoding: .utf8)
        #expect(label1 == "_matterc")
        #expect(data[nameStart + 9] == 4) // length of "_udp"
        let label2 = String(bytes: data[(nameStart+10)..<(nameStart+14)], encoding: .utf8)
        #expect(label2 == "_udp")
        #expect(data[nameStart + 14] == 5) // length of "local"
        #expect(data[nameStart + 20] == 0) // root terminator
    }

    // MARK: - DNS Message Round-trip

    @Test("DNSMessage encode/decode round-trip preserves all record types")
    func dnsMessageRoundTrip() throws {
        var msg = DNSMessage(isResponse: true, isAuthoritative: true)
        msg.id = 0xABCD

        // PTR answer
        msg.answers.append(DNSRecord(
            name: "_matterc._udp.local",
            type: .ptr,
            ttl: 4500,
            rdata: .ptr(domain: "My Bridge._matterc._udp.local")
        ))

        // SRV answer
        msg.answers.append(DNSRecord(
            name: "My Bridge._matterc._udp.local",
            type: .srv,
            ttl: 4500,
            rdata: .srv(priority: 0, weight: 0, port: 5540, target: "myhost.local")
        ))

        // TXT answer
        msg.answers.append(DNSRecord(
            name: "My Bridge._matterc._udp.local",
            type: .txt,
            ttl: 4500,
            rdata: .txt(["D=3840", "CM=1", "VP=65521+32769"])
        ))

        let encoded = msg.encode()
        guard let decoded = DNSMessage.decode(from: encoded) else {
            Issue.record("Failed to decode encoded message")
            return
        }

        #expect(decoded.id == 0xABCD)
        #expect(decoded.isResponse == true)
        #expect(decoded.isAuthoritative == true)
        #expect(decoded.answers.count == 3)

        // Check PTR
        if case .ptr(let domain) = decoded.answers[0].rdata {
            #expect(domain == "My Bridge._matterc._udp.local")
        } else {
            Issue.record("Expected PTR rdata")
        }
        #expect(decoded.answers[0].ttl == 4500)

        // Check SRV
        if case .srv(let priority, let weight, let port, let target) = decoded.answers[1].rdata {
            #expect(priority == 0)
            #expect(weight == 0)
            #expect(port == 5540)
            #expect(target == "myhost.local")
        } else {
            Issue.record("Expected SRV rdata")
        }

        // Check TXT
        if case .txt(let strings) = decoded.answers[2].rdata {
            #expect(strings.contains("D=3840"))
            #expect(strings.contains("CM=1"))
        } else {
            Issue.record("Expected TXT rdata")
        }
    }

    // MARK: - DNS Name Pointer Decompression

    @Test("DNS name pointer decompression reconstructs full name")
    func dnsPointerDecompression() {
        // Build a raw DNS message where the answer NAME uses a pointer back to
        // the question's name at offset 12 (0x0C).
        // Header: 12 bytes of zeros except QDCOUNT=1, ANCOUNT=1
        var raw = Data(repeating: 0, count: 12)
        // DNS header: ID(0-1) FLAGS(2-3) QDCOUNT(4-5) ANCOUNT(6-7) NSCOUNT(8-9) ARCOUNT(10-11)
        raw[4] = 0; raw[5] = 1  // QDCOUNT = 1
        raw[6] = 0; raw[7] = 1  // ANCOUNT = 1

        // Question: name = "_ptr._udp.local", QTYPE=PTR, QCLASS=IN
        func appendLabel(_ s: String, to data: inout Data) {
            data.append(UInt8(s.utf8.count))
            data.append(contentsOf: s.utf8)
        }
        appendLabel("_ptr", to: &raw)
        appendLabel("_udp", to: &raw)
        appendLabel("local", to: &raw)
        raw.append(0) // root
        raw.append(contentsOf: [0x00, 0x0C]) // QTYPE = PTR
        raw.append(contentsOf: [0x00, 0x01]) // QCLASS = IN

        // Answer: NAME = pointer to offset 12 (0x0C), TYPE=PTR, CLASS=IN, TTL=60, RDLEN=5
        // RDATA = pointer 0xC0 0x0C again (pointing to same name)
        raw.append(contentsOf: [0xC0, 0x0C])  // name pointer to offset 12
        raw.append(contentsOf: [0x00, 0x0C])  // TYPE = PTR
        raw.append(contentsOf: [0x00, 0x01])  // CLASS = IN
        raw.append(contentsOf: [0x00, 0x00, 0x00, 0x3C]) // TTL = 60
        // RDATA: label "instance" + pointer to 12
        let rdata: [UInt8] = [
            0x08] + Array("instance".utf8) + [0xC0, 0x0C]
        raw.append(contentsOf: [UInt8((rdata.count >> 8) & 0xFF), UInt8(rdata.count & 0xFF)])
        raw.append(contentsOf: rdata)

        guard let decoded = DNSMessage.decode(from: raw) else {
            Issue.record("Failed to decode message with pointer")
            return
        }

        #expect(decoded.questions.count == 1)
        #expect(decoded.questions[0].name == "_ptr._udp.local")
        #expect(decoded.answers.count == 1)
        #expect(decoded.answers[0].name == "_ptr._udp.local")
        if case .ptr(let domain) = decoded.answers[0].rdata {
            #expect(domain.hasSuffix("_ptr._udp.local"))
        } else {
            Issue.record("Expected PTR rdata after pointer decompression")
        }
    }

    // MARK: - UDP Transport Loopback

    @Test("LinuxUDPTransport send/receive loopback")
    func udpLoopback() async throws {
        let transport = LinuxUDPTransport()
        try await transport.bind(port: 15541)

        let testPayload = Data("hello-matter".utf8)
        // The transport binds to "::" (AF_INET6). Send to the IPv6 loopback
        // address "::1" — NIO rejects sending to an AF_INET sockaddr from an
        // AF_INET6 socket with EINVAL.
        let target = MatterAddress(host: "::1", port: 15541)

        try await transport.send(testPayload, to: target)

        // Collect the first datagram with a 3-second timeout
        let received: Data = try await withCheckedThrowingContinuation { cont in
            Task {
                var found = false
                for await (data, _) in transport.receive() {
                    if !found {
                        found = true
                        cont.resume(returning: data)
                    }
                    break
                }
                // Timeout
                try await Task.sleep(for: .seconds(3))
                if !found {
                    cont.resume(throwing: CancellationError())
                }
            }
        }

        #expect(received == testPayload)
        await transport.close()
    }

    // MARK: - MatterAddress / SocketAddress conversion

    @Test("SocketAddress parses IPv4 and IPv6 addresses and their port correctly")
    func socketAddressParsing() throws {
        // IPv4 — verify it's a .v4 case and the port is preserved
        let v4 = try SocketAddress(ipAddress: "192.168.1.1", port: 5540)
        if case .v4 = v4 {
            #expect(v4.port == 5540)
        } else {
            Issue.record("Expected .v4 address for '192.168.1.1'")
        }

        // IPv6 — verify it's a .v6 case and port is preserved
        let v6 = try SocketAddress(ipAddress: "::1", port: 5540)
        if case .v6 = v6 {
            #expect(v6.port == 5540)
        } else {
            Issue.record("Expected .v6 address for '::1'")
        }

        // Verify incompatible string throws
        #expect(throws: (any Error).self) {
            try SocketAddress(ipAddress: "not-an-ip", port: 80)
        }
    }
}
