// MDNSMessage.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

// MARK: - DNSRecordType

/// DNS record types used by Matter's mDNS/DNS-SD advertisement and discovery.
public enum DNSRecordType: UInt16, Sendable {
    case a    = 1
    case ptr  = 12
    case txt  = 16
    case aaaa = 28
    case srv  = 33
    case any  = 255
}

// MARK: - DNSRData

/// Resource record data payload.
public enum DNSRData: Sendable {
    /// PTR record: pointer to a domain name (e.g. service instance name).
    case ptr(domain: String)
    /// SRV record: priority, weight, port, and target hostname.
    case srv(priority: UInt16, weight: UInt16, port: UInt16, target: String)
    /// TXT record: array of "key=value" or "key" strings.
    case txt([String])
    /// A record: 4-byte IPv4 address.
    case a(Data)
    /// AAAA record: 16-byte IPv6 address.
    case aaaa(Data)
    /// Unrecognised record type — raw bytes preserved.
    case unknown(Data)
}

// MARK: - DNSQuestion

/// A DNS/mDNS question section entry.
public struct DNSQuestion: Sendable {
    /// Dot-separated domain name, e.g. `"_matterc._udp.local"`.
    public var name: String
    public var type: DNSRecordType
    /// When `true` the QU bit (high bit of QCLASS) is set, requesting a
    /// unicast response (mDNS §5.4).
    public var unicastResponse: Bool

    public init(name: String, type: DNSRecordType, unicastResponse: Bool = false) {
        self.name = name
        self.type = type
        self.unicastResponse = unicastResponse
    }
}

// MARK: - DNSRecord

/// A DNS/mDNS resource record.
public struct DNSRecord: Sendable {
    public var name: String
    public var type: DNSRecordType
    /// TTL in seconds. Use 0 for "goodbye" records (mDNS §11.3).
    public var ttl: UInt32
    public var rdata: DNSRData

    public init(name: String, type: DNSRecordType, ttl: UInt32, rdata: DNSRData) {
        self.name = name
        self.type = type
        self.ttl = ttl
        self.rdata = rdata
    }
}

// MARK: - DNSMessage

/// A minimal DNS/mDNS message with encode and decode support.
///
/// Covers the subset of RFC 1035 / RFC 6762 needed by Matter:
/// - PTR queries and responses for service type discovery
/// - SRV + TXT + A/AAAA records in advertisement packets
/// - Name pointer decompression for parsing foreign mDNS responses
public struct DNSMessage: Sendable {
    public var id: UInt16
    /// `true` for responses (QR bit), `false` for queries.
    public var isResponse: Bool
    /// Authoritative Answer bit — set to `true` in mDNS responses we send.
    public var isAuthoritative: Bool
    public var questions: [DNSQuestion]
    public var answers: [DNSRecord]
    public var additionals: [DNSRecord]

    public init(
        id: UInt16 = 0,
        isResponse: Bool,
        isAuthoritative: Bool = false,
        questions: [DNSQuestion] = [],
        answers: [DNSRecord] = [],
        additionals: [DNSRecord] = []
    ) {
        self.id = id
        self.isResponse = isResponse
        self.isAuthoritative = isAuthoritative
        self.questions = questions
        self.answers = answers
        self.additionals = additionals
    }

    // MARK: - Encode

    /// Encode the message to DNS wire format (RFC 1035 §4).
    public func encode() -> Data {
        var out = Data()

        // Header
        out.appendUInt16(id)
        var flags: UInt16 = 0
        if isResponse      { flags |= 0x8000 }
        if isAuthoritative { flags |= 0x0400 }
        out.appendUInt16(flags)
        out.appendUInt16(UInt16(questions.count))
        out.appendUInt16(UInt16(answers.count))
        out.appendUInt16(0) // NSCOUNT
        out.appendUInt16(UInt16(additionals.count))

        for q in questions { out.append(encodeQuestion(q)) }
        for r in answers   { out.append(encodeRecord(r, cacheFlush: isResponse)) }
        for r in additionals { out.append(encodeRecord(r, cacheFlush: isResponse)) }

        return out
    }

    private func encodeQuestion(_ q: DNSQuestion) -> Data {
        var out = Data()
        out.append(encodeName(q.name))
        out.appendUInt16(q.type.rawValue)
        var qclass: UInt16 = 0x0001 // IN
        if q.unicastResponse { qclass |= 0x8000 }
        out.appendUInt16(qclass)
        return out
    }

    private func encodeRecord(_ r: DNSRecord, cacheFlush: Bool) -> Data {
        var out = Data()
        out.append(encodeName(r.name))
        out.appendUInt16(r.type.rawValue)
        var rrclass: UInt16 = 0x0001 // IN
        if cacheFlush { rrclass |= 0x8000 }
        out.appendUInt16(rrclass)
        out.appendUInt32(r.ttl)
        let rdata = encodeRData(r.rdata)
        out.appendUInt16(UInt16(rdata.count))
        out.append(rdata)
        return out
    }

    private func encodeRData(_ rdata: DNSRData) -> Data {
        var out = Data()
        switch rdata {
        case .ptr(let domain):
            out.append(encodeName(domain))
        case .srv(let priority, let weight, let port, let target):
            out.appendUInt16(priority)
            out.appendUInt16(weight)
            out.appendUInt16(port)
            out.append(encodeName(target))
        case .txt(let strings):
            for s in strings {
                let bytes = Array(s.utf8)
                out.append(UInt8(min(bytes.count, 255)))
                out.append(contentsOf: bytes.prefix(255))
            }
        case .a(let bytes):
            out.append(bytes)
        case .aaaa(let bytes):
            out.append(bytes)
        case .unknown(let bytes):
            out.append(bytes)
        }
        return out
    }

    /// Encode a dot-separated name to DNS label format (no compression).
    private func encodeName(_ name: String) -> Data {
        var out = Data()
        let labels = name.split(separator: ".", omittingEmptySubsequences: false)
        for label in labels {
            guard !label.isEmpty else { continue }
            let bytes = Array(label.utf8)
            out.append(UInt8(min(bytes.count, 63)))
            out.append(contentsOf: bytes.prefix(63))
        }
        out.append(0) // root label
        return out
    }

    // MARK: - Decode

    /// Decode a DNS wire-format message. Returns `nil` if the data is malformed.
    public static func decode(from data: Data) -> DNSMessage? {
        var parser = DNSParser(data: data)

        guard let id     = parser.readUInt16(),
              let flags  = parser.readUInt16(),
              let qdcount = parser.readUInt16(),
              let ancount = parser.readUInt16(),
              let _       = parser.readUInt16(), // nscount
              let arcount = parser.readUInt16()
        else { return nil }

        let isResponse      = (flags & 0x8000) != 0
        let isAuthoritative = (flags & 0x0400) != 0

        var questions  = [DNSQuestion]()
        var answers    = [DNSRecord]()
        var additionals = [DNSRecord]()

        for _ in 0..<qdcount {
            guard let name  = parser.readName(),
                  let qtype = parser.readUInt16(),
                  let qclass = parser.readUInt16()
            else { return nil }
            let unicast = (qclass & 0x8000) != 0
            let type = DNSRecordType(rawValue: qtype) ?? .any
            questions.append(DNSQuestion(name: name, type: type, unicastResponse: unicast))
        }

        for _ in 0..<(ancount + arcount) {
            guard let record = parser.readRecord() else { return nil }
            if answers.count < Int(ancount) {
                answers.append(record)
            } else {
                additionals.append(record)
            }
        }

        return DNSMessage(
            id: id,
            isResponse: isResponse,
            isAuthoritative: isAuthoritative,
            questions: questions,
            answers: answers,
            additionals: additionals
        )
    }
}

// MARK: - DNSParser

/// Cursor-based DNS wire-format parser with pointer decompression.
struct DNSParser {
    let data: Data
    var offset: Int = 0

    init(data: Data) {
        self.data = data
    }

    mutating func readUInt8() -> UInt8? {
        guard offset < data.count else { return nil }
        defer { offset += 1 }
        return data[offset]
    }

    mutating func readUInt16() -> UInt16? {
        guard offset + 1 < data.count else { return nil }
        let hi = UInt16(data[offset])
        let lo = UInt16(data[offset + 1])
        offset += 2
        return (hi << 8) | lo
    }

    mutating func readUInt32() -> UInt32? {
        guard offset + 3 < data.count else { return nil }
        let b0 = UInt32(data[offset])
        let b1 = UInt32(data[offset + 1])
        let b2 = UInt32(data[offset + 2])
        let b3 = UInt32(data[offset + 3])
        offset += 4
        return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    }

    mutating func readBytes(_ count: Int) -> Data? {
        guard offset + count <= data.count else { return nil }
        defer { offset += count }
        return data[offset..<(offset + count)]
    }

    /// Read a DNS name with pointer decompression (RFC 1035 §4.1.4).
    mutating func readName() -> String? {
        readNameAt(offset: &offset, depth: 0)
    }

    private func readNameAt(offset: inout Int, depth: Int) -> String? {
        guard depth < 10 else { return nil } // guard against pointer loops
        var labels = [String]()
        while offset < data.count {
            let len = data[offset]
            if len == 0 {
                offset += 1
                break
            }
            // Pointer: 0xC0 prefix
            if (len & 0xC0) == 0xC0 {
                guard offset + 1 < data.count else { return nil }
                let ptrHi = UInt16(len & 0x3F)
                let ptrLo = UInt16(data[offset + 1])
                var ptrOffset = Int((ptrHi << 8) | ptrLo)
                offset += 2
                guard let rest = readNameAt(offset: &ptrOffset, depth: depth + 1) else { return nil }
                if !rest.isEmpty { labels.append(rest) }
                break
            }
            // Regular label
            let labelLen = Int(len)
            offset += 1
            guard offset + labelLen <= data.count else { return nil }
            let labelBytes = data[offset..<(offset + labelLen)]
            guard let label = String(bytes: labelBytes, encoding: .utf8) else { return nil }
            labels.append(label)
            offset += labelLen
        }
        return labels.joined(separator: ".")
    }

    mutating func readRecord() -> DNSRecord? {
        guard let name   = readName(),
              let rtype  = readUInt16(),
              let _      = readUInt16(), // class (ignore cache-flush bit)
              let ttl    = readUInt32(),
              let rdlen  = readUInt16()
        else { return nil }

        let rdataStart = offset
        let recordType = DNSRecordType(rawValue: rtype) ?? .any

        let rdata: DNSRData
        switch recordType {
        case .ptr:
            guard let domain = readName() else { return nil }
            rdata = .ptr(domain: domain)
        case .srv:
            guard let priority = readUInt16(),
                  let weight   = readUInt16(),
                  let port     = readUInt16(),
                  let target   = readName()
            else { return nil }
            rdata = .srv(priority: priority, weight: weight, port: port, target: target)
        case .txt:
            var strings = [String]()
            let end = rdataStart + Int(rdlen)
            while offset < end {
                guard let slen = readUInt8() else { break }
                guard let bytes = readBytes(Int(slen)) else { break }
                strings.append(String(bytes: bytes, encoding: .utf8) ?? "")
            }
            rdata = .txt(strings)
        case .a:
            guard let bytes = readBytes(4) else { return nil }
            rdata = .a(bytes)
        case .aaaa:
            guard let bytes = readBytes(16) else { return nil }
            rdata = .aaaa(bytes)
        default:
            guard let bytes = readBytes(Int(rdlen)) else { return nil }
            rdata = .unknown(bytes)
        }

        // Advance to end of RDATA in case we didn't read it all (e.g. unknown)
        offset = rdataStart + Int(rdlen)

        return DNSRecord(name: name, type: recordType, ttl: ttl, rdata: rdata)
    }
}

// MARK: - Data Helpers

private extension Data {
    mutating func appendUInt16(_ value: UInt16) {
        append(UInt8((value >> 8) & 0xFF))
        append(UInt8(value & 0xFF))
    }

    mutating func appendUInt32(_ value: UInt32) {
        append(UInt8((value >> 24) & 0xFF))
        append(UInt8((value >> 16) & 0xFF))
        append(UInt8((value >>  8) & 0xFF))
        append(UInt8(value & 0xFF))
    }
}
