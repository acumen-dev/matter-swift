// TLVTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
@testable import MatterTypes

@Suite("TLV Encoding/Decoding")
struct TLVTests {

    // MARK: - Integer Encoding

    @Test("Encode signed integer uses minimum byte width")
    func signedIntMinWidth() throws {
        // Value fits in 1 byte
        let data1 = TLVEncoder.encode(.signedInt(42))
        let (_, decoded1) = try TLVDecoder.decode(data1)
        #expect(decoded1.intValue == 42)

        // Value requires 2 bytes
        let data2 = TLVEncoder.encode(.signedInt(1000))
        let (_, decoded2) = try TLVDecoder.decode(data2)
        #expect(decoded2.intValue == 1000)

        // Negative value
        let data3 = TLVEncoder.encode(.signedInt(-100))
        let (_, decoded3) = try TLVDecoder.decode(data3)
        #expect(decoded3.intValue == -100)
    }

    @Test("Encode unsigned integer uses minimum byte width")
    func unsignedIntMinWidth() throws {
        let data1 = TLVEncoder.encode(.unsignedInt(200))
        let (_, decoded1) = try TLVDecoder.decode(data1)
        #expect(decoded1.uintValue == 200)

        let data2 = TLVEncoder.encode(.unsignedInt(70000))
        let (_, decoded2) = try TLVDecoder.decode(data2)
        #expect(decoded2.uintValue == 70000)
    }

    // MARK: - Boolean Encoding

    @Test("Encode booleans")
    func booleans() throws {
        let dataTrue = TLVEncoder.encode(.bool(true))
        let (_, decodedTrue) = try TLVDecoder.decode(dataTrue)
        #expect(decodedTrue.boolValue == true)

        let dataFalse = TLVEncoder.encode(.bool(false))
        let (_, decodedFalse) = try TLVDecoder.decode(dataFalse)
        #expect(decodedFalse.boolValue == false)
    }

    // MARK: - String Encoding

    @Test("Encode UTF-8 string")
    func utf8String() throws {
        let data = TLVEncoder.encode(.utf8String("Hello, Matter!"))
        let (_, decoded) = try TLVDecoder.decode(data)
        #expect(decoded.stringValue == "Hello, Matter!")
    }

    @Test("Encode empty string")
    func emptyString() throws {
        let data = TLVEncoder.encode(.utf8String(""))
        let (_, decoded) = try TLVDecoder.decode(data)
        #expect(decoded.stringValue == "")
    }

    // MARK: - Octet String Encoding

    @Test("Encode octet string")
    func octetString() throws {
        let bytes = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let data = TLVEncoder.encode(.octetString(bytes))
        let (_, decoded) = try TLVDecoder.decode(data)
        #expect(decoded.dataValue == bytes)
    }

    // MARK: - Null

    @Test("Encode null")
    func nullValue() throws {
        let data = TLVEncoder.encode(.null)
        let (_, decoded) = try TLVDecoder.decode(data)
        #expect(decoded.isNull)
    }

    // MARK: - Float / Double

    @Test("Encode float")
    func floatValue() throws {
        let data = TLVEncoder.encode(.float(3.14))
        let (_, decoded) = try TLVDecoder.decode(data)
        if case .float(let v) = decoded {
            #expect(abs(v - 3.14) < 0.001)
        } else {
            Issue.record("Expected float")
        }
    }

    @Test("Encode double")
    func doubleValue() throws {
        let data = TLVEncoder.encode(.double(3.141592653589793))
        let (_, decoded) = try TLVDecoder.decode(data)
        if case .double(let v) = decoded {
            #expect(abs(v - 3.141592653589793) < 0.0000001)
        } else {
            Issue.record("Expected double")
        }
    }

    // MARK: - Structure

    @Test("Encode structure with context tags")
    func structure() throws {
        let element = TLVElement.structure([
            .init(tag: .contextSpecific(0), value: .bool(true)),
            .init(tag: .contextSpecific(1), value: .unsignedInt(42)),
            .init(tag: .contextSpecific(2), value: .utf8String("test")),
        ])
        let data = TLVEncoder.encode(element)
        let (_, decoded) = try TLVDecoder.decode(data)

        #expect(decoded[contextTag: 0]?.boolValue == true)
        #expect(decoded[contextTag: 1]?.uintValue == 42)
        #expect(decoded[contextTag: 2]?.stringValue == "test")
    }

    // MARK: - Array

    @Test("Encode array")
    func array() throws {
        let element = TLVElement.array([
            .unsignedInt(1),
            .unsignedInt(2),
            .unsignedInt(3),
        ])
        let data = TLVEncoder.encode(element)
        let (_, decoded) = try TLVDecoder.decode(data)

        let elements = decoded.arrayElements
        #expect(elements?.count == 3)
        #expect(elements?[0].uintValue == 1)
        #expect(elements?[1].uintValue == 2)
        #expect(elements?[2].uintValue == 3)
    }

    // MARK: - Nested Structures

    @Test("Encode nested structure")
    func nestedStructure() throws {
        let element = TLVElement.structure([
            .init(tag: .contextSpecific(0), value: .utf8String("outer")),
            .init(tag: .contextSpecific(1), value: .structure([
                .init(tag: .contextSpecific(0), value: .utf8String("inner")),
                .init(tag: .contextSpecific(1), value: .unsignedInt(99)),
            ])),
        ])
        let data = TLVEncoder.encode(element)
        let (_, decoded) = try TLVDecoder.decode(data)

        #expect(decoded[contextTag: 0]?.stringValue == "outer")
        let inner = decoded[contextTag: 1]
        #expect(inner?[contextTag: 0]?.stringValue == "inner")
        #expect(inner?[contextTag: 1]?.uintValue == 99)
    }

    // MARK: - Roundtrip

    @Test("Roundtrip all types")
    func roundtripAllTypes() throws {
        let original = TLVElement.structure([
            .init(tag: .contextSpecific(0), value: .signedInt(-1)),
            .init(tag: .contextSpecific(1), value: .unsignedInt(UInt64.max)),
            .init(tag: .contextSpecific(2), value: .bool(true)),
            .init(tag: .contextSpecific(3), value: .float(1.5)),
            .init(tag: .contextSpecific(4), value: .double(2.5)),
            .init(tag: .contextSpecific(5), value: .utf8String("hello")),
            .init(tag: .contextSpecific(6), value: .octetString(Data([0x01, 0x02]))),
            .init(tag: .contextSpecific(7), value: .null),
            .init(tag: .contextSpecific(8), value: .array([.unsignedInt(1), .unsignedInt(2)])),
        ])

        let data = TLVEncoder.encode(original)
        let (_, decoded) = try TLVDecoder.decode(data)
        #expect(decoded == original)
    }
}
