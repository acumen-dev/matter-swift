// MatterProtocolTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
@testable import MatterProtocol
@testable import MatterTypes

// MARK: - Message Header Tests

@Suite("Message Header")
struct MessageHeaderTests {

    @Test("Encode minimal header — no source, no destination")
    func encodeMinimal() throws {
        let header = MessageHeader(
            sessionID: 0,
            messageCounter: 42
        )

        let data = header.encode()
        #expect(data.count == 8)

        // Flags: version=0, S=0, DSIZ=00
        #expect(data[0] == 0x00)
        // Session ID = 0 (LE)
        #expect(data[1] == 0x00)
        #expect(data[2] == 0x00)
        // Security flags: all zero
        #expect(data[3] == 0x00)
        // Counter = 42 (LE)
        #expect(data[4] == 42)
        #expect(data[5] == 0)
        #expect(data[6] == 0)
        #expect(data[7] == 0)
    }

    @Test("Encode with source node ID")
    func encodeWithSource() throws {
        let header = MessageHeader(
            sessionID: 0,
            messageCounter: 1,
            sourceNodeID: NodeID(rawValue: 0x0102030405060708)
        )

        let data = header.encode()
        #expect(data.count == 16) // 8 fixed + 8 source

        // Flags: S=1 (bit 2)
        #expect(data[0] & 0x04 == 0x04)

        // Source node ID (LE: 08 07 06 05 04 03 02 01)
        #expect(data[8] == 0x08)
        #expect(data[9] == 0x07)
        #expect(data[15] == 0x01)
    }

    @Test("Encode with destination node ID")
    func encodeWithDestNode() throws {
        let header = MessageHeader(
            sessionID: 0x1234,
            messageCounter: 100,
            destinationNodeID: NodeID(rawValue: 0xAABBCCDD00112233)
        )

        let data = header.encode()
        #expect(data.count == 16) // 8 fixed + 8 dest

        // DSIZ = 01 (dest node ID)
        #expect(data[0] & 0x03 == 0x01)

        // Session ID (LE)
        #expect(data[1] == 0x34)
        #expect(data[2] == 0x12)
    }

    @Test("Encode with destination group ID")
    func encodeWithDestGroup() throws {
        let header = MessageHeader(
            sessionID: 5,
            messageCounter: 200,
            destinationGroupID: GroupID(rawValue: 0xABCD)
        )

        let data = header.encode()
        #expect(data.count == 10) // 8 fixed + 2 group

        // DSIZ = 02 (group ID)
        #expect(data[0] & 0x03 == 0x02)

        // Group ID (LE)
        #expect(data[8] == 0xCD)
        #expect(data[9] == 0xAB)
    }

    @Test("Encode with source and destination")
    func encodeSourceAndDest() throws {
        let header = MessageHeader(
            sessionID: 0,
            messageCounter: 500,
            sourceNodeID: NodeID(rawValue: 1),
            destinationNodeID: NodeID(rawValue: 2)
        )

        let data = header.encode()
        #expect(data.count == 24) // 8 + 8 source + 8 dest

        // Flags: S=1, DSIZ=01
        #expect(data[0] == 0x05) // 0b00000101
    }

    @Test("Encode security flags — privacy and group session")
    func encodeSecurityFlags() throws {
        let header = MessageHeader(
            sessionID: 10,
            securityFlags: MessageHeader.SecurityFlags(
                privacy: true,
                sessionType: .group
            ),
            messageCounter: 1
        )

        let data = header.encode()
        // Security flags: P=1 (0x80) | session type=1
        #expect(data[3] == 0x81)
    }

    @Test("Roundtrip — minimal header")
    func roundtripMinimal() throws {
        let original = MessageHeader(
            sessionID: 0,
            messageCounter: 42
        )

        let data = original.encode()
        let (decoded, consumed) = try MessageHeader.decode(from: data)

        #expect(consumed == 8)
        #expect(decoded.sessionID == 0)
        #expect(decoded.messageCounter == 42)
        #expect(decoded.sourceNodeID == nil)
        #expect(decoded.destinationNodeID == nil)
        #expect(decoded.destinationGroupID == nil)
        #expect(decoded.isUnsecured == true)
    }

    @Test("Roundtrip — full header with source and dest node")
    func roundtripFull() throws {
        let original = MessageHeader(
            sessionID: 0xBEEF,
            securityFlags: MessageHeader.SecurityFlags(
                privacy: false,
                controlMessage: true,
                sessionType: .unicast
            ),
            messageCounter: 0xDEADBEEF,
            sourceNodeID: NodeID(rawValue: 0x1122334455667788),
            destinationNodeID: NodeID(rawValue: 0x99AABBCCDDEEFF00)
        )

        let data = original.encode()
        let (decoded, consumed) = try MessageHeader.decode(from: data)

        #expect(consumed == 24)
        #expect(decoded.sessionID == 0xBEEF)
        #expect(decoded.messageCounter == 0xDEADBEEF)
        #expect(decoded.sourceNodeID?.rawValue == 0x1122334455667788)
        #expect(decoded.destinationNodeID?.rawValue == 0x99AABBCCDDEEFF00)
        #expect(decoded.securityFlags.controlMessage == true)
        #expect(decoded.securityFlags.privacy == false)
        #expect(decoded.isUnsecured == false)
    }

    @Test("Roundtrip — group destination")
    func roundtripGroup() throws {
        let original = MessageHeader(
            sessionID: 10,
            securityFlags: MessageHeader.SecurityFlags(sessionType: .group),
            messageCounter: 999,
            sourceNodeID: NodeID(rawValue: 5),
            destinationGroupID: GroupID(rawValue: 0x1234)
        )

        let data = original.encode()
        let (decoded, _) = try MessageHeader.decode(from: data)

        #expect(decoded.destinationGroupID?.rawValue == 0x1234)
        #expect(decoded.destinationNodeID == nil)
        #expect(decoded.securityFlags.sessionType == .group)
    }

    @Test("Decode truncated data throws")
    func decodeTruncated() throws {
        // Only 4 bytes — need at least 8
        let data = Data([0x00, 0x00, 0x00, 0x00])
        #expect(throws: MessageError.self) {
            _ = try MessageHeader.decode(from: data)
        }
    }

    @Test("Unsecured session detection")
    func unsecuredSession() throws {
        let unsecured = MessageHeader(sessionID: 0, messageCounter: 1)
        #expect(unsecured.isUnsecured == true)

        let secured = MessageHeader(sessionID: 1, messageCounter: 1)
        #expect(secured.isUnsecured == false)
    }
}

// MARK: - Exchange Header Tests

@Suite("Exchange Header")
struct ExchangeHeaderTests {

    @Test("Encode minimal exchange header")
    func encodeMinimal() throws {
        let header = ExchangeHeader(
            flags: ExchangeFlags(initiator: true, reliableDelivery: true),
            protocolOpcode: SecureChannelOpcode.pbkdfParamRequest.rawValue,
            exchangeID: 1,
            protocolID: MatterProtocolID.secureChannel.rawValue
        )

        let data = header.encode()
        #expect(data.count == 6)

        // Flags: I=1 (0x01), R=1 (0x04) = 0x05
        #expect(data[0] == 0x05)
        // Opcode
        #expect(data[1] == 0x20)
        // Exchange ID (LE)
        #expect(data[2] == 0x01)
        #expect(data[3] == 0x00)
        // Protocol ID (LE)
        #expect(data[4] == 0x00)
        #expect(data[5] == 0x00)
    }

    @Test("Encode with acknowledgment")
    func encodeWithAck() throws {
        let header = ExchangeHeader(
            flags: ExchangeFlags(acknowledgment: true, reliableDelivery: true),
            protocolOpcode: InteractionModelOpcode.readRequest.rawValue,
            exchangeID: 42,
            protocolID: MatterProtocolID.interactionModel.rawValue,
            acknowledgedMessageCounter: 0x12345678
        )

        let data = header.encode()
        #expect(data.count == 10) // 6 base + 4 ack counter

        // Flags: A=1 (0x02), R=1 (0x04) = 0x06
        #expect(data[0] == 0x06)

        // Ack counter at end (LE)
        #expect(data[6] == 0x78)
        #expect(data[7] == 0x56)
        #expect(data[8] == 0x34)
        #expect(data[9] == 0x12)
    }

    @Test("Encode with vendor ID")
    func encodeWithVendor() throws {
        let header = ExchangeHeader(
            flags: ExchangeFlags(initiator: true),
            protocolOpcode: 0x01,
            exchangeID: 1,
            protocolVendorID: 0xFFF1,
            protocolID: 0x0001
        )

        let data = header.encode()
        #expect(data.count == 8) // 6 base + 2 vendor ID

        // V flag should be set (0x10)
        #expect(data[0] & 0x10 == 0x10)

        // Vendor ID (LE) before Protocol ID
        #expect(data[4] == 0xF1)
        #expect(data[5] == 0xFF)
        // Protocol ID (LE)
        #expect(data[6] == 0x01)
        #expect(data[7] == 0x00)
    }

    @Test("Roundtrip — Secure Channel PASE request")
    func roundtripPASE() throws {
        let original = ExchangeHeader(
            flags: ExchangeFlags(initiator: true, reliableDelivery: true),
            protocolOpcode: SecureChannelOpcode.pbkdfParamRequest.rawValue,
            exchangeID: 100,
            protocolID: MatterProtocolID.secureChannel.rawValue
        )

        let data = original.encode()
        let (decoded, consumed) = try ExchangeHeader.decode(from: data)

        #expect(consumed == 6)
        #expect(decoded.flags.initiator == true)
        #expect(decoded.flags.reliableDelivery == true)
        #expect(decoded.flags.acknowledgment == false)
        #expect(decoded.protocolOpcode == SecureChannelOpcode.pbkdfParamRequest.rawValue)
        #expect(decoded.exchangeID == 100)
        #expect(decoded.protocolID == MatterProtocolID.secureChannel.rawValue)
    }

    @Test("Roundtrip — Interaction Model with ack")
    func roundtripIMWithAck() throws {
        let original = ExchangeHeader(
            flags: ExchangeFlags(
                initiator: false,
                acknowledgment: true,
                reliableDelivery: true
            ),
            protocolOpcode: InteractionModelOpcode.reportData.rawValue,
            exchangeID: 0xFFFF,
            protocolID: MatterProtocolID.interactionModel.rawValue,
            acknowledgedMessageCounter: 0xAABBCCDD
        )

        let data = original.encode()
        let (decoded, consumed) = try ExchangeHeader.decode(from: data)

        #expect(consumed == 10)
        #expect(decoded.flags.initiator == false)
        #expect(decoded.flags.acknowledgment == true)
        #expect(decoded.protocolOpcode == InteractionModelOpcode.reportData.rawValue)
        #expect(decoded.exchangeID == 0xFFFF)
        #expect(decoded.protocolID == MatterProtocolID.interactionModel.rawValue)
        #expect(decoded.acknowledgedMessageCounter == 0xAABBCCDD)
    }

    @Test("Roundtrip — vendor-specific protocol")
    func roundtripVendor() throws {
        let original = ExchangeHeader(
            flags: ExchangeFlags(initiator: true),
            protocolOpcode: 0x42,
            exchangeID: 7,
            protocolVendorID: 0xFFF1,
            protocolID: 0x0099
        )

        let data = original.encode()
        let (decoded, _) = try ExchangeHeader.decode(from: data)

        #expect(decoded.flags.vendorIDPresent == true)
        #expect(decoded.protocolVendorID == 0xFFF1)
        #expect(decoded.protocolID == 0x0099)
        #expect(decoded.qualifiedProtocolID == 0xFFF10099)
    }

    @Test("Decode truncated data throws")
    func decodeTruncated() throws {
        let data = Data([0x05, 0x20, 0x01]) // only 3 bytes, need at least 6
        #expect(throws: MessageError.self) {
            _ = try ExchangeHeader.decode(from: data)
        }
    }

    @Test("Standalone ACK encoding")
    func standaloneAck() throws {
        let header = ExchangeHeader(
            flags: ExchangeFlags(acknowledgment: true),
            protocolOpcode: SecureChannelOpcode.standaloneAck.rawValue,
            exchangeID: 50,
            protocolID: MatterProtocolID.secureChannel.rawValue,
            acknowledgedMessageCounter: 12345
        )

        let data = header.encode()
        let (decoded, _) = try ExchangeHeader.decode(from: data)

        #expect(decoded.protocolOpcode == 0x10)
        #expect(decoded.acknowledgedMessageCounter == 12345)
    }
}

// MARK: - Exchange Flags Tests

@Suite("Exchange Flags")
struct ExchangeFlagsTests {

    @Test("All flags set")
    func allFlags() {
        let flags = ExchangeFlags(
            initiator: true,
            acknowledgment: true,
            reliableDelivery: true,
            securedExtension: true,
            vendorIDPresent: true
        )
        #expect(flags.rawValue == 0x1F)
    }

    @Test("No flags set")
    func noFlags() {
        let flags = ExchangeFlags()
        #expect(flags.rawValue == 0x00)
    }

    @Test("Roundtrip via raw value")
    func roundtripRawValue() {
        let original = ExchangeFlags(
            initiator: true,
            reliableDelivery: true
        )
        let decoded = ExchangeFlags(rawValue: original.rawValue)
        #expect(decoded == original)
    }
}

// MARK: - Full Message Tests

@Suite("Matter Message")
struct MatterMessageTests {

    @Test("Encode/decode unsecured PASE message")
    func unsecuredPASEMessage() throws {
        let msgHeader = MessageHeader(
            sessionID: 0,
            messageCounter: 1,
            sourceNodeID: NodeID(rawValue: 0x1234)
        )

        let exchHeader = ExchangeHeader(
            flags: ExchangeFlags(initiator: true, reliableDelivery: true),
            protocolOpcode: SecureChannelOpcode.pbkdfParamRequest.rawValue,
            exchangeID: 1,
            protocolID: MatterProtocolID.secureChannel.rawValue
        )

        let payload = Data([0x15, 0x30, 0x01, 0x20]) // some TLV data

        let encoded = MatterMessage.encodeUnsecured(
            messageHeader: msgHeader,
            exchangeHeader: exchHeader,
            payload: payload
        )

        let decoded = try MatterMessage.decodeUnsecured(from: encoded)

        #expect(decoded.messageHeader.sessionID == 0)
        #expect(decoded.messageHeader.messageCounter == 1)
        #expect(decoded.messageHeader.sourceNodeID?.rawValue == 0x1234)
        #expect(decoded.exchangeHeader?.protocolOpcode == 0x20)
        #expect(decoded.exchangeHeader?.exchangeID == 1)
        #expect(decoded.payload == payload)
    }

    @Test("Decode header only from encrypted message")
    func decodeHeaderOnly() throws {
        // Build a message with session ID != 0 (encrypted)
        let msgHeader = MessageHeader(
            sessionID: 0x1234,
            messageCounter: 500,
            sourceNodeID: NodeID(rawValue: 1)
        )

        var data = msgHeader.encode()
        let ciphertext = Data(repeating: 0xAB, count: 32) // fake encrypted payload
        data.append(ciphertext)

        let (decoded, payload) = try MatterMessage.decodeHeader(from: data)

        #expect(decoded.sessionID == 0x1234)
        #expect(decoded.messageCounter == 500)
        #expect(payload == ciphertext)
    }
}

// MARK: - Status Report Tests

@Suite("Status Report")
struct StatusReportTests {

    @Test("Encode success status report")
    func encodeSuccess() throws {
        let report = StatusReportMessage(
            generalStatus: .success,
            protocolID: 0x00000000, // Secure Channel
            protocolStatus: SecureChannelStatusCode.success.rawValue
        )

        let data = report.encode()
        #expect(data.count == 8) // 2 + 4 + 2

        // General status (LE)
        #expect(data[0] == 0x00)
        #expect(data[1] == 0x00)
        // Protocol ID (LE)
        #expect(data[2] == 0x00)
        #expect(data[3] == 0x00)
        #expect(data[4] == 0x00)
        #expect(data[5] == 0x00)
        // Protocol status (LE)
        #expect(data[6] == 0x00)
        #expect(data[7] == 0x00)
    }

    @Test("Encode busy with wait time")
    func encodeBusy() throws {
        var waitTime = Data()
        waitTime.appendLittleEndian(UInt16(500)) // 500ms minimum wait

        let report = StatusReportMessage(
            generalStatus: .busy,
            protocolID: 0x00000000,
            protocolStatus: SecureChannelStatusCode.busy.rawValue,
            protocolData: waitTime
        )

        let data = report.encode()
        #expect(data.count == 10) // 8 base + 2 wait time
    }

    @Test("Roundtrip status report")
    func roundtrip() throws {
        let original = StatusReportMessage(
            generalStatus: .failure,
            protocolID: 0x00000001, // Interaction Model
            protocolStatus: 0x0087   // constraintError
        )

        let data = original.encode()
        let decoded = try StatusReportMessage.decode(from: data)

        #expect(decoded.generalStatus == .failure)
        #expect(decoded.protocolID == 0x00000001)
        #expect(decoded.protocolStatus == 0x0087)
        #expect(decoded.protocolData == nil)
    }

    @Test("Roundtrip with protocol data")
    func roundtripWithData() throws {
        let extra = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let original = StatusReportMessage(
            generalStatus: .resourceExhausted,
            protocolID: 0x00000000,
            protocolStatus: 0,
            protocolData: extra
        )

        let data = original.encode()
        let decoded = try StatusReportMessage.decode(from: data)

        #expect(decoded.generalStatus == .resourceExhausted)
        #expect(decoded.protocolData == extra)
    }
}

// MARK: - Security Flags Tests

@Suite("Security Flags")
struct SecurityFlagsTests {

    @Test("Default flags")
    func defaults() {
        let flags = MessageHeader.SecurityFlags()
        #expect(flags.rawValue == 0x00)
        #expect(flags.privacy == false)
        #expect(flags.controlMessage == false)
        #expect(flags.messageExtension == false)
        #expect(flags.sessionType == .unicast)
    }

    @Test("All flags set")
    func allSet() {
        let flags = MessageHeader.SecurityFlags(
            privacy: true,
            controlMessage: true,
            messageExtension: true,
            sessionType: .group
        )
        // P(0x80) | C(0x40) | MX(0x20) | group(0x01) = 0xE1
        #expect(flags.rawValue == 0xE1)
    }

    @Test("Roundtrip via raw value")
    func roundtrip() {
        let original = MessageHeader.SecurityFlags(
            privacy: true,
            sessionType: .group
        )
        let decoded = MessageHeader.SecurityFlags(rawValue: original.rawValue)
        #expect(decoded == original)
    }
}

// MARK: - Protocol ID Tests

@Suite("Protocol IDs")
struct ProtocolIDTests {

    @Test("Qualified protocol ID computation")
    func qualifiedID() {
        let header = ExchangeHeader(
            protocolOpcode: 0,
            exchangeID: 0,
            protocolVendorID: 0xFFF1,
            protocolID: 0x0002
        )
        #expect(header.qualifiedProtocolID == 0xFFF10002)
    }

    @Test("Standard protocol qualified ID — vendor 0 omitted")
    func standardProtocolID() {
        let header = ExchangeHeader(
            protocolOpcode: 0,
            exchangeID: 0,
            protocolID: MatterProtocolID.interactionModel.rawValue
        )
        #expect(header.qualifiedProtocolID == 0x00000001)
        #expect(header.flags.vendorIDPresent == false)
    }
}
