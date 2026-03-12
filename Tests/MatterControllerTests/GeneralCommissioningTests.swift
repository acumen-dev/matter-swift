// GeneralCommissioningTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
@testable import MatterModel
import MatterTypes

@Suite("GeneralCommissioning Cluster")
struct GeneralCommissioningTests {

    @Test("ArmFailSafeRequest TLV round-trip")
    func armFailSafeRequestRoundTrip() throws {
        let request = GeneralCommissioningCluster.ArmFailSafeRequest(
            expiryLengthSeconds: 60,
            breadcrumb: 42
        )

        let tlv = request.toTLVElement()
        let encoded = TLVEncoder.encode(tlv)
        let (_, decoded) = try TLVDecoder.decode(encoded)
        let parsed = try GeneralCommissioningCluster.ArmFailSafeRequest.fromTLVElement(decoded)

        #expect(parsed.expiryLengthSeconds == 60)
        #expect(parsed.breadcrumb == 42)
    }

    @Test("ArmFailSafeResponse TLV round-trip")
    func armFailSafeResponseRoundTrip() throws {
        let response = GeneralCommissioningCluster.ArmFailSafeResponse(
            errorCode: .ok,
            debugText: "Success"
        )

        let tlv = response.toTLVElement()
        let encoded = TLVEncoder.encode(tlv)
        let (_, decoded) = try TLVDecoder.decode(encoded)
        let parsed = try GeneralCommissioningCluster.ArmFailSafeResponse.fromTLVElement(decoded)

        #expect(parsed.errorCode == .ok)
        #expect(parsed.debugText == "Success")
    }

    @Test("SetRegulatoryConfigRequest TLV round-trip")
    func setRegulatoryConfigRequestRoundTrip() throws {
        let request = GeneralCommissioningCluster.SetRegulatoryConfigRequest(
            newRegulatoryConfig: .indoorOutdoor,
            countryCode: "AU",
            breadcrumb: 99
        )

        let tlv = request.toTLVElement()
        let encoded = TLVEncoder.encode(tlv)
        let (_, decoded) = try TLVDecoder.decode(encoded)
        let parsed = try GeneralCommissioningCluster.SetRegulatoryConfigRequest.fromTLVElement(decoded)

        #expect(parsed.newRegulatoryConfig == .indoorOutdoor)
        #expect(parsed.countryCode == "AU")
        #expect(parsed.breadcrumb == 99)
    }

    @Test("SetRegulatoryConfigResponse TLV round-trip")
    func setRegulatoryConfigResponseRoundTrip() throws {
        let response = GeneralCommissioningCluster.SetRegulatoryConfigResponse(
            errorCode: .valueOutsideRange,
            debugText: "Bad value"
        )

        let tlv = response.toTLVElement()
        let encoded = TLVEncoder.encode(tlv)
        let (_, decoded) = try TLVDecoder.decode(encoded)
        let parsed = try GeneralCommissioningCluster.SetRegulatoryConfigResponse.fromTLVElement(decoded)

        #expect(parsed.errorCode == .valueOutsideRange)
        #expect(parsed.debugText == "Bad value")
    }

    @Test("CommissioningCompleteResponse TLV round-trip")
    func commissioningCompleteResponseRoundTrip() throws {
        let response = GeneralCommissioningCluster.CommissioningCompleteResponse(
            errorCode: .ok,
            debugText: ""
        )

        let tlv = response.toTLVElement()
        let encoded = TLVEncoder.encode(tlv)
        let (_, decoded) = try TLVDecoder.decode(encoded)
        let parsed = try GeneralCommissioningCluster.CommissioningCompleteResponse.fromTLVElement(decoded)

        #expect(parsed.errorCode == .ok)
        #expect(parsed.debugText == "")
    }
}
