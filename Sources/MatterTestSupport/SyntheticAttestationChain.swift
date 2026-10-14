// SyntheticAttestationChain.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import SwiftASN1
import X509

// MARK: - SyntheticAttestationChain

/// A Matter-profile PAA → PAI → DAC chain built in-process, with chosen validity, signers and
/// key identifiers, for attestation tests that the connectedhomeip vectors do not isolate.
///
/// Every certificate is P-256 / ecdsa-with-SHA256 with critical basicConstraints and keyUsage
/// and a 20-byte SubjectKeyIdentifier; the PAI and DAC carry AuthorityKeyIdentifiers. All
/// three name VID 0xFFF1; the DAC names PID 0x8000.
public struct SyntheticAttestationChain: Sendable {

    public let paa: Data
    public let pai: Data
    public let dac: Data
    public let dacKey: P256.Signing.PrivateKey

    static let vidOID: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 37244, 2, 1]
    static let pidOID: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 37244, 2, 2]

    /// - Parameters:
    ///   - paiSigner: signs the PAI instead of the PAA key (the PAI still names the PAA).
    ///   - paiAKI: the PAI's AuthorityKeyIdentifier; defaults to the PAA's SKI.
    ///   - dacSigner: signs the DAC instead of the PAI key (the DAC still names the PAI).
    ///   - dacAKI: the DAC's AuthorityKeyIdentifier; defaults to the PAI's SKI.
    ///   - dacCriticalSubjectAlternativeName: add a critical SAN to the DAC.
    public init(
        paaValidity: ClosedRange<Date>,
        paiValidity: ClosedRange<Date>,
        dacValidity: ClosedRange<Date>,
        paiSigner: P256.Signing.PrivateKey? = nil,
        paiAKI: [UInt8]? = nil,
        dacSigner: P256.Signing.PrivateKey? = nil,
        dacAKI: [UInt8]? = nil,
        dacCriticalSubjectAlternativeName: Bool = false
    ) throws {
        let paaKey = P256.Signing.PrivateKey()
        let paiKey = P256.Signing.PrivateKey()
        let dacKey = P256.Signing.PrivateKey()
        let paaSKI = SubjectKeyIdentifier(hash: Certificate.PublicKey(paaKey.publicKey))
        let paiSKI = SubjectKeyIdentifier(hash: Certificate.PublicKey(paiKey.publicKey))
        let paaName = Self.name("Synthetic PAA", vid: "FFF1")
        let paiName = Self.name("Synthetic PAI", vid: "FFF1")

        let paa = try Certificate(
            version: .v3, serialNumber: .init(), publicKey: .init(paaKey.publicKey),
            notValidBefore: paaValidity.lowerBound, notValidAfter: paaValidity.upperBound,
            issuer: paaName, subject: paaName, signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 1))
                Critical(KeyUsage(keyCertSign: true, cRLSign: true))
                paaSKI
            },
            issuerPrivateKey: .init(paaKey)
        )
        let pai = try Certificate(
            version: .v3, serialNumber: .init(), publicKey: .init(paiKey.publicKey),
            notValidBefore: paiValidity.lowerBound, notValidAfter: paiValidity.upperBound,
            issuer: paaName, subject: paiName, signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0))
                Critical(KeyUsage(keyCertSign: true, cRLSign: true))
                paiSKI
                AuthorityKeyIdentifier(keyIdentifier: ArraySlice(paiAKI ?? Array(paaSKI.keyIdentifier)))
            },
            issuerPrivateKey: .init(paiSigner ?? paaKey)
        )
        let dac = try Certificate(
            version: .v3, serialNumber: .init(), publicKey: .init(dacKey.publicKey),
            notValidBefore: dacValidity.lowerBound, notValidAfter: dacValidity.upperBound,
            issuer: paiName, subject: Self.name("Synthetic DAC", vid: "FFF1", pid: "8000"),
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.notCertificateAuthority)
                Critical(KeyUsage(digitalSignature: true))
                SubjectKeyIdentifier(hash: Certificate.PublicKey(dacKey.publicKey))
                AuthorityKeyIdentifier(keyIdentifier: ArraySlice(dacAKI ?? Array(paiSKI.keyIdentifier)))
                if dacCriticalSubjectAlternativeName {
                    Critical(SubjectAlternativeNames([.dnsName("device.example")]))
                }
            },
            issuerPrivateKey: .init(dacSigner ?? paiKey)
        )
        self.paa = try Self.der(paa)
        self.pai = try Self.der(pai)
        self.dac = try Self.der(dac)
        self.dacKey = dacKey
    }

    /// A UTC date at the start of `year`.
    public static func date(_ year: Int, month: Int = 1, day: Int = 1) -> Date {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        return calendar.date(from: DateComponents(year: year, month: month, day: day))!
    }

    // MARK: - Helpers

    private static func name(_ commonName: String, vid: String, pid: String? = nil) -> DistinguishedName {
        var rdns = [
            RelativeDistinguishedName(.init(type: .RDNAttributeType.commonName, utf8String: commonName)),
            RelativeDistinguishedName(.init(type: vidOID, utf8String: vid)),
        ]
        if let pid { rdns.append(RelativeDistinguishedName(.init(type: pidOID, utf8String: pid))) }
        return DistinguishedName(rdns)
    }

    private static func der(_ certificate: Certificate) throws -> Data {
        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        return Data(serializer.serializedBytes)
    }
}
