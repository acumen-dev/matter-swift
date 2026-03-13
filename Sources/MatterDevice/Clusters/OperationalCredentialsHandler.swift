// OperationalCredentialsHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import MatterTypes
import MatterModel
import MatterCrypto

/// Cluster handler for the Operational Credentials cluster (0x003E).
///
/// Handles CSRRequest (generates operational key pair + CSR), AddTrustedRootCert
/// (stages RCAC), and AddNOC (stages NOC + IPK). Credentials are staged in
/// `CommissioningState` and only committed when `CommissioningComplete` fires.
public struct OperationalCredentialsHandler: ClusterHandler, @unchecked Sendable {

    public let clusterID = ClusterID.operationalCredentials

    /// Shared commissioning state for staging credentials.
    public let commissioningState: CommissioningState

    public init(commissioningState: CommissioningState) {
        self.commissioningState = commissioningState
    }

    // MARK: - ClusterHandler

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        [
            (OperationalCredentialsCluster.Attribute.supportedFabrics, .unsignedInt(5)),
            (OperationalCredentialsCluster.Attribute.commissionedFabrics, .unsignedInt(0)),
            (OperationalCredentialsCluster.Attribute.trustedRootCerts, .array([])),
            (OperationalCredentialsCluster.Attribute.currentFabricIndex, .unsignedInt(0)),
            (OperationalCredentialsCluster.Attribute.fabrics, .array([])),
        ]
    }

    public func handleCommand(
        commandID: CommandID,
        fields: TLVElement?,
        store: AttributeStore,
        endpointID: EndpointID
    ) throws -> TLVElement? {
        switch commandID {
        case OperationalCredentialsCluster.Command.csrRequest:
            return try handleCSRRequest(fields: fields)

        case OperationalCredentialsCluster.Command.addNOC:
            return try handleAddNOC(fields: fields, store: store, endpointID: endpointID)

        case OperationalCredentialsCluster.Command.addTrustedRootCert:
            return try handleAddTrustedRootCert(fields: fields)

        case OperationalCredentialsCluster.Command.removeFabric:
            return handleRemoveFabric(fields: fields, store: store, endpointID: endpointID)

        case OperationalCredentialsCluster.Command.updateFabricLabel:
            return handleUpdateFabricLabel(fields: fields, store: store, endpointID: endpointID)

        default:
            return nil
        }
    }

    // MARK: - CSRRequest

    private func handleCSRRequest(fields: TLVElement?) throws -> TLVElement {
        guard let fields else {
            return nocResponse(.missingCSR, debugText: "Missing fields")
        }

        guard commissioningState.isFailSafeArmed else {
            return nocResponse(.missingCSR, debugText: "Fail-safe not armed")
        }

        let request = try OperationalCredentialsCluster.CSRRequest.fromTLVElement(fields)

        // Generate new operational key pair
        let opKey = commissioningState.generateOperationalKey(csrNonce: request.csrNonce)

        // Build NOCSRElements TLV:
        // Structure { 1: csr (octet string), 2: csrNonce (octet string) }
        // The CSR is a DER-encoded PKCS#10 containing the public key.
        // For simplicity, we encode just the raw public key (65 bytes, uncompressed P-256).
        // Real Matter devices would produce a proper PKCS#10 CSR.
        let csrData = buildSimpleCSR(publicKey: opKey.publicKey)

        let nocsrElements = TLVEncoder.encode(
            .structure([
                .init(tag: .contextSpecific(1), value: .octetString(csrData)),
                .init(tag: .contextSpecific(2), value: .octetString(request.csrNonce)),
            ])
        )

        // Sign with a dummy attestation key (test/dev only — real devices use DAC)
        let signature = try opKey.signature(for: nocsrElements)

        let response = OperationalCredentialsCluster.CSRResponse(
            nocsrElements: nocsrElements,
            attestationSignature: Data(signature.derRepresentation)
        )

        return response.toTLVElement()
    }

    // MARK: - AddTrustedRootCert

    private func handleAddTrustedRootCert(fields: TLVElement?) throws -> TLVElement? {
        guard let fields else { return nil }
        guard commissioningState.isFailSafeArmed else { return nil }

        // AddTrustedRootCertificate: Structure { 0: rootCACertificate (octet string) }
        guard case .structure(let structFields) = fields,
              let rcacData = structFields.first(where: { $0.tag == .contextSpecific(0) })?.value.dataValue else {
            return nil
        }

        commissioningState.stagedRCAC = rcacData

        // No response payload — status-only
        return nil
    }

    // MARK: - AddNOC

    private func handleAddNOC(
        fields: TLVElement?,
        store: AttributeStore,
        endpointID: EndpointID
    ) throws -> TLVElement {
        guard let fields else {
            return nocResponse(.invalidNOC, debugText: "Missing fields")
        }

        guard commissioningState.isFailSafeArmed else {
            return nocResponse(.invalidNOC, debugText: "Fail-safe not armed")
        }

        let addNOC = try OperationalCredentialsCluster.AddNOCCommand.fromTLVElement(fields)

        // Stage the credentials
        commissioningState.stagedNOC = addNOC.nocValue
        commissioningState.stagedICAC = addNOC.icacValue
        commissioningState.stagedIPK = addNOC.ipkValue
        commissioningState.stagedCaseAdminSubject = addNOC.caseAdminSubject
        commissioningState.stagedAdminVendorId = addNOC.adminVendorId

        // Return success with the fabric index that will be assigned
        let pendingIndex = FabricIndex(rawValue: UInt8(commissioningState.fabrics.count + 1))

        return OperationalCredentialsCluster.NOCResponse(
            statusCode: .ok,
            fabricIndex: pendingIndex
        ).toTLVElement()
    }

    // MARK: - RemoveFabric

    /// Handle RemoveFabric command.
    ///
    /// Per Matter spec §11.17.6.12:
    /// - Removes the fabric, its ACLs, and triggers cleanup callbacks
    /// - Returns NOCResponse with status
    private func handleRemoveFabric(
        fields: TLVElement?,
        store: AttributeStore,
        endpointID: EndpointID
    ) -> TLVElement {
        guard let fields,
              case .structure(let structFields) = fields,
              let fabricIndexValue = structFields.first(where: { $0.tag == .contextSpecific(0) })?.value.uintValue else {
            return nocResponse(.invalidFabricIndex, debugText: "Missing fabricIndex field")
        }

        let fabricIndex = FabricIndex(rawValue: UInt8(fabricIndexValue))

        guard commissioningState.removeFabric(fabricIndex) else {
            return nocResponse(.invalidFabricIndex, debugText: "Fabric \(fabricIndex) not found")
        }

        // Update cluster attributes
        updateFabricAttributes(store: store, endpointID: endpointID)

        return OperationalCredentialsCluster.NOCResponse(
            statusCode: .ok,
            fabricIndex: fabricIndex
        ).toTLVElement()
    }

    // MARK: - UpdateFabricLabel

    /// Handle UpdateFabricLabel command.
    ///
    /// Per Matter spec §11.17.6.11:
    /// - Updates the label on an existing fabric
    /// - Returns NOCResponse with status
    private func handleUpdateFabricLabel(
        fields: TLVElement?,
        store: AttributeStore,
        endpointID: EndpointID
    ) -> TLVElement {
        guard let fields,
              case .structure(let structFields) = fields,
              let label = structFields.first(where: { $0.tag == .contextSpecific(0) })?.value.stringValue else {
            return nocResponse(.invalidFabricIndex, debugText: "Missing label field")
        }

        // UpdateFabricLabel updates the current session's fabric
        // For now, we need the fabric index from context. Since we don't have session
        // context in handleCommand, we check if there's a fabricIndex field (tag 1)
        // or default to the first fabric.
        let fabricIndex: FabricIndex
        if let fidxValue = structFields.first(where: { $0.tag == .contextSpecific(1) })?.value.uintValue {
            fabricIndex = FabricIndex(rawValue: UInt8(fidxValue))
        } else {
            // Per spec, UpdateFabricLabel operates on the accessing fabric.
            // Without session context here, we use the invoking fabric stored on
            // CommissioningState (set by the server before dispatch).
            guard let invokingFabric = commissioningState.invokingFabricIndex else {
                return nocResponse(.invalidFabricIndex, debugText: "No invoking fabric context")
            }
            fabricIndex = invokingFabric
        }

        guard commissioningState.fabrics[fabricIndex] != nil else {
            return nocResponse(.invalidFabricIndex, debugText: "Fabric \(fabricIndex) not found")
        }

        // Check for label conflicts — no two fabrics can share the same non-empty label
        if !label.isEmpty {
            let conflict = commissioningState.fabrics.contains { (idx, fabric) in
                idx != fabricIndex && fabric.label == label
            }
            if conflict {
                return nocResponse(.labelConflict, debugText: "Label '\(label)' already in use")
            }
        }

        commissioningState.fabrics[fabricIndex]?.label = label
        updateFabricAttributes(store: store, endpointID: endpointID)

        return OperationalCredentialsCluster.NOCResponse(
            statusCode: .ok,
            fabricIndex: fabricIndex
        ).toTLVElement()
    }

    // MARK: - Attribute Updates

    /// Update OperationalCredentials cluster attributes to reflect current fabric state.
    private func updateFabricAttributes(store: AttributeStore, endpointID: EndpointID) {
        store.set(
            endpoint: endpointID,
            cluster: clusterID,
            attribute: OperationalCredentialsCluster.Attribute.commissionedFabrics,
            value: .unsignedInt(UInt64(commissioningState.fabrics.count))
        )
    }

    // MARK: - Helpers

    private func nocResponse(_ status: OperationalCredentialsCluster.NOCStatus, debugText: String = "") -> TLVElement {
        OperationalCredentialsCluster.NOCResponse(
            statusCode: status,
            debugText: debugText
        ).toTLVElement()
    }

    /// Build a simple CSR-like structure containing the raw public key.
    ///
    /// Real Matter devices produce a proper DER-encoded PKCS#10 CSR.
    /// For our bridge, we encode a minimal structure that the commissioner
    /// can parse to extract the public key (uncompressed P-256, 65 bytes).
    private func buildSimpleCSR(publicKey: P256.Signing.PublicKey) -> Data {
        // Minimal DER PKCS#10 CSR structure
        // For compatibility with CommissioningController.handleCSRResponse(),
        // we produce a real PKCS#10 CSR-like DER structure.
        // The public key is at a known offset that the controller parses.
        let pubKeyData = Data(publicKey.x963Representation) // 65 bytes uncompressed
        return buildDERCSR(publicKey: pubKeyData)
    }

    /// Build a minimal DER-encoded PKCS#10 CSR.
    ///
    /// Structure: SEQUENCE { SEQUENCE { version, subject, subjectPKInfo } }
    /// The commissioner only needs to extract the public key from subjectPKInfo.
    private func buildDERCSR(publicKey: Data) -> Data {
        // SubjectPublicKeyInfo for P-256
        let algOID: [UInt8] = [
            0x30, 0x13,             // SEQUENCE (19 bytes)
            0x06, 0x07,             // OID: 1.2.840.10045.2.1 (EC public key)
            0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
            0x06, 0x08,             // OID: 1.2.840.10045.3.1.7 (P-256)
            0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
        ]

        // BIT STRING wrapper for the public key
        let bitString: [UInt8] = [0x03, UInt8(publicKey.count + 1), 0x00] + [UInt8](publicKey)

        // SubjectPublicKeyInfo
        let spkiContent = algOID + bitString
        let spki: [UInt8] = [0x30, UInt8(spkiContent.count)] + spkiContent

        // CertificationRequestInfo
        let version: [UInt8] = [0x02, 0x01, 0x00]  // INTEGER 0
        let subject: [UInt8] = [0x30, 0x00]          // Empty SEQUENCE (no subject DN)
        let criContent = version + subject + spki
        let cri: [UInt8] = [0x30, UInt8(criContent.count)] + criContent

        // Outer SEQUENCE (no signature — simplified for bridge use)
        let outer: [UInt8] = [0x30, UInt8(cri.count)] + cri

        return Data(outer)
    }
}
