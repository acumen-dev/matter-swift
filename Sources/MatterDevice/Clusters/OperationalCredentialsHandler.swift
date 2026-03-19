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

    public func acceptedCommands() -> [CommandID] {
        [
            OperationalCredentialsCluster.Command.attestationRequest,
            OperationalCredentialsCluster.Command.certificateChainRequest,
            OperationalCredentialsCluster.Command.csrRequest,
            OperationalCredentialsCluster.Command.addNOC,
            OperationalCredentialsCluster.Command.addTrustedRootCert,
            OperationalCredentialsCluster.Command.removeFabric,
            OperationalCredentialsCluster.Command.updateFabricLabel,
        ]
    }

    public func generatedCommands() -> [CommandID] {
        [
            OperationalCredentialsCluster.Command.attestationResponse,
            OperationalCredentialsCluster.Command.certificateChainResponse,
            OperationalCredentialsCluster.Command.csrResponse,
            OperationalCredentialsCluster.Command.nocResponse,
        ]
    }

    public func handleCommand(
        commandID: CommandID,
        fields: TLVElement?,
        store: AttributeStore,
        endpointID: EndpointID
    ) throws -> TLVElement? {
        switch commandID {
        case OperationalCredentialsCluster.Command.attestationRequest:
            return try handleAttestationRequest(fields: fields)

        case OperationalCredentialsCluster.Command.certificateChainRequest:
            return try handleCertificateChainRequest(fields: fields)

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

    // MARK: - Response Command IDs

    /// Maps request command IDs to their response command IDs per the Matter spec.
    ///
    /// Per spec §11.17.7, attestation/chain/CSR commands have paired response commands
    /// and addNOC/updateNOC/updateFabricLabel/removeFabric all respond with NOCResponse (0x08).
    /// addTrustedRootCert produces no response data (status-only).
    public func responseCommandID(for requestCommandID: CommandID) -> CommandID? {
        switch requestCommandID {
        case OperationalCredentialsCluster.Command.attestationRequest:
            return OperationalCredentialsCluster.Command.attestationResponse
        case OperationalCredentialsCluster.Command.certificateChainRequest:
            return OperationalCredentialsCluster.Command.certificateChainResponse
        case OperationalCredentialsCluster.Command.csrRequest:
            return OperationalCredentialsCluster.Command.csrResponse
        case OperationalCredentialsCluster.Command.addNOC,
             OperationalCredentialsCluster.Command.updateNOC,
             OperationalCredentialsCluster.Command.updateFabricLabel,
             OperationalCredentialsCluster.Command.removeFabric:
            return OperationalCredentialsCluster.Command.nocResponse
        default:
            return nil
        }
    }

    // MARK: - AttestationRequest

    /// Handle AttestationRequest command (0x00).
    ///
    /// Per Matter spec §11.17.6.1:
    /// - Parses attestationNonce from the request
    /// - Builds attestationElements TLV (CD, nonce, timestamp)
    /// - Signs attestationElements || attestationChallenge with DAC key
    /// - Returns AttestationResponse (0x01)
    private func handleAttestationRequest(fields: TLVElement?) throws -> TLVElement {
        guard let fields,
              case .structure(let structFields) = fields,
              let nonce = structFields.first(where: { $0.tag == .contextSpecific(0) })?.value.dataValue else {
            // Return empty structure — commissioner will reject without valid elements
            return TLVElement.structure([])
        }

        // Get attestation credentials from commissioning state
        guard let credentials = commissioningState.attestationCredentials else {
            return TLVElement.structure([])
        }

        // Build attestationElements TLV per Matter spec §11.17.6.2:
        // Structure { 1: certificationDeclaration, 2: attestationNonce, 3: timestamp }
        let timestamp: UInt32 = 0  // Matter epoch seconds — 0 for test devices
        let attestationElements = TLVEncoder.encode(
            .structure([
                .init(tag: .contextSpecific(1), value: .octetString(credentials.certificationDeclaration)),
                .init(tag: .contextSpecific(2), value: .octetString(nonce)),
                .init(tag: .contextSpecific(3), value: .unsignedInt(UInt64(timestamp))),
            ])
        )

        // Sign attestationElements || attestationChallenge with DAC private key.
        // Per Matter spec §11.17.6.3 the signature field is a 64-byte raw ECDSA
        // signature (r ‖ s, each 32 bytes), NOT DER-encoded.
        let challenge = commissioningState.attestationChallenge ?? Data()
        let messageToSign = attestationElements + challenge
        let signature = try credentials.dacPrivateKey.signature(for: messageToSign)

        // Return AttestationResponse: { 0: attestationElements, 1: attestationSignature }
        return TLVElement.structure([
            .init(tag: .contextSpecific(0), value: .octetString(attestationElements)),
            .init(tag: .contextSpecific(1), value: .octetString(Data(signature.rawRepresentation))),
        ])
    }

    // MARK: - CertificateChainRequest

    /// Handle CertificateChainRequest command (0x02).
    ///
    /// Per Matter spec §11.17.6.3:
    /// - certificateType 1 = DAC
    /// - certificateType 2 = PAI
    /// Returns CertificateChainResponse (0x03): { 0: certificate (DER bytes) }
    private func handleCertificateChainRequest(fields: TLVElement?) throws -> TLVElement {
        guard let fields,
              case .structure(let structFields) = fields,
              let certTypeValue = structFields.first(where: { $0.tag == .contextSpecific(0) })?.value.uintValue else {
            return TLVElement.structure([])
        }

        guard let credentials = commissioningState.attestationCredentials else {
            return TLVElement.structure([])
        }

        let certData: Data
        switch UInt8(certTypeValue) {
        case 1:
            certData = credentials.dacCertificate
        case 2:
            certData = credentials.paiCertificate
        default:
            return TLVElement.structure([])
        }

        return TLVElement.structure([
            .init(tag: .contextSpecific(0), value: .octetString(certData)),
        ])
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

        // Build a proper DER-encoded PKCS#10 CSR with the operational key
        let csrData = try PKCS10CSRBuilder.buildCSR(privateKey: opKey)

        let nocsrElements = TLVEncoder.encode(
            .structure([
                .init(tag: .contextSpecific(1), value: .octetString(csrData)),
                .init(tag: .contextSpecific(2), value: .octetString(request.csrNonce)),
            ])
        )

        // Sign nocsrElements || attestationChallenge with DAC key if available,
        // otherwise fall back to the operational key (test/dev only).
        let challenge = commissioningState.attestationChallenge ?? Data()
        let messageToSign = nocsrElements + challenge

        // Per Matter spec §11.17.6.6 the CSRResponse attestation_signature is also a
        // 64-byte raw ECDSA signature (r ‖ s), NOT DER-encoded.
        let attestationSignature: Data
        if let credentials = commissioningState.attestationCredentials {
            let sig = try credentials.dacPrivateKey.signature(for: messageToSign)
            attestationSignature = Data(sig.rawRepresentation)
        } else {
            let sig = try opKey.signature(for: messageToSign)
            attestationSignature = Data(sig.rawRepresentation)
        }

        let response = OperationalCredentialsCluster.CSRResponse(
            nocsrElements: nocsrElements,
            attestationSignature: attestationSignature
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

        // Per Matter spec §11.17.6.8, the device SHALL create an initial ACL entry granting
        // Administer privilege to the CaseAdminSubject. Without this, the CASE session that
        // carries CommissioningComplete would be denied access.
        do {
            let adminACE = AccessControlCluster.AccessControlEntry(
                privilege: .administer,
                authMode: .case,
                subjects: [addNOC.caseAdminSubject],
                targets: nil,
                fabricIndex: FabricIndex(rawValue: 0)  // Placeholder — stamped on commit
            )
            commissioningState.stagedACLs = [adminACE]
        }

        // Per Matter spec §4.3.5, the device SHALL begin operational mDNS advertisement
        // immediately after the NOC is installed (staged), before CommissioningComplete.
        // This allows Apple Home (and other commissioners) to discover the device operationally.
        commissioningState.onNOCStaged?()

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

    // MARK: - Fabric Scoping

    /// NOCs list, fabrics list, and currentFabricIndex are all fabric-scoped.
    public func isFabricScoped(attributeID: AttributeID) -> Bool {
        attributeID == OperationalCredentialsCluster.Attribute.nocs
            || attributeID == OperationalCredentialsCluster.Attribute.fabrics
            || attributeID == OperationalCredentialsCluster.Attribute.currentFabricIndex
    }

    /// Filter fabric-scoped OperationalCredentials attributes.
    ///
    /// - NOCs list: filter entries by fabricIndex field (context tag `0xFE`).
    /// - Fabrics list: filter entries by fabricIndex field (context tag `0xFE`).
    /// - currentFabricIndex: return the requesting fabric's index directly.
    public func filterFabricScopedAttribute(attributeID: AttributeID, value: TLVElement, fabricIndex: FabricIndex) -> TLVElement {
        switch attributeID {
        case OperationalCredentialsCluster.Attribute.nocs,
             OperationalCredentialsCluster.Attribute.fabrics:
            guard case .array(let elements) = value else { return value }
            let filtered = elements.filter { element in
                guard case .structure(let fields) = element,
                      let fiValue = fields.first(where: { $0.tag == .contextSpecific(0xFE) })?.value.uintValue else {
                    return false
                }
                return UInt8(fiValue) == fabricIndex.rawValue
            }
            return .array(filtered)

        case OperationalCredentialsCluster.Attribute.currentFabricIndex:
            return .unsignedInt(UInt64(fabricIndex.rawValue))

        default:
            return value
        }
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

}
