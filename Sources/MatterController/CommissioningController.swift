// CommissioningController.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import MatterTypes
import MatterModel
import MatterCrypto
import MatterProtocol

/// Orchestrates the full Matter commissioning flow.
///
/// Each method is a pure step: takes context + response data, returns the
/// next message(s) + updated context. No networking — the caller handles
/// message transport.
///
/// ## Commissioning Flow
///
/// 1. PASE session establishment (PBKDFParamRequest → Pake3)
/// 2. ArmFailSafe
/// 3. SetRegulatoryConfig
/// 4. CSRRequest → generate NOC
/// 5. AddTrustedRootCert + AddNOC
/// 6. ACL write (grant controller admin access)
/// 7. CommissioningComplete
///
/// ```swift
/// let cc = CommissioningController(fabricManager: mgr)
/// let (msg, ctx) = cc.beginPASE(passcode: 20202021, initiatorSessionID: 1)
/// // ... send/receive messages through each step ...
/// let device = try cc.handleCommissioningComplete(response: data, context: ctx)
/// ```
public struct CommissioningController: Sendable {

    private let fabricManager: FabricManager

    public init(fabricManager: FabricManager) {
        self.fabricManager = fabricManager
    }

    // MARK: - Commissioning Context

    /// Accumulated state across commissioning steps.
    public struct CommissioningContext: Sendable {
        /// PASE session (nil until PASE completes).
        public var paseSession: SecureSession?

        /// PASE handshake sub-context.
        public var paseRequestContext: PASESession.PBKDFParamRequestContext?
        public var pasePake1Context: PASESession.Pake1Context?

        /// The PASESession helper.
        public var paseSessionHelper: PASESession?

        /// Node ID allocated for the commissioned device.
        public var deviceNodeID: NodeID?

        /// Responder session ID from PASE.
        public var responderSessionID: UInt16?

        /// Initiator session ID used for PASE.
        public var initiatorSessionID: UInt16?

        /// Fabric index of the controller.
        public var fabricIndex: FabricIndex?

        /// Attestation challenge from the PASE session keys (16 bytes).
        /// Used to verify the attestation signature in the AttestationResponse.
        public var attestationChallenge: Data?

        public init() {}
    }

    // MARK: - Step 1: Begin PASE

    /// Start PASE session establishment by creating a PBKDFParamRequest.
    ///
    /// - Parameters:
    ///   - passcode: The device's setup passcode.
    ///   - initiatorSessionID: Session ID to propose.
    /// - Returns: TLV-encoded PBKDFParamRequest and commissioning context.
    public func beginPASE(
        passcode: UInt32,
        initiatorSessionID: UInt16
    ) -> (message: Data, context: CommissioningContext) {
        let pase = PASESession(passcode: passcode)
        let (pbkdfReq, paseCtx) = pase.createPBKDFParamRequest(
            initiatorSessionID: initiatorSessionID
        )

        var ctx = CommissioningContext()
        ctx.paseSessionHelper = pase
        ctx.paseRequestContext = paseCtx
        ctx.initiatorSessionID = initiatorSessionID

        return (pbkdfReq, ctx)
    }

    // MARK: - Step 2: Handle PBKDFParamResponse

    /// Process PBKDFParamResponse and produce Pake1.
    public func handlePBKDFParamResponse(
        response: Data,
        context: CommissioningContext
    ) throws -> (message: Data, context: CommissioningContext) {
        guard let pase = context.paseSessionHelper,
              let paseCtx = context.paseRequestContext else {
            throw ControllerError.paseHandshakeFailed("Missing PASE context")
        }

        let (pake1, pake1Ctx) = try pase.handlePBKDFParamResponse(
            pbkdfParamResponse: response,
            context: paseCtx
        )

        var ctx = context
        ctx.pasePake1Context = pake1Ctx

        return (pake1, ctx)
    }

    // MARK: - Step 3: Handle Pake2

    /// Process Pake2 and produce Pake3. Establishes the PASE session.
    public func handlePake2(
        response: Data,
        context: CommissioningContext
    ) throws -> (message: Data, context: CommissioningContext) {
        guard let pase = context.paseSessionHelper,
              let pake1Ctx = context.pasePake1Context else {
            throw ControllerError.paseHandshakeFailed("Missing Pake1 context")
        }

        let (pake3, session, responderSessionID) = try pase.handlePake2(
            pake2Data: response,
            context: pake1Ctx
        )

        var ctx = context
        ctx.paseSession = session
        ctx.responderSessionID = responderSessionID

        // Extract attestation challenge from the session keys (attestationKey bytes).
        // Used later in attestation validation (§11.17.6.1).
        if let attKey = session.attestationKey {
            ctx.attestationChallenge = attKey.withUnsafeBytes { Data($0) }
        }

        return (pake3, ctx)
    }

    // MARK: - Step 4: ArmFailSafe

    /// Build an ArmFailSafe invoke request (sent over the PASE session).
    public func buildArmFailSafe(
        context: CommissioningContext,
        failSafeExpirySeconds: UInt16 = 60
    ) throws -> (message: Data, context: CommissioningContext) {
        let request = GeneralCommissioningCluster.ArmFailSafeRequest(
            expiryLengthSeconds: failSafeExpirySeconds
        )

        let message = IMClient.invokeCommandRequest(
            endpointID: .root,
            clusterID: GeneralCommissioningCluster.id,
            commandID: GeneralCommissioningCluster.Command.armFailSafe,
            commandFields: request.toTLVElement()
        )

        return (message, context)
    }

    /// Validate the ArmFailSafe response.
    public func handleArmFailSafeResponse(
        response: Data,
        context: CommissioningContext
    ) throws -> CommissioningContext {
        let responseElement = try IMClient.parseInvokeResponse(response)

        if let element = responseElement {
            let armResp = try GeneralCommissioningCluster.ArmFailSafeResponse.fromTLVElement(element)
            guard armResp.errorCode == .ok else {
                throw ControllerError.commissioningFailed(
                    "ArmFailSafe failed: \(armResp.errorCode) - \(armResp.debugText)"
                )
            }
        }

        return context
    }

    // MARK: - Step 5: SetRegulatoryConfig

    /// Build a SetRegulatoryConfig invoke request.
    public func buildSetRegulatoryConfig(
        context: CommissioningContext,
        locationType: GeneralCommissioningCluster.RegulatoryLocationType = .indoorOutdoor,
        countryCode: String = "XX"
    ) -> Data {
        let request = GeneralCommissioningCluster.SetRegulatoryConfigRequest(
            newRegulatoryConfig: locationType,
            countryCode: countryCode
        )

        return IMClient.invokeCommandRequest(
            endpointID: .root,
            clusterID: GeneralCommissioningCluster.id,
            commandID: GeneralCommissioningCluster.Command.setRegulatoryConfig,
            commandFields: request.toTLVElement()
        )
    }

    /// Validate the SetRegulatoryConfig response.
    public func handleSetRegulatoryConfigResponse(
        response: Data
    ) throws {
        let responseElement = try IMClient.parseInvokeResponse(response)

        if let element = responseElement {
            let setResp = try GeneralCommissioningCluster.SetRegulatoryConfigResponse.fromTLVElement(element)
            guard setResp.errorCode == .ok else {
                throw ControllerError.commissioningFailed(
                    "SetRegulatoryConfig failed: \(setResp.errorCode) - \(setResp.debugText)"
                )
            }
        }
    }

    // MARK: - Step 6: CSR Request

    /// Build a CSRRequest invoke request.
    public func buildCSRRequest() -> Data {
        var csrNonce = Data(count: 32)
        for i in 0..<32 { csrNonce[i] = UInt8.random(in: 0...255) }

        let request = OperationalCredentialsCluster.CSRRequest(csrNonce: csrNonce)

        return IMClient.invokeCommandRequest(
            endpointID: .root,
            clusterID: ClusterID(rawValue: 0x003E), // OperationalCredentials
            commandID: OperationalCredentialsCluster.Command.csrRequest,
            commandFields: request.toTLVElement()
        )
    }

    /// Parse CSR response and extract the device's operational public key.
    ///
    /// The NOCSRElements field contains a TLV structure with:
    /// - Tag 1: NOCSR (the CSR itself, DER-encoded PKCS#10)
    /// - Tag 2: CSRNonce (echo of our nonce)
    ///
    /// For now, we extract the public key from the NOCSR raw bytes.
    /// The NOCSR in Matter is a DER-encoded PKCS#10 CSR containing
    /// the device's P-256 public key.
    public func handleCSRResponse(
        response: Data,
        context: CommissioningContext
    ) async throws -> (addRootCertMessage: Data, addNOCMessage: Data, deviceNodeID: NodeID, context: CommissioningContext) {
        let responseElement = try IMClient.parseInvokeResponse(response)

        guard let element = responseElement else {
            throw ControllerError.invalidCSRResponse
        }

        let csrResp = try OperationalCredentialsCluster.CSRResponse.fromTLVElement(element)

        // Parse the NOCSRElements to extract the CSR
        let (_, nocsrElement) = try TLVDecoder.decode(csrResp.nocsrElements)
        guard case .structure(let nocsrFields) = nocsrElement,
              let csrData = nocsrFields.first(where: { $0.tag == .contextSpecific(1) })?.value.dataValue else {
            throw ControllerError.invalidCSRResponse
        }

        // Extract public key from the DER-encoded CSR
        // The P-256 public key (65 bytes uncompressed) is near the end of the CSR
        let publicKey = try extractPublicKeyFromCSR(csrData)

        // Allocate a node ID for the device
        let deviceNodeID = await fabricManager.allocateNodeID()

        // Generate NOC for the device
        let noc = try await fabricManager.generateNOC(
            nodePublicKey: publicKey,
            nodeID: deviceNodeID
        )

        // Build AddTrustedRootCert message
        let rcac = fabricManager.rcac
        let rcacTLV = rcac.tlvEncode()
        let addRootCertMessage = IMClient.invokeCommandRequest(
            endpointID: .root,
            clusterID: ClusterID(rawValue: 0x003E),
            commandID: OperationalCredentialsCluster.Command.addTrustedRootCert,
            commandFields: .structure([
                .init(tag: .contextSpecific(0), value: .octetString(rcacTLV))
            ])
        )

        // Build AddNOC message
        // Per Matter spec §11.17.6.8.2, IPKValue SHALL be the epoch key (EKS(0)),
        // NOT the derived IPK. The device derives the actual IPK from this epoch key
        // via HKDF-SHA256 during CASE session establishment.
        let nocTLV = noc.tlvEncode()
        let ipk = fabricManager.ipkEpochKey
        let fabricInfo = fabricManager.controllerFabricInfo
        let vendorID = fabricManager.vendorID

        let addNOCCommand = OperationalCredentialsCluster.AddNOCCommand(
            nocValue: nocTLV,
            ipkValue: ipk,
            caseAdminSubject: fabricInfo.nodeID.rawValue,
            adminVendorId: vendorID.rawValue
        )

        let addNOCMessage = IMClient.invokeCommandRequest(
            endpointID: .root,
            clusterID: ClusterID(rawValue: 0x003E),
            commandID: OperationalCredentialsCluster.Command.addNOC,
            commandFields: addNOCCommand.toTLVElement()
        )

        var ctx = context
        ctx.deviceNodeID = deviceNodeID
        ctx.fabricIndex = fabricManager.fabricIndex

        return (addRootCertMessage, addNOCMessage, deviceNodeID, ctx)
    }

    // MARK: - Step 7: Handle NOC Response + ACL Write

    /// Validate the NOC response and build the ACL write message.
    public func handleNOCResponse(
        response: Data,
        context: CommissioningContext
    ) throws -> (aclWriteMessage: Data, context: CommissioningContext) {
        let responseElement = try IMClient.parseInvokeResponse(response)

        if let element = responseElement {
            let nocResp = try OperationalCredentialsCluster.NOCResponse.fromTLVElement(element)
            guard nocResp.statusCode == .ok else {
                throw ControllerError.commissioningFailed(
                    "AddNOC failed: \(nocResp.statusCode)"
                )
            }
        }

        // Build ACL write — grant controller admin access
        let fabricInfo = fabricManager.controllerFabricInfo
        let fabricIndex = fabricManager.fabricIndex

        let ace = AccessControlCluster.AccessControlEntry.adminACE(
            subjectNodeID: fabricInfo.nodeID.rawValue,
            fabricIndex: fabricIndex
        )

        let aclWriteMessage = IMClient.writeAttributeRequest(
            endpointID: .root,
            clusterID: ClusterID(rawValue: 0x001F), // AccessControl
            attributeID: AccessControlCluster.Attribute.acl,
            value: .array([ace.toTLVElement()])
        )

        return (aclWriteMessage, context)
    }

    // MARK: - Step 8: CommissioningComplete

    /// Build the CommissioningComplete invoke request.
    public func buildCommissioningComplete() -> Data {
        IMClient.invokeCommandRequest(
            endpointID: .root,
            clusterID: GeneralCommissioningCluster.id,
            commandID: GeneralCommissioningCluster.Command.commissioningComplete
        )
    }

    /// Validate the CommissioningComplete response and produce a CommissionedDevice.
    public func handleCommissioningComplete(
        response: Data,
        context: CommissioningContext
    ) throws -> CommissionedDevice {
        let responseElement = try IMClient.parseInvokeResponse(response)

        if let element = responseElement {
            let completeResp = try GeneralCommissioningCluster.CommissioningCompleteResponse.fromTLVElement(element)
            guard completeResp.errorCode == .ok else {
                throw ControllerError.commissioningFailed(
                    "CommissioningComplete failed: \(completeResp.errorCode) - \(completeResp.debugText)"
                )
            }
        }

        guard let deviceNodeID = context.deviceNodeID else {
            throw ControllerError.commissioningFailed("No device node ID allocated")
        }

        let fabricIndex = fabricManager.fabricIndex
        let vendorID = fabricManager.vendorID

        return CommissionedDevice(
            nodeID: deviceNodeID,
            fabricIndex: fabricIndex,
            vendorID: vendorID
        )
    }

    // MARK: - Attestation Validation

    /// Build a `CertificateChainRequest` invoke to retrieve the DAC from the device.
    ///
    /// - Parameter certificateType: 1 = DAC, 2 = PAI.
    /// - Returns: TLV-encoded InvokeRequest.
    public func buildCertificateChainRequest(certificateType: UInt8 = 1) -> Data {
        IMClient.invokeCommandRequest(
            endpointID: .root,
            clusterID: ClusterID(rawValue: 0x003E),
            commandID: OperationalCredentialsCluster.Command.certificateChainRequest,
            commandFields: .structure([
                .init(tag: .contextSpecific(0), value: .unsignedInt(UInt64(certificateType)))
            ])
        )
    }

    /// Build an `AttestationRequest` invoke with a random 32-byte nonce.
    ///
    /// - Returns: Tuple of (TLV-encoded InvokeRequest, nonce sent).
    public func buildAttestationRequest() -> (message: Data, nonce: Data) {
        var nonceBytes = [UInt8](repeating: 0, count: 32)
        for i in 0..<32 { nonceBytes[i] = UInt8.random(in: 0...255) }
        let nonce = Data(nonceBytes)

        let message = IMClient.invokeCommandRequest(
            endpointID: .root,
            clusterID: ClusterID(rawValue: 0x003E),
            commandID: OperationalCredentialsCluster.Command.attestationRequest,
            commandFields: .structure([
                .init(tag: .contextSpecific(0), value: .octetString(nonce))
            ])
        )

        return (message, nonce)
    }

    /// Parse the `CertificateChainResponse` and return the raw DER certificate bytes.
    public func handleCertificateChainResponse(_ response: Data) throws -> Data {
        let responseElement = try IMClient.parseInvokeResponse(response)

        guard let element = responseElement,
              case .structure(let fields) = element,
              let certData = fields.first(where: { $0.tag == .contextSpecific(0) })?.value.dataValue else {
            throw ControllerError.attestationValidationFailed("CertificateChainResponse missing certificate data")
        }

        return certData
    }

    /// Validate an `AttestationResponse` against the sent nonce and PASE session attestation challenge.
    ///
    /// Performs:
    /// 1. Parses `attestationElements` TLV — verifies the echoed nonce matches `sentNonce`.
    /// 2. Verifies `attestationSignature` using the DAC public key:
    ///    `ECDSA-SHA256(dacPublicKey, attestationElements || attestationChallenge)`.
    ///
    /// - Parameters:
    ///   - response: TLV-encoded InvokeResponse containing the AttestationResponse.
    ///   - sentNonce: The 32-byte nonce originally sent in the AttestationRequest.
    ///   - attestationChallenge: 16-byte challenge from the PASE session keys.
    ///   - dacPublicKey: The device's DAC public key (P-256) retrieved via CertificateChainRequest.
    /// - Throws: `ControllerError.attestationValidationFailed` if any check fails.
    public func validateAttestationResponse(
        response: Data,
        sentNonce: Data,
        attestationChallenge: Data,
        dacPublicKey: P256.Signing.PublicKey
    ) throws {
        let responseElement = try IMClient.parseInvokeResponse(response)

        guard let element = responseElement,
              case .structure(let fields) = element else {
            throw ControllerError.attestationValidationFailed("AttestationResponse: missing or invalid response element")
        }

        // Field 0: attestationElements (octet string containing TLV)
        guard let attestationElementsData = fields.first(where: { $0.tag == .contextSpecific(0) })?.value.dataValue else {
            throw ControllerError.attestationValidationFailed("AttestationResponse: missing attestationElements (tag 0)")
        }

        // Field 1: attestationSignature (DER-encoded ECDSA signature, 64 bytes raw)
        guard let sigData = fields.first(where: { $0.tag == .contextSpecific(1) })?.value.dataValue else {
            throw ControllerError.attestationValidationFailed("AttestationResponse: missing attestationSignature (tag 1)")
        }

        // Decode attestationElements TLV and verify nonce echo (tag 2)
        let (_, elementsElement) = try TLVDecoder.decode(attestationElementsData)
        guard case .structure(let elemFields) = elementsElement else {
            throw ControllerError.attestationValidationFailed("AttestationElements: expected TLV structure")
        }

        guard let echoedNonce = elemFields.first(where: { $0.tag == .contextSpecific(2) })?.value.dataValue else {
            throw ControllerError.attestationValidationFailed("AttestationElements: missing nonce echo (tag 2)")
        }

        guard echoedNonce == sentNonce else {
            throw ControllerError.attestationValidationFailed("AttestationElements: nonce mismatch — echoed nonce does not match sent nonce")
        }

        // Verify attestation signature: ECDSA-SHA256(dacKey, attestationElements || attestationChallenge)
        // Per Matter spec §11.17.6.3 the signature is a 64-byte raw r‖s encoding.
        // Accept both raw (64 bytes) and DER (variable) for compatibility.
        let messageToVerify = attestationElementsData + attestationChallenge

        do {
            let sig: P256.Signing.ECDSASignature
            if sigData.count == 64 {
                sig = try P256.Signing.ECDSASignature(rawRepresentation: sigData)
            } else {
                sig = try P256.Signing.ECDSASignature(derRepresentation: sigData)
            }
            guard dacPublicKey.isValidSignature(sig, for: messageToVerify) else {
                throw ControllerError.attestationValidationFailed("AttestationResponse: signature verification failed")
            }
        } catch let error as ControllerError {
            throw error
        } catch {
            throw ControllerError.attestationValidationFailed("AttestationResponse: failed to parse signature — \(error)")
        }
    }

    /// Extract the P-256 public key from a DER-encoded X.509 certificate.
    ///
    /// Searches for the uncompressed point marker (0x04) followed by 64 bytes
    /// in the SubjectPublicKeyInfo structure of the certificate.
    public func extractPublicKeyFromCertificate(_ derCert: Data) throws -> P256.Signing.PublicKey {
        for i in 0..<derCert.count {
            if derCert[derCert.startIndex + i] == 0x04 && i + 64 < derCert.count {
                let pubKeyData = derCert[(derCert.startIndex + i)..<(derCert.startIndex + i + 65)]
                do {
                    return try P256.Signing.PublicKey(x963Representation: pubKeyData)
                } catch {
                    continue
                }
            }
        }
        throw ControllerError.attestationValidationFailed("Could not extract P-256 public key from DER certificate")
    }

    // MARK: - CSR Parsing

    /// Extract the P-256 public key from a DER-encoded PKCS#10 CSR.
    ///
    /// In a Matter CSR, the subject public key is a P-256 uncompressed point
    /// (65 bytes starting with 0x04). We search for this pattern in the DER data.
    private func extractPublicKeyFromCSR(_ csrData: Data) throws -> P256.Signing.PublicKey {
        // Look for the uncompressed point marker (0x04) followed by 64 bytes
        // in the DER structure. The public key is the BIT STRING value in the
        // SubjectPublicKeyInfo ASN.1 structure.
        //
        // For P-256, the BIT STRING content is:
        // 0x00 (unused bits) + 0x04 (uncompressed) + 32 bytes X + 32 bytes Y
        for i in 0..<csrData.count {
            if csrData[csrData.startIndex + i] == 0x04 && i + 64 < csrData.count {
                let pubKeyData = csrData[(csrData.startIndex + i)..<(csrData.startIndex + i + 65)]
                do {
                    return try P256.Signing.PublicKey(x963Representation: pubKeyData)
                } catch {
                    continue // Not a valid key, keep searching
                }
            }
        }
        throw ControllerError.invalidCSRResponse
    }
}
