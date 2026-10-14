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
/// 3. LocationCapability read → SetRegulatoryConfig
/// 4. Device attestation: Basic Information VendorID/ProductID reads,
///    CertificateChainRequest (DAC, PAI), AttestationRequest, verification
/// 5. CSRRequest → generate NOC
/// 6. AddTrustedRootCert + AddNOC
/// 7. ACL write (grant controller admin access)
/// 8. CASE session to the device on the new fabric (driven by the caller)
/// 9. CommissioningComplete, over that CASE session
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

        /// Fabric index the device assigned in its AddNOC response.
        public var deviceFabricIndex: FabricIndex?

        /// Attestation challenge from the PASE session keys (16 bytes).
        /// Used to verify the attestation signature in the AttestationResponse.
        public var attestationChallenge: Data?

        /// The DAC's public key, set once attestation has verified or its failure was
        /// approved. The CSRResponse's attestation signature is checked against it.
        public var dacPublicKey: P256.Signing.PublicKey?

        /// The vendor ID in the DAC's subject (nil if it has none that can be read).
        public var dacVendorID: UInt16?

        /// The product ID in the DAC's subject (nil if it has none that can be read).
        public var dacProductID: UInt16?

        /// How the device passed attestation.
        public var attestation: DeviceAttestationRecord?

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

    /// The fail-safe commissioning arms, in seconds: the device reverts
    /// what was staged if commissioning has not completed by then.
    @usableFromInline static let defaultFailSafeExpirySeconds: UInt16 = 60

    /// Build an ArmFailSafe invoke request (sent over the PASE session).
    public func buildArmFailSafe(
        context: CommissioningContext,
        failSafeExpirySeconds: UInt16 = CommissioningController.defaultFailSafeExpirySeconds
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

    /// Build an ArmFailSafe invoke request with expiry 0, which disarms the
    /// fail-safe and has the device revert everything staged under it.
    public func buildDisarmFailSafe() -> Data {
        IMClient.invokeCommandRequest(
            endpointID: .root,
            clusterID: GeneralCommissioningCluster.id,
            commandID: GeneralCommissioningCluster.Command.armFailSafe,
            commandFields: GeneralCommissioningCluster.ArmFailSafeRequest(
                expiryLengthSeconds: 0, breadcrumb: 0
            ).toTLVElement()
        )
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

    /// Build a read of the device's GeneralCommissioning LocationCapability.
    public func buildReadLocationCapability() -> Data {
        IMClient.readAttributeRequest(
            endpointID: .root,
            clusterID: GeneralCommissioningCluster.id,
            attributeID: GeneralCommissioningCluster.Attribute.locationCapability
        )
    }

    /// The regulatory location to send, given the device's LocationCapability
    /// read response: the device's own value unless it supports both, in which
    /// case `preferred`. A device fixed to Indoor or Outdoor refuses any other
    /// value (connectedhomeip answers ValueOutsideRange).
    public func handleLocationCapabilityResponse(
        _ response: Data,
        preferred: GeneralCommissioningCluster.RegulatoryLocationType = .indoorOutdoor
    ) throws -> GeneralCommissioningCluster.RegulatoryLocationType {
        let value: TLVElement
        do {
            value = try IMClient.parseReadResponse(response)
        } catch {
            throw ControllerError.commissioningFailed("LocationCapability: \(error)")
        }
        guard let raw = value.uintValue, raw <= UInt64(UInt8.max),
              let capability = GeneralCommissioningCluster.RegulatoryLocationType(rawValue: UInt8(raw)) else {
            throw ControllerError.commissioningFailed("LocationCapability: unexpected value \(value)")
        }
        return capability == .indoorOutdoor ? preferred : capability
    }

    /// Build a SetRegulatoryConfig invoke request.
    public func buildSetRegulatoryConfig(
        context: CommissioningContext,
        locationType: GeneralCommissioningCluster.RegulatoryLocationType,
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

    // MARK: - Step 6: Device Attestation

    /// Build a read of a Basic Information attribute on the root endpoint (VendorID 0x0002,
    /// ProductID 0x0004), which attestation compares with the Certification Declaration.
    public func buildReadBasicInformation(_ attribute: AttributeID) -> Data {
        IMClient.readAttributeRequest(
            endpointID: .root,
            clusterID: BasicInformationCluster.id,
            attributeID: attribute
        )
    }

    /// The 16-bit value of a Basic Information VendorID or ProductID read response.
    ///
    /// - Parameter name: names the attribute in the error.
    /// - Throws: `ControllerError.commissioningFailed("Basic Information <name>: …")` if the read
    ///   failed or the value is not a 16-bit unsigned integer.
    public func handleBasicInformationResponse(_ response: Data, name: String) throws -> UInt16 {
        let value: TLVElement
        do {
            value = try IMClient.parseReadResponse(response)
        } catch {
            throw ControllerError.commissioningFailed("Basic Information \(name): \(error)")
        }
        guard let raw = value.uintValue, let narrowed = UInt16(exactly: raw) else {
            throw ControllerError.commissioningFailed("Basic Information \(name): unexpected value \(value)")
        }
        return narrowed
    }

    /// The attestation elements (tag 0) and attestation signature (tag 1) of an
    /// `AttestationResponse`, unverified.
    public func handleAttestationResponse(_ response: Data) throws -> (elements: Data, signature: Data) {
        let responseElement = try IMClient.parseInvokeResponse(response)
        guard let element = responseElement,
              case .structure(let fields) = element,
              let elements = fields.first(where: { $0.tag == .contextSpecific(0) })?.value.dataValue,
              let signature = fields.first(where: { $0.tag == .contextSpecific(1) })?.value.dataValue else {
            throw ControllerError.attestationValidationFailed("AttestationResponse missing its elements or signature")
        }
        return (elements, signature)
    }

    /// Apply the verifier's result for `dac`.
    ///
    /// A verified attestation is recorded as such. A failure is approved only when
    /// `approvingUnverifiedDevice` equals its non-nil `dacFingerprint` and its reason is not
    /// `.malformed`; it is then recorded as overridden at `approvedAt`, and commissioning carries
    /// on with the key in the DAC (read unverified), against which the CSRResponse is still
    /// checked. Otherwise the failure is thrown.
    ///
    /// - Throws: `ControllerError.attestationFailed` with the verifier's failure.
    public func applyAttestationResult(
        _ result: AttestationResult,
        dac: Data,
        approvingUnverifiedDevice approval: Data?,
        approvedAt: Date,
        context: CommissioningContext
    ) throws -> CommissioningContext {
        var ctx = context
        switch result {
        case .verified(let verified):
            ctx.dacPublicKey = verified.dacPublicKey
            ctx.dacVendorID = verified.vendorID
            ctx.dacProductID = verified.productID
            ctx.attestation = .verified(
                paaSubject: verified.paaSubject, vendorID: verified.vendorID, productID: verified.productID)
        case .failed(let failure):
            guard failure.reason != .malformed,
                  let fingerprint = failure.dacFingerprint,
                  let approval, approval == fingerprint,
                  let contents = DeviceAttestationVerifier.unverifiedDACContents(dac)
            else {
                throw ControllerError.attestationFailed(failure)
            }
            ctx.dacPublicKey = contents.publicKey
            ctx.dacVendorID = contents.vendorID
            ctx.dacProductID = contents.productID
            ctx.attestation = .overridden(dacFingerprint: fingerprint, reason: failure.reason, approvedAt: approvedAt)
        }
        return ctx
    }

    // MARK: - Step 7: CSR Request

    /// Build a CSRRequest invoke request.
    ///
    /// - Returns: the request message and the CSRNonce it carries; pass the nonce
    ///   to ``handleCSRResponse(response:expectedNonce:deviceNodeID:context:)`` to check the echo.
    public func buildCSRRequest() -> (message: Data, nonce: Data) {
        var csrNonce = Data(count: 32)
        for i in 0..<32 { csrNonce[i] = UInt8.random(in: 0...255) }

        let request = OperationalCredentialsCluster.CSRRequest(csrNonce: csrNonce)

        let message = IMClient.invokeCommandRequest(
            endpointID: .root,
            clusterID: ClusterID(rawValue: 0x003E), // OperationalCredentials
            commandID: OperationalCredentialsCluster.Command.csrRequest,
            commandFields: request.toTLVElement()
        )
        return (message, csrNonce)
    }

    /// Parse CSR response and extract the device's operational public key.
    ///
    /// The NOCSRElements field contains a TLV structure with:
    /// - Tag 1: NOCSR (the CSR itself, DER-encoded PKCS#10)
    /// - Tag 2: CSRNonce (echo of our nonce)
    ///
    /// The echoed CSRNonce must equal `expectedNonce`, the attestation signature over
    /// `nocsrElements || attestationChallenge` must verify with `context.dacPublicKey` (set by
    /// ``applyAttestationResult(_:dac:approvingUnverifiedDevice:approvedAt:context:)``, on the
    /// approval path too), and the CSR's self-signature must verify; the device key is read
    /// from its SubjectPublicKeyInfo.
    ///
    /// - Parameters:
    ///   - deviceNodeID: The operational node ID the caller allocated for the
    ///     device. It becomes the NOC's subject node ID and is recorded in the
    ///     returned context, from which
    ///     ``handleCommissioningComplete(response:context:)`` builds the device.
    public func handleCSRResponse(
        response: Data,
        expectedNonce: Data,
        deviceNodeID: NodeID,
        context: CommissioningContext
    ) async throws -> (addRootCertMessage: Data, addNOCMessage: Data, context: CommissioningContext) {
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

        guard let echoedNonce = nocsrFields.first(where: { $0.tag == .contextSpecific(2) })?.value.dataValue,
              echoedNonce == expectedNonce else {
            throw ControllerError.commissioningFailed("CSR nonce mismatch")
        }

        guard let dacPublicKey = context.dacPublicKey, let challenge = context.attestationChallenge else {
            throw ControllerError.commissioningFailed("CSR attestation signature cannot be checked: no DAC key or attestation challenge")
        }
        guard DeviceAttestationVerifier.verifyNOCSRSignature(
            nocsrElements: csrResp.nocsrElements, signature: csrResp.attestationSignature,
            attestationChallenge: challenge, dacPublicKey: dacPublicKey
        ) else {
            throw ControllerError.commissioningFailed("CSR attestation signature invalid")
        }

        let publicKey: P256.Signing.PublicKey
        do {
            publicKey = try PKCS10CSR(der: csrData).publicKey
        } catch {
            throw ControllerError.commissioningFailed("Invalid CSR: \(error)")
        }

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

        return (addRootCertMessage, addNOCMessage, ctx)
    }

    // MARK: - Step 7b: Handle AddTrustedRootCert Response

    /// Check the AddTrustedRootCert response (a bare status).
    public func handleAddTrustedRootCertResponse(_ data: Data) throws {
        do {
            _ = try IMClient.parseInvokeResponse(data)
        } catch {
            throw ControllerError.commissioningFailed("AddTrustedRootCert failed: \(error)")
        }
    }

    // MARK: - Step 8: Handle NOC Response + ACL Write

    /// Check the AddNOC response and return the fabric index the device
    /// assigned (not the controller's own index).
    public func handleNOCResponse(_ data: Data) throws -> FabricIndex {
        let element: TLVElement?
        do {
            element = try IMClient.parseInvokeResponse(data)
        } catch {
            throw ControllerError.commissioningFailed("AddNOC failed: \(error)")
        }
        guard let element else {
            throw ControllerError.commissioningFailed("AddNOC failed: response carries no NOCResponse")
        }
        let nocResp: OperationalCredentialsCluster.NOCResponse
        do {
            nocResp = try OperationalCredentialsCluster.NOCResponse.fromTLVElement(element)
        } catch {
            throw ControllerError.commissioningFailed("AddNOC failed: \(error)")
        }
        guard nocResp.statusCode == .ok else {
            throw ControllerError.commissioningFailed(
                "AddNOC failed: \(nocResp.statusCode) \(nocResp.debugText ?? "")"
            )
        }
        guard let index = nocResp.fabricIndex else {
            throw ControllerError.commissioningFailed("AddNOC failed: NOCResponse carries no fabric index")
        }
        return index
    }

    /// Check the ACL write response; any non-SUCCESS entry fails.
    public func handleACLWriteResponse(_ data: Data) throws {
        let allSucceeded: Bool
        do {
            allSucceeded = try IMClient.parseWriteResponse(data)
        } catch {
            throw ControllerError.commissioningFailed("ACL write failed: \(error)")
        }
        guard allSucceeded else {
            throw ControllerError.commissioningFailed("ACL write failed: non-SUCCESS write status")
        }
    }

    /// Build the ACL write message granting the controller admin access.
    public func buildACLWrite() -> Data {
        // Build ACL write — grant controller admin access
        let fabricInfo = fabricManager.controllerFabricInfo
        let fabricIndex = fabricManager.fabricIndex

        let ace = AccessControlCluster.AccessControlEntry.adminACE(
            subjectNodeID: fabricInfo.nodeID.rawValue,
            fabricIndex: fabricIndex
        )

        return IMClient.writeAttributeRequest(
            endpointID: .root,
            clusterID: ClusterID(rawValue: 0x001F), // AccessControl
            attributeID: AccessControlCluster.Attribute.acl,
            value: .array([ace.toTLVElement()])
        )
    }

    // MARK: - Step 9: CommissioningComplete

    /// Build the CommissioningComplete invoke request.
    public func buildCommissioningComplete() -> Data {
        IMClient.invokeCommandRequest(
            endpointID: .root,
            clusterID: GeneralCommissioningCluster.id,
            commandID: GeneralCommissioningCluster.Command.commissioningComplete
        )
    }

    /// Validate the CommissioningComplete response and produce a CommissionedDevice, whose
    /// vendor and product IDs are those in its DAC and whose attestation record is the
    /// context's.
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

        guard let fabricIndex = context.deviceFabricIndex else {
            throw ControllerError.commissioningFailed("No device fabric index recorded")
        }

        return CommissionedDevice(
            nodeID: deviceNodeID,
            fabricIndex: fabricIndex,
            vendorID: context.dacVendorID.map(VendorID.init(rawValue:)),
            productID: context.dacProductID.map(ProductID.init(rawValue:)),
            attestation: context.attestation
        )
    }

    // MARK: - Attestation Requests

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
}
