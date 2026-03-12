// OperationalController.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import MatterTypes
import MatterCrypto
import MatterProtocol

/// Builds encrypted Interaction Model messages and parses encrypted responses
/// for operational device interaction.
///
/// Wraps `SecureMessageCodec` and `IMClient` to provide a higher-level API
/// for read/write/invoke operations over established CASE sessions.
///
/// ```swift
/// let opCtrl = OperationalController()
/// let readMsg = try opCtrl.readAttribute(
///     endpointID: .root, clusterID: clusterID,
///     attributeID: attrID, session: session,
///     sourceNodeID: myNodeID
/// )
/// // ... send readMsg, receive response ...
/// let value = try opCtrl.parseReadResponse(
///     encryptedMessage: response, session: session
/// )
/// ```
public struct OperationalController: Sendable {

    public init() {}

    // MARK: - Read

    /// Build an encrypted ReadRequest for a single attribute.
    public func readAttribute(
        endpointID: EndpointID,
        clusterID: ClusterID,
        attributeID: AttributeID,
        session: SecureSession,
        sourceNodeID: NodeID,
        exchangeID: UInt16 = UInt16.random(in: 1...UInt16.max)
    ) throws -> Data {
        let payload = IMClient.readAttributeRequest(
            endpointID: endpointID,
            clusterID: clusterID,
            attributeID: attributeID
        )

        let exchangeHeader = ExchangeHeader(
            flags: ExchangeFlags(initiator: true, reliableDelivery: true),
            protocolOpcode: InteractionModelOpcode.readRequest.rawValue,
            exchangeID: exchangeID,
            protocolID: MatterProtocolID.interactionModel.rawValue
        )

        return try SecureMessageCodec.encode(
            exchangeHeader: exchangeHeader,
            payload: payload,
            session: session,
            sourceNodeID: sourceNodeID
        )
    }

    /// Decrypt and parse a ReadResponse (ReportData).
    public func parseReadResponse(
        encryptedMessage: Data,
        session: SecureSession
    ) throws -> TLVElement {
        let (_, _, payload) = try SecureMessageCodec.decode(
            data: encryptedMessage,
            session: session
        )
        return try IMClient.parseReadResponse(payload)
    }

    // MARK: - Write

    /// Build an encrypted WriteRequest for a single attribute.
    public func writeAttribute(
        endpointID: EndpointID,
        clusterID: ClusterID,
        attributeID: AttributeID,
        value: TLVElement,
        session: SecureSession,
        sourceNodeID: NodeID,
        exchangeID: UInt16 = UInt16.random(in: 1...UInt16.max)
    ) throws -> Data {
        let payload = IMClient.writeAttributeRequest(
            endpointID: endpointID,
            clusterID: clusterID,
            attributeID: attributeID,
            value: value
        )

        let exchangeHeader = ExchangeHeader(
            flags: ExchangeFlags(initiator: true, reliableDelivery: true),
            protocolOpcode: InteractionModelOpcode.writeRequest.rawValue,
            exchangeID: exchangeID,
            protocolID: MatterProtocolID.interactionModel.rawValue
        )

        return try SecureMessageCodec.encode(
            exchangeHeader: exchangeHeader,
            payload: payload,
            session: session,
            sourceNodeID: sourceNodeID
        )
    }

    /// Decrypt and parse a WriteResponse.
    public func parseWriteResponse(
        encryptedMessage: Data,
        session: SecureSession
    ) throws -> Bool {
        let (_, _, payload) = try SecureMessageCodec.decode(
            data: encryptedMessage,
            session: session
        )
        return try IMClient.parseWriteResponse(payload)
    }

    // MARK: - Invoke

    /// Build an encrypted InvokeRequest for a single command.
    public func invokeCommand(
        endpointID: EndpointID,
        clusterID: ClusterID,
        commandID: CommandID,
        commandFields: TLVElement? = nil,
        session: SecureSession,
        sourceNodeID: NodeID,
        exchangeID: UInt16 = UInt16.random(in: 1...UInt16.max)
    ) throws -> Data {
        let payload = IMClient.invokeCommandRequest(
            endpointID: endpointID,
            clusterID: clusterID,
            commandID: commandID,
            commandFields: commandFields
        )

        let exchangeHeader = ExchangeHeader(
            flags: ExchangeFlags(initiator: true, reliableDelivery: true),
            protocolOpcode: InteractionModelOpcode.invokeRequest.rawValue,
            exchangeID: exchangeID,
            protocolID: MatterProtocolID.interactionModel.rawValue
        )

        return try SecureMessageCodec.encode(
            exchangeHeader: exchangeHeader,
            payload: payload,
            session: session,
            sourceNodeID: sourceNodeID
        )
    }

    /// Decrypt and parse an InvokeResponse.
    public func parseInvokeResponse(
        encryptedMessage: Data,
        session: SecureSession
    ) throws -> TLVElement? {
        let (_, _, payload) = try SecureMessageCodec.decode(
            data: encryptedMessage,
            session: session
        )
        return try IMClient.parseInvokeResponse(payload)
    }
}
