// IMClient.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

/// Convenience helpers for building and parsing Interaction Model messages.
///
/// All methods produce or consume `Data` (TLV-encoded). Callers handle
/// encryption and transport.
public enum IMClient {

    // MARK: - Read

    /// Build a ReadRequest for a single attribute.
    public static func readAttributeRequest(
        endpointID: EndpointID,
        clusterID: ClusterID,
        attributeID: AttributeID,
        isFabricFiltered: Bool = true
    ) -> Data {
        ReadRequest(
            attributeRequests: [AttributePath(endpointID: endpointID, clusterID: clusterID, attributeID: attributeID)],
            isFabricFiltered: isFabricFiltered
        ).tlvEncode()
    }

    /// Build a ReadRequest for multiple attributes.
    public static func readAttributesRequest(
        paths: [AttributePath],
        isFabricFiltered: Bool = true
    ) -> Data {
        ReadRequest(attributeRequests: paths, isFabricFiltered: isFabricFiltered).tlvEncode()
    }

    /// Parse a ReportData response and extract the first attribute value.
    ///
    /// Returns the `TLVElement` data for the first successful attribute report,
    /// or throws if the report contains an error status.
    public static func parseReadResponse(_ data: Data) throws -> TLVElement {
        let report = try ReportData.fromTLV(data)

        guard let first = report.attributeReports.first else {
            throw IMError.invalidMessage("ReportData: no attribute reports")
        }

        if let status = first.attributeStatus {
            throw IMError.invalidStatus("Attribute error: status \(status.status.status)")
        }

        guard let attrData = first.attributeData else {
            throw IMError.invalidMessage("ReportData: no attribute data")
        }

        return attrData.data
    }

    // MARK: - Write

    /// Build a WriteRequest for a single attribute.
    public static func writeAttributeRequest(
        endpointID: EndpointID,
        clusterID: ClusterID,
        attributeID: AttributeID,
        dataVersion: DataVersion = DataVersion(rawValue: 0),
        value: TLVElement,
        timedRequest: Bool = false
    ) -> Data {
        WriteRequest(
            timedRequest: timedRequest,
            writeRequests: [
                AttributeDataIB(
                    dataVersion: dataVersion,
                    path: AttributePath(endpointID: endpointID, clusterID: clusterID, attributeID: attributeID),
                    data: value
                )
            ]
        ).tlvEncode()
    }

    /// Parse a WriteResponse and check for success.
    ///
    /// Returns `true` if all writes succeeded, `false` otherwise.
    public static func parseWriteResponse(_ data: Data) throws -> Bool {
        let resp = try WriteResponse.fromTLV(data)
        return resp.writeResponses.allSatisfy { $0.status == .success }
    }

    // MARK: - Invoke

    /// Build an InvokeRequest for a single command.
    public static func invokeCommandRequest(
        endpointID: EndpointID,
        clusterID: ClusterID,
        commandID: CommandID,
        commandFields: TLVElement? = nil,
        timedRequest: Bool = false
    ) -> Data {
        InvokeRequest(
            timedRequest: timedRequest,
            invokeRequests: [
                CommandDataIB(
                    commandPath: CommandPath(endpointID: endpointID, clusterID: clusterID, commandID: commandID),
                    commandFields: commandFields
                )
            ]
        ).tlvEncode()
    }

    /// Parse an InvokeResponse and extract the first response.
    ///
    /// Returns the command data if present, or throws on error status.
    public static func parseInvokeResponse(_ data: Data) throws -> TLVElement? {
        let resp = try InvokeResponse.fromTLV(data)

        guard let first = resp.invokeResponses.first else {
            throw IMError.invalidMessage("InvokeResponse: no responses")
        }

        if let status = first.status {
            if status.status != .success {
                throw IMError.invalidStatus("Command error: status \(status.status.status)")
            }
            return nil // success status, no response data
        }

        return first.command?.commandFields
    }
}
