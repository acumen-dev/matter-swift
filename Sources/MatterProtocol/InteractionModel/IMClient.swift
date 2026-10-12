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
        return resp.writeResponses.allSatisfy { $0.status.status == StatusIB.success.status }
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

    /// Parse every response in an `InvokeResponse`, in order.
    public static func parseInvokeResponses(_ data: Data) throws -> [InvokeResponseIB] {
        let response = try InvokeResponse.fromTLV(data)
        guard !response.invokeResponses.isEmpty else {
            throw IMError.invalidMessage("InvokeResponse: no responses")
        }
        return response.invokeResponses
    }

    /// Parse a single-command `InvokeResponse`.
    ///
    /// Throws if **any** response carries a non-success status. Returns the
    /// first command response's fields, or `nil` when every response is a
    /// (successful) status.
    public static func parseInvokeResponse(_ data: Data) throws -> TLVElement? {
        let responses = try parseInvokeResponses(data)
        for response in responses {
            if let status = response.status, status.status.status != StatusIB.success.status {
                throw IMError.invalidStatus("Command error: status \(status.status.status)")
            }
        }
        return responses.first(where: { $0.command != nil })?.command?.commandFields
    }

    /// Build a `TimedRequest` opening a timed-interaction window of `timeout`.
    public static func timedRequest(timeout: Duration) -> Data {
        let ms = timeout.components.seconds * 1000 + timeout.components.attoseconds / 1_000_000_000_000_000
        return TimedRequest(timeoutMs: UInt16(clamping: ms)).tlvEncode()
    }
}
