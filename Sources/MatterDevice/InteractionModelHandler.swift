// InteractionModelHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel
import MatterProtocol

/// Server-side Interaction Model message handler.
///
/// Receives decoded IM messages and produces responses using the `EndpointManager`
/// for data access and `SubscriptionManager` for subscriptions.
/// Does NOT handle transport or encryption — operates on decoded payloads.
///
/// ```swift
/// let handler = InteractionModelHandler(
///     endpoints: endpointManager,
///     subscriptions: subscriptionManager,
///     store: attributeStore
/// )
///
/// let responses = try await handler.handleMessage(
///     opcode: .readRequest,
///     payload: requestData,
///     sessionID: session.id,
///     fabricIndex: session.fabricIndex
/// )
/// for (opcode, data) in responses {
///     try await session.send(protocolID: .interactionModel, opcode: opcode, payload: data)
/// }
/// ```
public struct InteractionModelHandler: Sendable {

    private let endpoints: EndpointManager
    private let subscriptions: SubscriptionManager
    private let store: AttributeStore

    public init(endpoints: EndpointManager, subscriptions: SubscriptionManager, store: AttributeStore) {
        self.endpoints = endpoints
        self.subscriptions = subscriptions
        self.store = store
    }

    // MARK: - Message Dispatch

    /// Handle an incoming IM message.
    ///
    /// - Parameters:
    ///   - opcode: The IM opcode identifying the message type.
    ///   - payload: TLV-encoded message body.
    ///   - sessionID: Session this message arrived on.
    ///   - fabricIndex: Fabric of the session.
    /// - Returns: Array of (responseOpcode, responsePayload) to send back.
    ///            Most operations return a single response, but subscribe returns two
    ///            (initial ReportData + SubscribeResponse).
    public func handleMessage(
        opcode: InteractionModelOpcode,
        payload: Data,
        sessionID: UInt16,
        fabricIndex: FabricIndex
    ) async throws -> [(InteractionModelOpcode, Data)] {
        switch opcode {
        case .readRequest:
            return try handleRead(payload: payload)
        case .writeRequest:
            return try await handleWrite(payload: payload)
        case .invokeRequest:
            return try await handleInvoke(payload: payload)
        case .subscribeRequest:
            return try await handleSubscribe(payload: payload, sessionID: sessionID, fabricIndex: fabricIndex)
        case .statusResponse:
            return try handleStatusResponse(payload: payload)
        default:
            return [(.statusResponse, IMStatusResponse(status: StatusIB.invalidAction.status).tlvEncode())]
        }
    }

    // MARK: - Read

    /// Handle a ReadRequest by reading attributes from the endpoint manager.
    ///
    /// Returns a single ReportData with `suppressResponse: true` (standalone read,
    /// client does not send StatusResponse).
    private func handleRead(payload: Data) throws -> [(InteractionModelOpcode, Data)] {
        let request = try ReadRequest.fromTLV(payload)
        let reports = endpoints.readAttributes(request.attributeRequests, fabricFiltered: request.isFabricFiltered)

        let response = ReportData(
            subscriptionID: nil,
            attributeReports: reports,
            suppressResponse: true
        )
        return [(.reportData, response.tlvEncode())]
    }

    // MARK: - Write

    /// Handle a WriteRequest by writing attributes via the endpoint manager.
    ///
    /// After writes are applied, notifies the subscription manager of any changed
    /// attribute paths so pending subscription reports can be generated.
    private func handleWrite(payload: Data) async throws -> [(InteractionModelOpcode, Data)] {
        let request = try WriteRequest.fromTLV(payload)
        let statuses = endpoints.writeAttributes(request.writeRequests)

        // Notify subscriptions of attribute changes
        let dirty = store.dirtyPaths()
        if !dirty.isEmpty {
            await subscriptions.attributesChanged(dirty)
        }

        let response = WriteResponse(writeResponses: statuses)
        return [(.writeResponse, response.tlvEncode())]
    }

    // MARK: - Invoke

    /// Handle an InvokeRequest by routing commands to cluster handlers.
    ///
    /// Each command in the request produces either a success response (with optional
    /// response data) or a failure status. After all commands are processed, the
    /// subscription manager is notified of any attribute changes caused by commands.
    private func handleInvoke(payload: Data) async throws -> [(InteractionModelOpcode, Data)] {
        let request = try InvokeRequest.fromTLV(payload)
        var invokeResponses: [InvokeResponseIB] = []

        for cmd in request.invokeRequests {
            do {
                let result = try endpoints.handleCommand(path: cmd.commandPath, fields: cmd.commandFields)
                if let responseData = result {
                    // Command returned response data
                    invokeResponses.append(InvokeResponseIB(command: CommandDataIB(
                        commandPath: cmd.commandPath,
                        commandFields: responseData
                    )))
                } else {
                    // Success, no response data
                    invokeResponses.append(InvokeResponseIB(status: CommandStatusIB(
                        commandPath: cmd.commandPath,
                        status: .success
                    )))
                }
            } catch {
                invokeResponses.append(InvokeResponseIB(status: CommandStatusIB(
                    commandPath: cmd.commandPath,
                    status: .invalidAction
                )))
            }
        }

        // Notify subscriptions of attribute changes from commands
        let dirty = store.dirtyPaths()
        if !dirty.isEmpty {
            await subscriptions.attributesChanged(dirty)
        }

        let response = InvokeResponse(invokeResponses: invokeResponses)
        return [(.invokeResponse, response.tlvEncode())]
    }

    // MARK: - Subscribe

    /// Handle a SubscribeRequest by creating a subscription and returning the initial report.
    ///
    /// Returns two messages:
    /// 1. ReportData with the current values of all requested attributes (subscriptionID set,
    ///    `suppressResponse: false` — client must reply with StatusResponse).
    /// 2. SubscribeResponse confirming the subscription with the negotiated max interval.
    private func handleSubscribe(
        payload: Data,
        sessionID: UInt16,
        fabricIndex: FabricIndex
    ) async throws -> [(InteractionModelOpcode, Data)] {
        let request = try SubscribeRequest.fromTLV(payload)

        // Create subscription
        let (subID, maxInterval) = await subscriptions.subscribe(
            request: request,
            sessionID: sessionID,
            fabricIndex: fabricIndex
        )

        // Build initial report with all requested attributes
        let reports = endpoints.readAttributes(request.attributeRequests, fabricFiltered: request.isFabricFiltered)

        let initialReport = ReportData(
            subscriptionID: subID,
            attributeReports: reports,
            suppressResponse: false  // Client must send StatusResponse
        )

        let subResponse = SubscribeResponse(
            subscriptionID: subID,
            maxInterval: maxInterval
        )

        return [
            (.reportData, initialReport.tlvEncode()),
            (.subscribeResponse, subResponse.tlvEncode())
        ]
    }

    // MARK: - Status Response

    /// Handle an incoming StatusResponse.
    ///
    /// StatusResponse messages keep subscriptions alive. The status is decoded
    /// but no response message is needed.
    private func handleStatusResponse(payload: Data) throws -> [(InteractionModelOpcode, Data)] {
        let _ = try IMStatusResponse.fromTLV(payload)
        // No response needed for status response acknowledgments
        return []
    }
}
