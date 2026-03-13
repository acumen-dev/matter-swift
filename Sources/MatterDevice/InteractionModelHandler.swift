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
/// When an `IMRequestContext` is provided, ACL checks are enforced on every operation:
/// - Read/Subscribe: requires `View` privilege; wildcard reads silently skip denied paths,
///   targeted reads return `unsupportedAccess`.
/// - Write: requires `Operate` privilege; ACL cluster writes require `Administer`.
/// - Invoke: requires `Operate` privilege.
/// - PASE sessions bypass all ACL checks (implicit Administer).
///
/// When no context is provided (nil), no ACL enforcement is applied — backward
/// compatible for tests that don't need ACL testing.
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
///     fabricIndex: session.fabricIndex,
///     requestContext: aclContext
/// )
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
    ///   - requestContext: Session context for ACL enforcement. Nil means no enforcement.
    /// - Returns: Array of (responseOpcode, responsePayload) to send back.
    ///            Most operations return a single response, but subscribe returns two
    ///            (initial ReportData + SubscribeResponse).
    public func handleMessage(
        opcode: InteractionModelOpcode,
        payload: Data,
        sessionID: UInt16,
        fabricIndex: FabricIndex,
        requestContext: IMRequestContext? = nil
    ) async throws -> [(InteractionModelOpcode, Data)] {
        switch opcode {
        case .readRequest:
            return try handleRead(payload: payload, requestContext: requestContext)
        case .writeRequest:
            return try await handleWrite(payload: payload, requestContext: requestContext)
        case .invokeRequest:
            return try await handleInvoke(payload: payload, requestContext: requestContext)
        case .subscribeRequest:
            return try await handleSubscribe(payload: payload, sessionID: sessionID, fabricIndex: fabricIndex, requestContext: requestContext)
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
    ///
    /// ACL enforcement:
    /// - Each report is checked against the ACL with `View` privilege.
    /// - Wildcard reads silently drop denied reports.
    /// - Targeted reads replace denied reports with `unsupportedAccess` status.
    private func handleRead(
        payload: Data,
        requestContext: IMRequestContext?
    ) throws -> [(InteractionModelOpcode, Data)] {
        let request = try ReadRequest.fromTLV(payload)
        let reports = endpoints.readAttributes(request.attributeRequests, fabricFiltered: request.isFabricFiltered)

        // Build a set of wildcard request paths (nil endpointID = wildcard)
        let wildcardPaths = Set(
            request.attributeRequests
                .filter { $0.endpointID == nil }
                .map { WildcardKey(clusterID: $0.clusterID, attributeID: $0.attributeID) }
        )
        let allWildcard = request.attributeRequests.contains { $0.endpointID == nil && $0.clusterID == nil && $0.attributeID == nil }

        let filteredReports = filterReportsForACL(
            reports: reports,
            requestContext: requestContext,
            wildcardPaths: wildcardPaths,
            allWildcard: allWildcard
        )

        let response = ReportData(
            subscriptionID: nil,
            attributeReports: filteredReports,
            suppressResponse: true
        )
        return [(.reportData, response.tlvEncode())]
    }

    // MARK: - Write

    /// Handle a WriteRequest by writing attributes via the endpoint manager.
    ///
    /// ACL enforcement:
    /// - Each write is checked before execution.
    /// - ACL cluster (0x001F) writes require `Administer` privilege.
    /// - All other writes require `Operate` privilege.
    /// - Denied writes produce `unsupportedAccess` status without executing.
    private func handleWrite(
        payload: Data,
        requestContext: IMRequestContext?
    ) async throws -> [(InteractionModelOpcode, Data)] {
        let request = try WriteRequest.fromTLV(payload)

        if let ctx = requestContext {
            // Pre-filter writes: separate allowed from denied
            var allowedWrites: [AttributeDataIB] = []
            var deniedStatuses: [AttributeStatusIB] = []

            for writeReq in request.writeRequests {
                let path = writeReq.path
                guard let endpointID = path.endpointID, let clusterID = path.clusterID else {
                    // Wildcard writes are not valid per spec — pass through to endpoint manager
                    allowedWrites.append(writeReq)
                    continue
                }

                // ACL cluster writes require Administer; others require Operate
                let requiredPrivilege: AccessControlCluster.Privilege =
                    clusterID == .accessControl ? .administer : .operate

                let decision = ACLChecker.check(
                    requiredPrivilege: requiredPrivilege,
                    endpointID: endpointID,
                    clusterID: clusterID,
                    context: ctx.checkerContext,
                    acls: ctx.acls
                )

                if decision == .allowed {
                    allowedWrites.append(writeReq)
                } else {
                    deniedStatuses.append(AttributeStatusIB(
                        path: path,
                        status: .unsupportedAccess
                    ))
                }
            }

            // Execute allowed writes
            let writeStatuses = allowedWrites.isEmpty ? [] : endpoints.writeAttributes(allowedWrites)

            // Notify subscriptions of attribute changes
            let dirty = store.dirtyPaths()
            if !dirty.isEmpty {
                await subscriptions.attributesChanged(dirty)
            }

            let response = WriteResponse(writeResponses: deniedStatuses + writeStatuses)
            return [(.writeResponse, response.tlvEncode())]
        } else {
            // No ACL context — execute all writes
            let statuses = endpoints.writeAttributes(request.writeRequests)

            let dirty = store.dirtyPaths()
            if !dirty.isEmpty {
                await subscriptions.attributesChanged(dirty)
            }

            let response = WriteResponse(writeResponses: statuses)
            return [(.writeResponse, response.tlvEncode())]
        }
    }

    // MARK: - Invoke

    /// Handle an InvokeRequest by routing commands to cluster handlers.
    ///
    /// ACL enforcement:
    /// - Each command is checked before execution with `Operate` privilege.
    /// - Denied commands produce `unsupportedAccess` command status.
    private func handleInvoke(
        payload: Data,
        requestContext: IMRequestContext?
    ) async throws -> [(InteractionModelOpcode, Data)] {
        let request = try InvokeRequest.fromTLV(payload)
        var invokeResponses: [InvokeResponseIB] = []

        for cmd in request.invokeRequests {
            // ACL check before execution
            if let ctx = requestContext {
                let decision = ACLChecker.check(
                    requiredPrivilege: .operate,
                    endpointID: cmd.commandPath.endpointID,
                    clusterID: cmd.commandPath.clusterID,
                    context: ctx.checkerContext,
                    acls: ctx.acls
                )
                if decision == .denied {
                    invokeResponses.append(InvokeResponseIB(status: CommandStatusIB(
                        commandPath: cmd.commandPath,
                        status: .unsupportedAccess
                    )))
                    continue
                }
            }

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
    /// ACL enforcement: Same as Read — the initial report is ACL-filtered.
    private func handleSubscribe(
        payload: Data,
        sessionID: UInt16,
        fabricIndex: FabricIndex,
        requestContext: IMRequestContext?
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

        // Build wildcard info for ACL filtering
        let wildcardPaths = Set(
            request.attributeRequests
                .filter { $0.endpointID == nil }
                .map { WildcardKey(clusterID: $0.clusterID, attributeID: $0.attributeID) }
        )
        let allWildcard = request.attributeRequests.contains { $0.endpointID == nil && $0.clusterID == nil && $0.attributeID == nil }

        let filteredReports = filterReportsForACL(
            reports: reports,
            requestContext: requestContext,
            wildcardPaths: wildcardPaths,
            allWildcard: allWildcard
        )

        let initialReport = ReportData(
            subscriptionID: subID,
            attributeReports: filteredReports,
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

    // MARK: - ACL Helpers

    /// Key for identifying wildcard request paths.
    private struct WildcardKey: Hashable {
        let clusterID: ClusterID?
        let attributeID: AttributeID?
    }

    /// Determine if a report originated from a wildcard request.
    ///
    /// A report is considered wildcard-originated if:
    /// 1. There was an all-wildcard request (nil endpoint, cluster, and attribute), OR
    /// 2. The report's cluster/attribute matches a wildcard request path (nil endpoint).
    private func isWildcardOriginated(
        report: AttributeReportIB,
        wildcardPaths: Set<WildcardKey>,
        allWildcard: Bool
    ) -> Bool {
        if allWildcard { return true }
        guard let data = report.attributeData else { return false }
        let key = WildcardKey(clusterID: data.path.clusterID, attributeID: data.path.attributeID)
        // Check for exact match or partially-wildcarded request paths
        return wildcardPaths.contains(key)
            || wildcardPaths.contains(WildcardKey(clusterID: data.path.clusterID, attributeID: nil))
            || wildcardPaths.contains(WildcardKey(clusterID: nil, attributeID: data.path.attributeID))
            || wildcardPaths.contains(WildcardKey(clusterID: nil, attributeID: nil))
    }

    /// Filter attribute reports according to ACL rules.
    ///
    /// - Wildcard-originated denied reports are silently dropped.
    /// - Targeted denied reports are replaced with `unsupportedAccess` status.
    /// - Reports without concrete endpoint/cluster paths pass through.
    private func filterReportsForACL(
        reports: [AttributeReportIB],
        requestContext: IMRequestContext?,
        wildcardPaths: Set<WildcardKey>,
        allWildcard: Bool
    ) -> [AttributeReportIB] {
        guard let ctx = requestContext else { return reports }

        var filtered: [AttributeReportIB] = []
        for report in reports {
            // Status reports (errors) pass through unchanged
            guard let data = report.attributeData else {
                filtered.append(report)
                continue
            }

            // Need concrete endpoint and cluster for ACL check
            guard let endpointID = data.path.endpointID, let clusterID = data.path.clusterID else {
                filtered.append(report)
                continue
            }

            let decision = ACLChecker.check(
                requiredPrivilege: .view,
                endpointID: endpointID,
                clusterID: clusterID,
                context: ctx.checkerContext,
                acls: ctx.acls
            )

            if decision == .allowed {
                filtered.append(report)
            } else if isWildcardOriginated(report: report, wildcardPaths: wildcardPaths, allWildcard: allWildcard) {
                // Wildcard: silently skip
                continue
            } else {
                // Targeted: return unsupportedAccess status
                filtered.append(AttributeReportIB(attributeStatus: AttributeStatusIB(
                    path: data.path,
                    status: .unsupportedAccess
                )))
            }
        }
        return filtered
    }
}
