// MetadataClusterHandler.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes
import MatterModel

/// A generic, metadata-driven cluster handler for bridge devices.
///
/// Instead of writing a custom `ClusterHandler` struct for each cluster,
/// bridge developers configure a `MetadataClusterHandler` with initial
/// attribute values and optional write/command callbacks. The handler
/// uses `ClusterSpecRegistry` metadata (when available) to validate
/// writes and populate global attributes automatically.
///
/// ```swift
/// let handler = MetadataClusterHandler(
///     clusterID: .onOff,
///     attributes: [
///         (OnOffCluster.Attribute.onOff, .bool(false)),
///     ],
///     onWrite: { attrID, value in
///         // forward to backing device
///         return true
///     }
/// )
/// ```
/// Thread-safe box for passing values between sync and async contexts.
private final class UnsafeBox<T>: @unchecked Sendable {
    var value: T
    init(_ value: T) { self.value = value }
}

public final class MetadataClusterHandler: ClusterHandler, @unchecked Sendable {

    // MARK: - Properties

    public let clusterID: ClusterID
    public let clusterRevision: UInt16
    public let featureMap: UInt32

    private let lock = NSLock()
    private var attributes: [AttributeID: TLVElement]
    private let initialAttributeList: [(AttributeID, TLVElement)]
    private let spec: ClusterSpec?
    private let onWrite: AttributeWriteCallback?
    private let onCommand: CommandInvokeCallback?
    private let acceptedCommandIDs: [CommandID]
    private let generatedCommandIDs: [CommandID]

    // MARK: - Init

    /// Create a metadata-driven cluster handler.
    ///
    /// - Parameters:
    ///   - clusterID: The cluster this handler serves.
    ///   - attributes: Initial attribute values (excluding global attributes which are auto-generated).
    ///   - clusterRevision: The cluster revision to report. Defaults to the spec revision if available, otherwise 1.
    ///   - featureMap: The feature map bitmask. Defaults to 0.
    ///   - acceptedCommands: Command IDs this cluster accepts. Defaults to empty.
    ///   - generatedCommands: Command IDs this cluster generates. Defaults to empty.
    ///   - onWrite: Callback for attribute writes. Return `true` to accept, `false` to reject.
    ///   - onCommand: Callback for command invocations.
    public init(
        clusterID: ClusterID,
        attributes: [(AttributeID, TLVElement)] = [],
        clusterRevision: UInt16? = nil,
        featureMap: UInt32 = 0,
        acceptedCommands: [CommandID] = [],
        generatedCommands: [CommandID] = [],
        onWrite: AttributeWriteCallback? = nil,
        onCommand: CommandInvokeCallback? = nil
    ) {
        self.clusterID = clusterID
        self.featureMap = featureMap
        self.onWrite = onWrite
        self.onCommand = onCommand
        self.acceptedCommandIDs = acceptedCommands
        self.generatedCommandIDs = generatedCommands

        let spec = ClusterSpecRegistry.spec(for: clusterID)
        self.spec = spec
        self.clusterRevision = clusterRevision ?? spec?.revision ?? 1

        // Build the attribute dictionary from initial values
        var attrDict = [AttributeID: TLVElement]()
        for (id, value) in attributes {
            attrDict[id] = value
        }
        self.attributes = attrDict
        self.initialAttributeList = attributes
    }

    // MARK: - ClusterHandler Conformance

    public func initialAttributes() -> [(AttributeID, TLVElement)] {
        initialAttributeList
    }

    public func acceptedCommands() -> [CommandID] {
        acceptedCommandIDs
    }

    public func generatedCommands() -> [CommandID] {
        generatedCommandIDs
    }

    public func handleCommand(
        commandID: CommandID,
        fields: TLVElement?,
        store: AttributeStore,
        endpointID: EndpointID
    ) throws -> TLVElement? {
        guard let onCommand else {
            return nil
        }

        // The ClusterHandler protocol is synchronous, but our callback is async.
        // Bridge the gap with a semaphore. In practice, bridge commands should be fast.
        let resultBox = UnsafeBox<TLVElement?>(nil)
        let errorBox = UnsafeBox<(any Error)?>(nil)

        let semaphore = DispatchSemaphore(value: 0)
        let cmdFields = fields ?? .structure([])

        Task {
            do {
                resultBox.value = try await onCommand(commandID, cmdFields)
            } catch {
                errorBox.value = error
            }
            semaphore.signal()
        }
        semaphore.wait()

        if let error = errorBox.value {
            throw error
        }
        return resultBox.value
    }

    public func validateWrite(attributeID: AttributeID, value: TLVElement) -> WriteValidation {
        // If no write callback is set, reject all writes
        guard let onWrite else {
            return .unsupportedWrite
        }

        // Validate against spec metadata if available
        if let spec, let attrSpec = spec.attributes.first(where: { $0.id == attributeID }) {
            // Check nullability
            if case .null = value {
                if !attrSpec.isNullable {
                    return .constraintError
                }
            } else if attrSpec.type != .unknown && !attrSpec.type.isCompatible(with: value) {
                // Type mismatch
                return .constraintError
            }
        }

        // Delegate to the bridge callback (synchronous bridge)
        let acceptedBox = UnsafeBox<Bool>(false)
        let semaphore = DispatchSemaphore(value: 0)

        Task {
            acceptedBox.value = await onWrite(attributeID, value)
            semaphore.signal()
        }
        semaphore.wait()

        return acceptedBox.value ? .allowed : .rejected(status: 0x87)
    }

    public func responseCommandID(for requestCommandID: CommandID) -> CommandID? {
        // Look up from spec metadata if available
        if let spec, let cmdSpec = spec.commands.first(where: { $0.id == requestCommandID }) {
            return cmdSpec.responseID
        }
        return nil
    }

    public func requiresTimedInteraction(commandID: CommandID) -> Bool {
        if let spec, let cmdSpec = spec.commands.first(where: { $0.id == commandID }) {
            return cmdSpec.isTimedInvoke
        }
        return false
    }

    public func isFabricScoped(attributeID: AttributeID) -> Bool {
        false
    }

    public func filterFabricScopedAttribute(attributeID: AttributeID, value: TLVElement, fabricIndex: FabricIndex) -> TLVElement {
        value
    }

    public func generatedEvents(commandID: CommandID, endpointID: EndpointID, store: AttributeStore) -> [ClusterEvent] {
        []
    }

    // MARK: - Bridge-Side State Management

    /// Update an attribute value from the bridge side.
    ///
    /// Call this when the backing device's state changes and the Matter
    /// attribute store needs to be updated (e.g., a sensor reading changed).
    /// Thread-safe.
    ///
    /// - Parameters:
    ///   - attributeID: The attribute to update.
    ///   - value: The new TLV value.
    public func updateAttribute(_ attributeID: AttributeID, value: TLVElement) {
        lock.lock()
        defer { lock.unlock() }
        attributes[attributeID] = value
    }

    /// Read the current value of an attribute from the handler's internal state.
    /// Thread-safe.
    ///
    /// - Parameter attributeID: The attribute to read.
    /// - Returns: The current TLV value, or `nil` if not set.
    public func getAttribute(_ attributeID: AttributeID) -> TLVElement? {
        lock.lock()
        defer { lock.unlock() }
        return attributes[attributeID]
    }
}
