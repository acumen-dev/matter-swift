// AppleDiscovery.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Network
import MatterTransport
import Logging

/// Apple platform mDNS/DNS-SD discovery using Network.framework.
///
/// Uses `NWBrowser` for browsing and `NWListener` for advertising.
///
/// ```swift
/// let discovery = AppleDiscovery()
///
/// // Advertise as a commissionable device
/// try await discovery.advertise(service: MatterServiceRecord(
///     name: "My Device",
///     serviceType: .commissionable,
///     host: "",
///     port: 5540,
///     txtRecords: ["D": "3840", "VP": "65521+32769", "CM": "1"]
/// ))
///
/// // Browse for commissionable devices
/// for await record in discovery.browse(type: .commissionable) {
///     let address = try await discovery.resolve(record)
///     print("Found \(record.name) at \(address)")
/// }
/// ```
public final class AppleDiscovery: MatterDiscovery, @unchecked Sendable {

    // MARK: - Thread Safety
    //
    // `advertiseListeners` and `browsers` are guarded by `lock`.
    // Rules:
    //   • Always acquire `lock` before reading or writing either collection.
    //   • Never hold `lock` across an `await` or a Network.framework callback.
    //   • Obtain the values to act on (cancel, etc.) under the lock, then act
    //     outside the lock to avoid lock inversion with Network.framework internals.

    private let lock = NSLock()

    // MARK: - State

    private let queue = DispatchQueue(label: "matter.discovery", qos: .userInitiated)
    /// Active advertisements keyed by service name.
    private var advertiseListeners: [String: NWListener] = [:]
    private var browsers: [NWBrowser] = []
    private let logger: Logger

    // MARK: - Locking Helpers

    private func withLock<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }

    // MARK: - Init

    public init(logger: Logger = Logger(label: "matter.apple.discovery")) {
        self.logger = logger
    }

    // MARK: - MatterDiscovery

    public func advertise(service: MatterServiceRecord) async throws {
        let params = NWParameters.udp
        params.allowLocalEndpointReuse = true

        let nwPort = NWEndpoint.Port(rawValue: service.port) ?? .any
        let listener = try NWListener(using: params, on: nwPort)

        let txtRecord = NWTXTRecord.from(service.txtRecords)
        listener.service = NWListener.Service(
            name: service.name,
            type: service.serviceType.rawValue,
            domain: "local.",
            txtRecord: txtRecord
        )

        // Accept but immediately cancel any inbound connections — we're
        // only using the listener for its service advertisement.
        listener.newConnectionHandler = { connection in
            connection.cancel()
        }

        // Cancel any existing listener with the same name (under lock).
        // The new listener is not stored until it reaches .ready state.
        withLock { advertiseListeners[service.name]?.cancel() }

        listener.start(queue: queue)

        // Wait for listener to reach ready state. Use a `resumed` flag to
        // guard against double-resume if the listener transitions through
        // multiple states (e.g. .ready then .cancelled on stopAdvertising).
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            nonisolated(unsafe) var resumed = false
            listener.stateUpdateHandler = { [weak self] state in
                guard let self, !resumed else { return }
                switch state {
                case .ready:
                    self.logger.info("Advertising '\(service.name)' as \(service.serviceType.rawValue)")
                    resumed = true
                    cont.resume()
                case .failed(let error):
                    self.logger.error("Advertise failed for '\(service.name)': \(error)")
                    resumed = true
                    cont.resume(throwing: error)
                case .cancelled:
                    self.logger.debug("Advertise cancelled: \(service.name)")
                    resumed = true
                    cont.resume(throwing: CancellationError())
                default:
                    break
                }
            }
        }

        // Store the listener only on success (under lock).
        withLock { self.advertiseListeners[service.name] = listener }
    }

    public func browse(type: MatterServiceType) -> AsyncStream<MatterServiceRecord> {
        let descriptor = NWBrowser.Descriptor.bonjour(type: type.rawValue, domain: "local.")
        let browser = NWBrowser(for: descriptor, using: .udp)

        return AsyncStream { continuation in
            browser.browseResultsChangedHandler = { [weak self] results, _ in
                guard let self else { return }
                for result in results {
                    if let record = self.serviceRecord(from: result, type: type) {
                        continuation.yield(record)
                    }
                }
            }

            browser.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .failed(let error):
                    self.logger.error("Browse failed: \(error)")
                    continuation.finish()
                case .cancelled:
                    continuation.finish()
                default:
                    break
                }
            }

            continuation.onTermination = { @Sendable [weak self] _ in
                browser.cancel()
                self?.withLock { self?.browsers.removeAll { $0 === browser } }
            }

            browser.start(queue: self.queue)
            withLock { browsers.append(browser) }
        }
    }

    public func resolve(_ record: MatterServiceRecord) async throws -> MatterAddress {
        // Create a connection to the browsed service to trigger resolution
        let endpoint = NWEndpoint.service(
            name: record.name,
            type: record.serviceType.rawValue,
            domain: "local.",
            interface: nil
        )
        let connection = NWConnection(to: endpoint, using: .udp)

        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<MatterAddress, Error>) in
            nonisolated(unsafe) var resumed = false
            connection.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                guard !resumed else { return }
                switch state {
                case .ready:
                    if let remoteEndpoint = connection.currentPath?.remoteEndpoint,
                       let address = MatterAddress(endpoint: remoteEndpoint) {
                        resumed = true
                        cont.resume(returning: address)
                    } else {
                        resumed = true
                        cont.resume(throwing: DiscoveryError.resolveFailed(record.name))
                    }
                    connection.cancel()
                case .failed(let error):
                    self.logger.error("Resolve failed for '\(record.name)': \(error)")
                    resumed = true
                    cont.resume(throwing: error)
                    connection.cancel()
                case .cancelled:
                    if !resumed {
                        resumed = true
                        cont.resume(throwing: CancellationError())
                    }
                default:
                    break
                }
            }
            connection.start(queue: self.queue)
        }
    }

    public func stopAdvertising() async {
        let toCancel = withLock { () -> [NWListener] in
            let all = Array(advertiseListeners.values)
            advertiseListeners.removeAll()
            return all
        }
        toCancel.forEach { $0.cancel() }
    }

    public func stopAdvertising(name: String) async {
        let listener = withLock { () -> NWListener? in
            let l = advertiseListeners[name]
            advertiseListeners.removeValue(forKey: name)
            return l
        }
        listener?.cancel()
    }

    // MARK: - Internal

    /// Convert an `NWBrowser.Result` to a `MatterServiceRecord`.
    private func serviceRecord(
        from result: NWBrowser.Result,
        type: MatterServiceType
    ) -> MatterServiceRecord? {
        guard case .service(let name, _, _, _) = result.endpoint else {
            return nil
        }

        // Extract TXT records from browse result metadata.
        // NWTXTRecord conforms to Collection with Element = (key: String, value: Entry).
        var txtRecords: [String: String] = [:]
        if case .bonjour(let txtRecord) = result.metadata {
            for (key, entry) in txtRecord {
                if case .string(let value) = entry {
                    txtRecords[key] = value
                }
            }
        }

        return MatterServiceRecord(
            name: name,
            serviceType: type,
            host: "",   // Resolved later via resolve()
            port: 0,    // Resolved later via resolve()
            txtRecords: txtRecords
        )
    }
}

// MARK: - NWTXTRecord Helpers

extension NWTXTRecord {

    /// Create an `NWTXTRecord` from a dictionary.
    static func from(_ dictionary: [String: String]) -> NWTXTRecord {
        var record = NWTXTRecord()
        for (key, value) in dictionary {
            record[key] = value
        }
        return record
    }
}

// MARK: - Errors

/// Errors specific to Apple platform discovery.
public enum DiscoveryError: Error, Sendable {
    case resolveFailed(String)
}
