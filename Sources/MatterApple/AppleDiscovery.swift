// AppleDiscovery.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(Network)
import Foundation
import Network
import MatterTransport
import Logging

/// Apple platform mDNS/DNS-SD discovery using Network.framework (browsing/resolving)
/// and NetService (advertising).
///
/// **Advertising** uses `NetService` which registers with `mDNSResponder` via IPC.
/// This avoids binding to the service port — important because `AppleUDPTransport`
/// already holds the Matter data socket on the same port.
///
/// **Browsing** and **resolving** use `NWBrowser` and `NWConnection` from
/// Network.framework, which are better suited for asynchronous discovery.
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
    // `advertisedServices` and `browsers` are guarded by `lock`.
    // Rules:
    //   • Always acquire `lock` before reading or writing either collection.
    //   • Never hold `lock` across an `await` or a callback.

    private let lock = NSLock()

    // MARK: - State

    /// Active advertisements keyed by service name. `NetService` keeps the DNS-SD
    /// record alive with mDNSResponder as long as the object exists.
    private var advertisedServices: [String: NetService] = [:]
    private var browsers: [NWBrowser] = []
    private let queue = DispatchQueue(label: "matter.discovery", qos: .userInitiated)
    private let logger: Logger

    /// Background run loop required by NetService for IPC with mDNSResponder.
    private let serviceRunLoop: RunLoop

    // MARK: - Locking Helpers

    private func withLock<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }

    // MARK: - Init

    public init(logger: Logger = Logger(label: "matter.apple.discovery")) {
        self.logger = logger

        // Spin up a background thread with its own run loop.
        // NetService.publish() must be called on a run-loop thread so that the
        // underlying CFRunLoopSource can deliver IPC to mDNSResponder.
        var capturedRunLoop: RunLoop?
        let ready = DispatchSemaphore(value: 0)
        let thread = Thread {
            capturedRunLoop = RunLoop.current
            // Add a dummy Port as a persistent input source. Without at least one
            // source, RunLoop.run() returns immediately — causing any blocks
            // scheduled via perform(inModes:block:) after the signal to be lost.
            let keepAlivePort = Port()
            RunLoop.current.add(keepAlivePort, forMode: .default)
            ready.signal()
            RunLoop.current.run()   // Runs until the process exits
        }
        thread.name = "matter.discovery.runloop"
        thread.qualityOfService = .userInitiated
        thread.start()
        ready.wait()
        serviceRunLoop = capturedRunLoop!
    }

    // MARK: - MatterDiscovery

    public func advertise(service: MatterServiceRecord) async throws {
        // Cancel any existing advertisement for this name (under lock).
        let existing = withLock { () -> NetService? in
            let s = advertisedServices[service.name]
            advertisedServices.removeValue(forKey: service.name)
            return s
        }
        if let s = existing {
            let box = NetServiceBox(s)
            scheduleOnServiceRunLoop { box.value.stop() }
        }

        // Build TXT record payload.
        let txtDict = service.txtRecords.mapValues { $0.data(using: .utf8) ?? Data() }
        let txtData = NetService.data(fromTXTRecord: txtDict)

        // Build the service type string including any DNS-SD subtypes.
        // Format: "_primary._proto,_sub1,_sub2" — registers under _sub1._sub._primary._proto etc.
        // Matter commissionable discovery requires subtypes like _CM, _L<disc>, _S<shortDisc>.
        let typeString: String
        if service.subtypes.isEmpty {
            typeString = service.serviceType.rawValue
        } else {
            typeString = service.serviceType.rawValue + "," + service.subtypes.joined(separator: ",")
        }

        // Create the NetService.
        // NetService registers the DNS-SD SRV/TXT records with mDNSResponder
        // via IPC — it does NOT bind to the service port. This avoids any
        // conflict with the UDP transport socket on the same port.
        let ns = NetService(
            domain: "local.",
            type: typeString,
            name: service.name,
            port: Int32(service.port)
        )
        ns.setTXTRecord(txtData)

        // Store before scheduling so stopAdvertising() can cancel it immediately.
        withLock { advertisedServices[service.name] = ns }

        // Schedule publish on the run-loop thread and await its execution.
        let box = NetServiceBox(ns)
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            scheduleOnServiceRunLoop {
                box.value.schedule(in: .current, forMode: .default)
                box.value.publish()
                cont.resume()
            }
        }

        let subtypeDesc = service.subtypes.isEmpty ? "" : " subtypes=[\(service.subtypes.joined(separator: ","))]"
        logger.info("Advertising '\(service.name)' as \(service.serviceType.rawValue)\(subtypeDesc) on port \(service.port)")
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
        let toStop = withLock { () -> [NetService] in
            let all = Array(advertisedServices.values)
            advertisedServices.removeAll()
            return all
        }
        for s in toStop {
            let box = NetServiceBox(s)
            scheduleOnServiceRunLoop { box.value.stop() }
        }
    }

    public func stopAdvertising(name: String) async {
        let s = withLock { () -> NetService? in
            let ns = advertisedServices[name]
            advertisedServices.removeValue(forKey: name)
            return ns
        }
        if let ns = s {
            let box = NetServiceBox(ns)
            scheduleOnServiceRunLoop { box.value.stop() }
        }
    }

    // MARK: - Private

    private func scheduleOnServiceRunLoop(_ block: @escaping @Sendable () -> Void) {
        serviceRunLoop.perform(inModes: [.default], block: block)
    }

    /// Convert an `NWBrowser.Result` to a `MatterServiceRecord`.
    private func serviceRecord(
        from result: NWBrowser.Result,
        type: MatterServiceType
    ) -> MatterServiceRecord? {
        guard case .service(let name, _, _, _) = result.endpoint else {
            return nil
        }

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
            host: "",
            port: 0,
            txtRecords: txtRecords
        )
    }
}

// MARK: - Errors

/// Errors specific to Apple platform discovery.
public enum DiscoveryError: Error, Sendable {
    case resolveFailed(String)
}

// MARK: - Internal

/// `@unchecked Sendable` box for `NetService`.
///
/// `NetService` predates Swift concurrency and does not conform to `Sendable`.
/// All operations on the wrapped service are performed on the discovery run-loop
/// thread, so concurrent access never occurs in practice.
private struct NetServiceBox: @unchecked Sendable {
    let value: NetService
    init(_ value: NetService) { self.value = value }
}
#endif
