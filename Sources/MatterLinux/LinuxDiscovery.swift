// LinuxDiscovery.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import NIOCore
import NIOPosix
import MatterTransport
import Logging

// MARK: - LinuxDiscovery

/// Linux platform mDNS/DNS-SD discovery using a pure-Swift mDNS responder (RFC 6762).
///
/// Binds a UDP socket to port 5353 and joins the IPv4 mDNS multicast group
/// (`224.0.0.251`). Handles PTR/SRV/TXT advertisement and PTR browsing without
/// any external dependency beyond SwiftNIO.
///
/// ```swift
/// let discovery = LinuxDiscovery()
/// try await discovery.advertise(service: MatterServiceRecord(
///     name: "My Bridge",
///     serviceType: .commissionable,
///     host: "",
///     port: 5540,
///     txtRecords: ["D": "3840", "CM": "1"]
/// ))
/// for await record in discovery.browse(type: .commissionable) {
///     print("Found: \(record.name)")
/// }
/// ```
public actor LinuxDiscovery: MatterDiscovery {

    // MARK: - State

    private var advertised: [String: MatterServiceRecord] = [:]
    /// Keyed by service type rawValue → (UUID → continuation), to allow
    /// precise removal on stream termination without requiring class identity.
    private var browseStreams: [String: [UUID: AsyncStream<MatterServiceRecord>.Continuation]] = [:]
    private var pendingResolves: [String: CheckedContinuation<MatterAddress, Error>] = [:]
    private var channel: Channel?
    private let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    private let logger: Logger
    private var announceTask: Task<Void, Never>?

    // MARK: - Init

    public init(logger: Logger = Logger(label: "matter.linux.discovery")) {
        self.logger = logger
    }

    // MARK: - MatterDiscovery

    public func advertise(service: MatterServiceRecord) async throws {
        try await ensureMDNSChannel()
        advertised[service.name] = service
        try await sendAnnouncement(for: service, ttl: 4500)
        restartAnnounceTask()
        logger.info("Advertising '\(service.name)' as \(service.serviceType.rawValue)")
    }

    public func stopAdvertising() async {
        let all = advertised
        advertised.removeAll()
        announceTask?.cancel()
        announceTask = nil
        for service in all.values {
            try? await sendAnnouncement(for: service, ttl: 0)
        }
    }

    public func stopAdvertising(name: String) async {
        guard let service = advertised.removeValue(forKey: name) else { return }
        try? await sendAnnouncement(for: service, ttl: 0)
        if advertised.isEmpty {
            announceTask?.cancel()
            announceTask = nil
        }
    }

    /// `nonisolated` to satisfy the non-`async` `MatterDiscovery` protocol requirement.
    /// Actor state is accessed safely via `Task { await self. }` inside the closure.
    public nonisolated func browse(type: MatterServiceType) -> AsyncStream<MatterServiceRecord> {
        let key = type.rawValue
        let streamID = UUID()
        return AsyncStream { [weak self] continuation in
            Task { [weak self] in
                await self?.addBrowseContinuation(continuation, id: streamID, key: key)
                try? await self?.ensureMDNSChannel()
                try? await self?.sendPTRQuery(serviceType: key)
            }
            continuation.onTermination = { @Sendable [weak self] _ in
                Task { await self?.removeBrowseContinuation(id: streamID, key: key) }
            }
        }
    }

    public func resolve(_ record: MatterServiceRecord) async throws -> MatterAddress {
        try await ensureMDNSChannel()
        // For a service we're already advertising, return our own address immediately.
        if let local = advertised[record.name] {
            return MatterAddress(host: ProcessInfo.processInfo.hostName, port: local.port)
        }
        let hostname = record.host.isEmpty ? "\(record.name).local" : record.host
        return try await withCheckedThrowingContinuation { cont in
            pendingResolves[hostname] = cont
            Task {
                try? await self.sendAQuery(hostname: hostname)
                try? await Task.sleep(for: .seconds(5))
                self.timeoutResolve(hostname: hostname)
            }
        }
    }

    // MARK: - Internal: Browse continuation management

    private func addBrowseContinuation(
        _ cont: AsyncStream<MatterServiceRecord>.Continuation,
        id: UUID,
        key: String
    ) {
        browseStreams[key, default: [:]][id] = cont
    }

    private func removeBrowseContinuation(id: UUID, key: String) {
        browseStreams[key]?.removeValue(forKey: id)
    }

    private func timeoutResolve(hostname: String) {
        guard let cont = pendingResolves.removeValue(forKey: hostname) else { return }
        cont.resume(throwing: LinuxDiscoveryError.resolveTimeout(hostname))
    }

    // MARK: - Internal: mDNS channel

    private func ensureMDNSChannel() async throws {
        guard channel == nil else { return }

        let callback: @Sendable (Data, SocketAddress) -> Void = { [weak self] data, addr in
            Task { await self?.handleIncoming(data: data, from: addr) }
        }
        let handler = MDNSHandler(callback: callback)

        let ch = try await DatagramBootstrap(group: group)
            .channelOption(.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(handler)
                }
            }
            .bind(host: "0.0.0.0", port: 5353)
            .get()

        // Join IPv4 mDNS multicast group 224.0.0.251
        let multicastAddr = try SocketAddress(ipAddress: "224.0.0.251", port: 5353)
        try await (ch as! MulticastChannel).joinGroup(multicastAddr).get()

        self.channel = ch
        logger.debug("mDNS socket bound on port 5353")
    }

    // MARK: - Internal: Send helpers

    private func sendAnnouncement(for service: MatterServiceRecord, ttl: UInt32) async throws {
        guard let ch = channel else { return }

        let hostname = ProcessInfo.processInfo.hostName
        let instanceName = "\(service.name).\(service.serviceType.rawValue)"
        let serviceTypeDomain = "\(service.serviceType.rawValue).local"

        var msg = DNSMessage(isResponse: true, isAuthoritative: true)

        // PTR: _service._proto.local → instance._service._proto.local
        msg.answers.append(DNSRecord(
            name: serviceTypeDomain,
            type: .ptr,
            ttl: ttl,
            rdata: .ptr(domain: instanceName)
        ))

        if ttl > 0 {
            // SRV: instance → priority:0 weight:0 port:N hostname.local
            msg.answers.append(DNSRecord(
                name: instanceName,
                type: .srv,
                ttl: ttl,
                rdata: .srv(priority: 0, weight: 0, port: service.port, target: "\(hostname).local")
            ))
            // TXT: instance → key=value strings
            let txtStrings = service.txtRecords.map { "\($0.key)=\($0.value)" }
            msg.answers.append(DNSRecord(
                name: instanceName,
                type: .txt,
                ttl: ttl,
                rdata: .txt(txtStrings.isEmpty ? [""] : txtStrings)
            ))
        }

        try await sendToMulticast(ch: ch, message: msg)
    }

    private func sendPTRQuery(serviceType: String) async throws {
        guard let ch = channel else { return }
        var msg = DNSMessage(isResponse: false)
        msg.questions.append(DNSQuestion(name: "\(serviceType).local", type: .ptr))
        try await sendToMulticast(ch: ch, message: msg)
    }

    private func sendAQuery(hostname: String) async throws {
        guard let ch = channel else { return }
        var msg = DNSMessage(isResponse: false)
        msg.questions.append(DNSQuestion(name: hostname, type: .a))
        msg.questions.append(DNSQuestion(name: hostname, type: .aaaa))
        try await sendToMulticast(ch: ch, message: msg)
    }

    private func sendToMulticast(ch: Channel, message: DNSMessage) async throws {
        let dest = try SocketAddress(ipAddress: "224.0.0.251", port: 5353)
        let encoded = message.encode()
        var buf = ch.allocator.buffer(capacity: encoded.count)
        buf.writeBytes(encoded)
        try await ch.writeAndFlush(AddressedEnvelope(remoteAddress: dest, data: buf)).get()
    }

    // MARK: - Internal: Announce task

    private func restartAnnounceTask() {
        announceTask?.cancel()
        announceTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                guard !Task.isCancelled else { break }
                await self?.reannounceAll()
            }
        }
    }

    private func reannounceAll() async {
        for service in advertised.values {
            try? await sendAnnouncement(for: service, ttl: 4500)
        }
    }

    // MARK: - Internal: Incoming packet handler

    func handleIncoming(data: Data, from sender: SocketAddress) {
        guard let msg = DNSMessage.decode(from: data) else { return }
        if msg.isResponse {
            handleResponse(msg)
        } else {
            handleQuery(msg)
        }
    }

    private func handleResponse(_ msg: DNSMessage) {
        for record in msg.answers + msg.additionals {
            switch record.rdata {
            case .ptr(let domain):
                let parts = record.name.split(separator: ".")
                guard parts.count >= 3 else { continue }
                // record.name is "_matterc._udp.local" — strip ".local" for lookup key
                let serviceTypeKey = parts.dropLast().joined(separator: ".")
                guard let conts = browseStreams[serviceTypeKey], !conts.isEmpty else { continue }
                // domain is "InstanceName._matterc._udp.local"
                let domainParts = domain.split(separator: ".")
                let instanceName = domainParts.first.map(String.init) ?? domain
                let serviceTypeParts = domainParts.dropFirst().dropLast().joined(separator: ".")
                guard let svcType = MatterServiceType(rawValue: serviceTypeParts) else { continue }
                let discovered = MatterServiceRecord(
                    name: instanceName, serviceType: svcType,
                    host: "", port: 0, txtRecords: [:]
                )
                for cont in conts.values { cont.yield(discovered) }

            case .a(let bytes):
                guard bytes.count == 4 else { continue }
                let host = "\(bytes[0]).\(bytes[1]).\(bytes[2]).\(bytes[3])"
                fulfillResolve(recordName: record.name, host: host)

            case .aaaa(let bytes):
                guard bytes.count == 16 else { continue }
                let groups = stride(from: 0, to: 16, by: 2).map { i in
                    String(format: "%x", UInt16(bytes[i]) << 8 | UInt16(bytes[i + 1]))
                }
                fulfillResolve(recordName: record.name, host: groups.joined(separator: ":"))

            default:
                break
            }
        }
    }

    private func fulfillResolve(recordName: String, host: String) {
        let bare = recordName.replacingOccurrences(of: ".local", with: "")
        for key in pendingResolves.keys where key.hasPrefix(bare) || bare.hasPrefix(key) {
            if let cont = pendingResolves.removeValue(forKey: key) {
                cont.resume(returning: MatterAddress(host: host, port: 0))
            }
        }
    }

    private func handleQuery(_ msg: DNSMessage) {
        for question in msg.questions {
            guard question.type == .ptr || question.type == .any else { continue }
            let queryServiceType = question.name.replacingOccurrences(of: ".local", with: "")
            for service in advertised.values where service.serviceType.rawValue == queryServiceType {
                Task { try? await sendAnnouncement(for: service, ttl: 4500) }
            }
        }
    }
}

// MARK: - MDNSHandler

private final class MDNSHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>

    private let callback: @Sendable (Data, SocketAddress) -> Void

    init(callback: @escaping @Sendable (Data, SocketAddress) -> Void) {
        self.callback = callback
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var envelope = Self.unwrapInboundIn(data)
        let bytes = envelope.data.readBytes(length: envelope.data.readableBytes) ?? []
        callback(Data(bytes), envelope.remoteAddress)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}

// MARK: - Errors

public enum LinuxDiscoveryError: Error, Sendable {
    case resolveTimeout(String)
    case channelSetupFailed
}
