// ControllerTelemetry.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Logging
import Metrics
import Tracing
import MatterTypes
import MatterProtocol

// MARK: - Bounded dimensions

/// `direction` of `<prefix>_controller_messages_total`.
enum MessageDirection: String, CaseIterable, Sendable {
    case inbound = "in"
    case outbound = "out"
}

/// `protocol` of `<prefix>_controller_messages_total`.
enum ProtocolLabel: String, CaseIterable, Sendable {
    case secureChannel = "secure_channel"
    case interactionModel = "interaction_model"
    case bdx
    case userDirectedCommissioning = "udc"
    case echo
    case other

    init(protocolID: UInt16) {
        switch MatterProtocolID(rawValue: protocolID) {
        case .secureChannel?: self = .secureChannel
        case .interactionModel?: self = .interactionModel
        case .bdx?: self = .bdx
        case .userDirectedCommissioning?: self = .userDirectedCommissioning
        case .echo?: self = .echo
        case nil: self = .other
        }
    }
}

/// `kind` of `<prefix>_im_requests_total` and `<prefix>_im_request_duration`.
enum IMRequestKind: String, CaseIterable, Sendable {
    case invoke, read, write, timed
}

/// `outcome` of `<prefix>_im_requests_total`.
enum IMRequestOutcome: String, CaseIterable, Sendable {
    case success
    case imStatus = "im_status"
    case timeout, unreachable, error

    init(_ error: any Error) {
        switch error {
        case ControllerError.imStatus, IMError.attributeStatus, IMError.commandStatus:
            self = .imStatus
        case ControllerError.timeout, MessagingError.responseTimeout:
            self = .timeout
        case ControllerError.peerUnreachable, MessagingError.peerUnreachable,
             MessagingError.sessionClosed, MessagingError.unknownSession:
            self = .unreachable
        default:
            self = .error
        }
    }

    /// The outcome to record for a failed request, or nil for an aborted one: cancellation and
    /// `stop()` are not failures and are not counted. After `stop()` the messenger's
    /// `MessagingError.stopped` reaches the caller already mapped, hence `controllerStopped`.
    init?(recording error: any Error, controllerStopped: Bool) {
        if isAborted(error, controllerStopped: controllerStopped) { return nil }
        self.init(error)
    }
}

/// Whether `error` ended an operation that was aborted rather than failed: cancellation, or
/// ``MatterController/stop()`` (the messenger's `MessagingError.stopped`, or `controllerStopped`
/// once the controller has mapped it).
fileprivate func isAborted(_ error: any Error, controllerStopped: Bool) -> Bool {
    controllerStopped || error is CancellationError || error as? MessagingError == .stopped
}

/// ``isAborted(_:controllerStopped:)`` for a subscription. Its own cancellation stands in for
/// `stop()`, which cancels every subscription before it stops the messenger.
func isSubscriptionAborted(_ error: any Error, cancelled: Bool) -> Bool {
    isAborted(error, controllerStopped: cancelled)
}

/// `type` of `<prefix>_sessions_established_total`.
enum SessionType: String, CaseIterable, Sendable {
    case caseSession = "case"
    case paseSession = "pase"
}

/// `outcome` of `<prefix>_sessions_established_total`.
enum SessionOutcome: String, CaseIterable, Sendable {
    case success, refused, timeout, unreachable, error

    init(_ error: any Error) {
        switch error {
        case ControllerError.caseSessionFailed, ControllerError.paseHandshakeFailed:
            self = .refused
        case ControllerError.timeout, MessagingError.responseTimeout:
            self = .timeout
        case ControllerError.peerUnreachable, MessagingError.peerUnreachable:
            self = .unreachable
        default:
            self = .error
        }
    }

    /// The outcome to record for a failed establishment, or nil for an aborted one, as
    /// ``IMRequestOutcome/init(recording:controllerStopped:)``: after `stop()` the messenger's
    /// `MessagingError.stopped` reaches here already mapped, hence `controllerStopped`.
    init?(recording error: any Error, controllerStopped: Bool) {
        if isAborted(error, controllerStopped: controllerStopped) { return nil }
        self.init(error)
    }
}

/// `reason` of `<prefix>_subscription_lost_total`.
enum SubscriptionLossReason: String, CaseIterable, Sendable {
    /// No report within the negotiated max interval plus the liveness margin.
    case liveness
    /// A re-establishment attempt failed.
    case resubscribeFailed = "resubscribe_failed"
    /// The session it ran on is gone, or its record was removed.
    case session
    /// Cancelled by its owner (including `stop()` and `removeDevice`).
    case closed
}

// MARK: - Metrics

/// Every controller metric, created once per dimension value so the hot path is a dictionary
/// lookup and an increment. Labels are `<prefix>_<name>`.
struct ControllerMetrics: Sendable {
    let messages: [MessageDirection: [ProtocolLabel: Counter]]
    let mrpRetransmits: Counter
    let mrpGiveUps: Counter
    let exchangeTimeouts: Counter
    let imRequests: [IMRequestKind: [IMRequestOutcome: Counter]]
    let imRequestDuration: [IMRequestKind: Metrics.Timer]
    let sessionsEstablished: [SessionType: [SessionOutcome: Counter]]
    /// Successful CASE establishments, handshake through registration. After an address-refresh
    /// retry it includes the failed attempt, the re-resolve and the second handshake.
    let caseDuration: Metrics.Timer
    let subscriptionLost: [SubscriptionLossReason: Counter]
    let resubscribes: Counter
    let reportInterval: Metrics.Timer

    init(prefix: String, factory: any MetricsFactory) {
        func counter(_ name: String, _ dimensions: [(String, String)] = []) -> Counter {
            Counter(label: "\(prefix)_\(name)", dimensions: dimensions, factory: factory)
        }
        func timer(_ name: String, _ dimensions: [(String, String)] = []) -> Metrics.Timer {
            Metrics.Timer(label: "\(prefix)_\(name)", dimensions: dimensions, factory: factory)
        }
        messages = Dictionary(uniqueKeysWithValues: MessageDirection.allCases.map { direction in
            (direction, Dictionary(uniqueKeysWithValues: ProtocolLabel.allCases.map { label in
                (label, counter("controller_messages_total", [("direction", direction.rawValue), ("protocol", label.rawValue)]))
            }))
        })
        mrpRetransmits = counter("mrp_retransmits_total")
        mrpGiveUps = counter("mrp_give_ups_total")
        exchangeTimeouts = counter("exchange_timeouts_total")
        imRequests = Dictionary(uniqueKeysWithValues: IMRequestKind.allCases.map { kind in
            (kind, Dictionary(uniqueKeysWithValues: IMRequestOutcome.allCases.map { outcome in
                (outcome, counter("im_requests_total", [("kind", kind.rawValue), ("outcome", outcome.rawValue)]))
            }))
        })
        imRequestDuration = Dictionary(uniqueKeysWithValues: IMRequestKind.allCases.map { kind in
            (kind, timer("im_request_duration", [("kind", kind.rawValue)]))
        })
        sessionsEstablished = Dictionary(uniqueKeysWithValues: SessionType.allCases.map { type in
            (type, Dictionary(uniqueKeysWithValues: SessionOutcome.allCases.map { outcome in
                (outcome, counter("sessions_established_total", [("type", type.rawValue), ("outcome", outcome.rawValue)]))
            }))
        })
        caseDuration = timer("case_duration")
        subscriptionLost = Dictionary(uniqueKeysWithValues: SubscriptionLossReason.allCases.map { reason in
            (reason, counter("subscription_lost_total", [("reason", reason.rawValue)]))
        })
        resubscribes = counter("resubscribes_total")
        reportInterval = timer("report_interval")
    }

    func message(_ direction: MessageDirection, protocolID: UInt16) {
        messages[direction]?[ProtocolLabel(protocolID: protocolID)]?.increment()
    }

    func imRequest(_ kind: IMRequestKind, _ outcome: IMRequestOutcome, duration: Duration) {
        imRequests[kind]?[outcome]?.increment()
        imRequestDuration[kind]?.record(duration: duration)
    }

    /// Counts every attempt; `case_duration` records successful CASE establishments only
    /// (including any address-refresh retry; see ``caseDuration``).
    func sessionEstablishment(_ type: SessionType, _ outcome: SessionOutcome, duration: Duration) {
        sessionsEstablished[type]?[outcome]?.increment()
        if type == .caseSession, outcome == .success {
            caseDuration.record(duration: duration)
        }
    }

    func subscriptionLoss(_ reason: SubscriptionLossReason) {
        subscriptionLost[reason]?.increment()
    }
}

// MARK: - Telemetry hub

/// Metrics and tracer shared by a messenger and everything built on it. Resolved once, at
/// creation: a process that bootstraps `MetricsSystem` / `InstrumentationSystem` must do so
/// before creating the controller, or pass a factory and tracer explicitly.
struct ControllerTelemetry: Sendable {
    let metrics: ControllerMetrics
    let tracer: any Tracer

    init(configuration: ControllerMessenger.Configuration) {
        metrics = ControllerMetrics(
            prefix: configuration.metricsLabelPrefix,
            factory: configuration.metricsFactory ?? MetricsSystem.factory
        )
        tracer = configuration.tracer ?? InstrumentationSystem.tracer
    }
}

// MARK: - Log metadata

extension Logger.Metadata {
    /// `matter.node` of a line about one node.
    static func node(_ nodeID: NodeID) -> Logger.Metadata {
        [MatterLogKey.node: MatterLogValue.hex(nodeID.rawValue)]
    }
}

/// The controller's injected logger once per subsystem it writes under (label unchanged).
struct ControllerLoggers: Sendable {
    let session: Logger
    let caseHandshake: Logger
    let paseHandshake: Logger
    let im: Logger
    let subscription: Logger
    let discovery: Logger

    init(_ base: Logger) {
        session = base.withSubsystem(.session)
        caseHandshake = base.withSubsystem(.caseHandshake)
        paseHandshake = base.withSubsystem(.paseHandshake)
        im = base.withSubsystem(.im)
        subscription = base.withSubsystem(.subscription)
        discovery = base.withSubsystem(.discovery)
    }
}
