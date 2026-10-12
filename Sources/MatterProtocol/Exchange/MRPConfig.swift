// MRPConfig.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

// MARK: - Peer parameters

/// A peer's advertised MRP session parameters (Matter Core §4.12.8; DNS-SD
/// TXT keys `SII`, `SAI`, `SAT`).
///
/// A sleepy end device advertises a long idle interval: retransmissions
/// toward it while it is idle are spaced by `SII` so they land while it
/// listens, instead of exhausting while it sleeps.
public struct MRPParameters: Sendable, Hashable, Codable {
    /// Session idle interval (`SII`): base retransmission interval while the
    /// peer is idle.
    public var sessionIdleInterval: Duration

    /// Session active interval (`SAI`): base retransmission interval while
    /// the peer is active.
    public var sessionActiveInterval: Duration

    /// Session active threshold (`SAT`): for how long after the peer's last
    /// message it counts as active.
    public var sessionActiveThreshold: Duration

    /// Spec defaults: SII 500 ms, SAI 300 ms, SAT 4000 ms.
    public static let `default` = MRPParameters()

    /// Largest interval accepted from a TXT record, in milliseconds (one hour).
    public static let maximumAdvertisedMilliseconds: UInt32 = 3_600_000

    public init(
        sessionIdleInterval: Duration = .milliseconds(500),
        sessionActiveInterval: Duration = .milliseconds(300),
        sessionActiveThreshold: Duration = .milliseconds(4000)
    ) {
        self.sessionIdleInterval = sessionIdleInterval
        self.sessionActiveInterval = sessionActiveInterval
        self.sessionActiveThreshold = sessionActiveThreshold
    }

    /// Parse `SII` / `SAI` / `SAT` (decimal milliseconds) from DNS-SD TXT
    /// records. A missing, non-numeric or out-of-range (> 3 600 000) value
    /// falls back to the default for that key only; so does a zero `SII` or
    /// `SAI` (below 1 ms), which would make retransmission spin.
    public init(txtRecords: [String: String]) {
        let defaults = MRPParameters.default
        self.init(
            sessionIdleInterval: Self.milliseconds(txtRecords["SII"], minimum: 1) ?? defaults.sessionIdleInterval,
            sessionActiveInterval: Self.milliseconds(txtRecords["SAI"], minimum: 1) ?? defaults.sessionActiveInterval,
            sessionActiveThreshold: Self.milliseconds(txtRecords["SAT"]) ?? defaults.sessionActiveThreshold
        )
    }

    private static func milliseconds(_ text: String?, minimum: UInt32 = 0) -> Duration? {
        guard let text, let value = UInt32(text), value >= minimum, value <= maximumAdvertisedMilliseconds else {
            return nil
        }
        return .milliseconds(Int64(value))
    }
}

// MARK: - MRP configuration

/// Message Reliability Protocol configuration (Matter Core §4.12).
///
/// MRP provides acknowledged delivery over UDP. Defaults are the spec's
/// (`MRP_MAX_TRANSMISSIONS` = 5, i.e. 4 retransmissions). The device server
/// passes `maxRetransmissions: 10` to keep its historical behaviour toward
/// Apple Home.
public struct MRPConfig: Sendable {
    /// The peer's advertised parameters; supplies the base interval.
    public var peer: MRPParameters

    /// Retransmissions after the initial transmission before giving up.
    public var maxRetransmissions: Int

    /// `MRP_BACKOFF_THRESHOLD`: transmissions sent at the base interval
    /// before exponential backoff starts.
    public var backoffThreshold: Int

    /// `MRP_BACKOFF_BASE`: backoff multiplier.
    public var backoffBase: Double

    /// `MRP_BACKOFF_JITTER`: maximum random addition, as a fraction.
    public var backoffJitter: Double

    /// `MRP_BACKOFF_MARGIN`: fixed margin on every interval.
    public var backoffMargin: Double

    /// `MRP_STANDALONE_ACK_TIMEOUT`: how long an owed ack waits for a
    /// message to piggyback on before it is sent alone.
    public var standaloneAckTimeout: Duration

    /// Spec defaults with ``MRPParameters/default`` peer parameters.
    public static let `default` = MRPConfig()

    public init(
        peer: MRPParameters = .default,
        maxRetransmissions: Int = 4,
        backoffThreshold: Int = 1,
        backoffBase: Double = 1.6,
        backoffJitter: Double = 0.25,
        backoffMargin: Double = 1.1,
        standaloneAckTimeout: Duration = .milliseconds(200)
    ) {
        self.peer = peer
        self.maxRetransmissions = maxRetransmissions
        self.backoffThreshold = backoffThreshold
        self.backoffBase = backoffBase
        self.backoffJitter = backoffJitter
        self.backoffMargin = backoffMargin
        self.standaloneAckTimeout = standaloneAckTimeout
    }

    /// The wait after a transmission before retransmitting (Matter Core
    /// §4.12.2.1):
    ///
    ///     i · MARGIN · BASE^max(0, n − THRESHOLD) · (1 + JITTER · u)
    ///
    /// - Parameters:
    ///   - n: transmissions of this message already sent — 1 after the
    ///     first send, 2 after the first retransmission.
    ///   - peerActive: `i` is SAI when true (the peer spoke within SAT),
    ///     otherwise SII.
    ///   - u: jitter unit in `0...1` (clamped).
    /// - Returns: the interval rounded to the nearest nanosecond, at least 1 ns.
    public func retransmissionInterval(transmissionsSoFar n: Int, peerActive: Bool, jitterUnit u: Double) -> Duration {
        let base = peerActive ? peer.sessionActiveInterval : peer.sessionIdleInterval
        let exponent = Double(max(0, n - backoffThreshold))
        let jitter = 1 + backoffJitter * min(max(u, 0), 1)
        let nanoseconds = (base.totalNanoseconds * backoffMargin * pow(backoffBase, exponent) * jitter).rounded()
        return .nanoseconds(Int64(max(1, nanoseconds)))
    }

    /// The longest a message can stay unacknowledged before MRP gives up:
    /// the sum of every interval (`n` = 1 … `maxRetransmissions + 1`) at full
    /// jitter. A receive waits at least this long, so a silent peer surfaces
    /// as unreachable rather than as a response timeout.
    public func exhaustionHorizon(peerActive: Bool) -> Duration {
        guard maxRetransmissions >= 0 else { return .zero }
        return (1...(maxRetransmissions + 1)).reduce(Duration.zero) {
            $0 + retransmissionInterval(transmissionsSoFar: $1, peerActive: peerActive, jitterUnit: 1)
        }
    }
}

// MARK: - Duration Extension

extension Duration {
    /// The total milliseconds represented by this duration.
    var milliseconds: Int64 {
        let (seconds, attoseconds) = components
        return seconds * 1000 + attoseconds / 1_000_000_000_000_000
    }

    /// The duration in nanoseconds as a `Double` (exact for MRP-sized intervals).
    var totalNanoseconds: Double {
        let (seconds, attoseconds) = components
        return Double(seconds) * 1_000_000_000 + Double(attoseconds) / 1_000_000_000
    }
}
