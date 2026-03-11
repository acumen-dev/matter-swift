// MRPConfig.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

/// Configuration parameters for the Message Reliability Protocol (MRP).
///
/// MRP provides acknowledged delivery over unreliable transports (UDP).
/// These defaults match the Matter specification.
public struct MRPConfig: Sendable {
    /// Base retransmission interval.
    public var baseRetryInterval: Duration

    /// Maximum number of retransmissions before giving up.
    public var maxRetransmissions: Int

    /// Number of retransmissions before switching to backoff.
    public var backoffThreshold: Int

    /// Multiplier applied after backoff threshold.
    public var backoffMultiplier: Double

    /// Random jitter factor (±percentage of interval).
    public var backoffJitter: Double

    /// Additional margin applied to backoff intervals.
    public var backoffMargin: Double

    /// Time to wait before sending a standalone ACK.
    public var standaloneAckTimeout: Duration

    /// Default MRP configuration per the Matter specification.
    public static let `default` = MRPConfig(
        baseRetryInterval: .milliseconds(300),
        maxRetransmissions: 10,
        backoffThreshold: 1,
        backoffMultiplier: 1.6,
        backoffJitter: 0.25,
        backoffMargin: 1.1,
        standaloneAckTimeout: .milliseconds(200)
    )

    /// Calculate the retry interval for a given attempt number.
    ///
    /// - Parameter attempt: Zero-based attempt number (0 = first retry).
    /// - Returns: The retry interval with jitter applied.
    public func retryInterval(attempt: Int) -> Duration {
        let baseMs = Double(baseRetryInterval.milliseconds)

        var intervalMs: Double
        if attempt <= backoffThreshold {
            intervalMs = baseMs
        } else {
            let backoffAttempts = attempt - backoffThreshold
            intervalMs = baseMs * pow(backoffMultiplier, Double(backoffAttempts)) * backoffMargin
        }

        // Apply jitter (±percentage)
        let jitterRange = intervalMs * backoffJitter
        let jitter = Double.random(in: -jitterRange...jitterRange)
        intervalMs += jitter

        return .milliseconds(Int(max(intervalMs, 1)))
    }
}

// MARK: - Duration Extension

extension Duration {
    /// The total milliseconds represented by this duration.
    var milliseconds: Int64 {
        let (seconds, attoseconds) = components
        return seconds * 1000 + attoseconds / 1_000_000_000_000_000
    }
}
