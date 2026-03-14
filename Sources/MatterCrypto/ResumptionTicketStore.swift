// ResumptionTicketStore.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

/// Actor that manages CASE resumption tickets.
///
/// Tickets are keyed by `resumptionID`. When the store reaches capacity, the
/// ticket with the earliest expiry date is evicted. Consuming a ticket removes
/// it from the store — tickets are single-use to prevent replay attacks.
public actor ResumptionTicketStore {

    private var tickets: [Data: ResumptionTicket] = [:]

    /// Maximum number of tickets that can be stored simultaneously.
    public let maxTickets: Int

    public init(maxTickets: Int = 64) {
        self.maxTickets = maxTickets
    }

    // MARK: - Storage

    /// Store a resumption ticket.
    ///
    /// If the store is at capacity, the ticket with the earliest expiry date
    /// is removed to make space.
    public func store(ticket: ResumptionTicket) {
        if tickets.count >= maxTickets {
            if let oldest = tickets.min(by: { $0.value.expiryDate < $1.value.expiryDate }) {
                tickets.removeValue(forKey: oldest.key)
            }
        }
        tickets[ticket.resumptionID] = ticket
    }

    // MARK: - Retrieval

    /// Consume a ticket by resumption ID.
    ///
    /// Removes the ticket from the store (single-use). Returns `nil` if the
    /// ticket does not exist or has expired.
    public func consume(resumptionID: Data) -> ResumptionTicket? {
        guard let ticket = tickets.removeValue(forKey: resumptionID) else { return nil }
        guard ticket.expiryDate > Date() else { return nil }
        return ticket
    }

    // MARK: - Maintenance

    /// Remove all expired tickets from the store.
    public func purgeExpired() {
        let now = Date()
        tickets = tickets.filter { $0.value.expiryDate > now }
    }

    /// Number of tickets currently in the store.
    public var count: Int { tickets.count }
}
