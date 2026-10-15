// BridgedEndpointAllocator.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import MatterTypes

/// Issues bridged endpoint IDs that stay stable per device across restarts.
///
/// A device's endpoint number is part of the bridge's identity toward its fabrics:
/// a controller binds its tiles and automations to it. The allocator keys numbers on
/// the `uniqueID` the host passes to every `MatterBridge.add*`:
///
/// - a known `uniqueID` gets its recorded ID back;
/// - a new one gets the highest ID ever issued + 1, so a removed device's ID is never
///   reused;
/// - an empty `uniqueID` cannot be keyed and gets a fresh ID every time.
///
/// The state is persisted inside `StoredDeviceState` through the fabric store, by
/// `CommissioningState`, which owns this allocator. Until that state has been loaded
/// the allocator issues provisional IDs from an empty map (sequential from 3 — the
/// historical behaviour) and asks for nothing to be saved; `load(assigned:highest:)`
/// then adopts what was issued, since the host already holds those numbers.
///
/// Thread-safe: `add*` runs on the host's context while saves run on the server actor.
final class BridgedEndpointAllocator: @unchecked Sendable {

    /// Endpoints 0 (root), 1 (aggregator) and 2 (reserved) are never issued.
    private static let lastReservedEndpoint: UInt16 = 2

    private let lock = NSLock()
    private var assigned: [String: UInt16] = [:]
    private var highest: UInt16 = 0
    private var live: [UInt16: String] = [:]
    private var loaded = false

    // MARK: - Allocation

    /// Issue an endpoint ID for a device.
    ///
    /// - Parameters:
    ///   - uniqueID: The device's stable identity, or empty if it has none.
    ///   - isInUse: Whether an endpoint ID is already registered by other means.
    /// - Returns: The ID, and whether the persisted allocation state changed and is
    ///   ready to be saved (never before the stored state has been loaded).
    func allocate(uniqueID: String, isInUse: (UInt16) -> Bool) -> (id: EndpointID, needsSave: Bool) {
        lock.withLock {
            if !uniqueID.isEmpty, let known = assigned[uniqueID], live[known] == nil, !isInUse(known) {
                live[known] = uniqueID
                return (EndpointID(rawValue: known), false)
            }

            var candidate = max(highest, Self.lastReservedEndpoint) + 1
            while live[candidate] != nil || isInUse(candidate) {
                candidate += 1
            }
            highest = candidate
            // A second live device with the same uniqueID gets its own ID but does not
            // take over the first one's entry.
            if !uniqueID.isEmpty, assigned[uniqueID] == nil {
                assigned[uniqueID] = candidate
            }
            live[candidate] = uniqueID
            return (EndpointID(rawValue: candidate), loaded)
        }
    }

    /// Mark an endpoint ID as no longer registered. Its `uniqueID` keeps the ID.
    func release(_ id: EndpointID) {
        lock.withLock { _ = live.removeValue(forKey: id.rawValue) }
    }

    // MARK: - Persistence

    /// Merge the stored allocation state. Only the first call has any effect.
    ///
    /// Endpoints issued before this call keep their IDs — the host already holds them
    /// — and are recorded, displacing any stored device that held the same ID. With
    /// an empty stored map this records today's call order, which is the migration
    /// path for installations that predate persisted allocation.
    ///
    /// - Returns: `true` if the merged state differs from the stored state and should
    ///   be saved.
    func load(assigned stored: [String: UInt16], highest storedHighest: UInt16) -> Bool {
        lock.withLock {
            guard !loaded else { return false }
            loaded = true

            var merged = stored
            var mergedHighest = storedHighest
            for (id, uniqueID) in live {
                mergedHighest = max(mergedHighest, id)
                guard !uniqueID.isEmpty, merged[uniqueID] != id else { continue }
                for (other, otherID) in merged where otherID == id {
                    merged.removeValue(forKey: other)
                }
                merged[uniqueID] = id
            }

            assigned = merged
            highest = mergedHighest
            return merged != stored || mergedHighest != storedHighest
        }
    }

    /// The allocation state to persist.
    func snapshot() -> (assigned: [String: UInt16], highest: UInt16) {
        lock.withLock { (assigned, highest) }
    }
}
