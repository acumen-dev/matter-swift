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
/// - a known `uniqueID` always gets its recorded number back, across restarts;
/// - a new one gets the number after the highest ever issued. Once 0xFFFE has been
///   issued, new numbers continue with the lowest free one; 0xFFFF is never issued;
/// - a number becomes free only when its device is explicitly removed
///   (`MatterBridge.removeEndpoint`), never because the process stopped. So a removed
///   device's number is reused only after the count has wrapped;
/// - a second live device with the same `uniqueID` gets a number of its own, which is
///   not recorded.
///
/// This follows the allocation rule of Matter Core § 9.2.10 as implemented by
/// matter.js (https://github.com/matter-js/matter.js/pull/4716): count up from the
/// highest number used, and after 0xFFFE continue with the lowest free number.
///
/// The state is persisted inside `StoredDeviceState` through the fabric store, by
/// `CommissioningState`, which owns this allocator. Until that state has been loaded
/// the allocator issues provisional IDs from an empty map (sequential from 3) and asks
/// for nothing to be saved; `load(assigned:highest:)` then adopts what was issued,
/// since the host already holds those numbers. Hosts cannot reach that path:
/// `MatterBridge.init(config:fabricStore:attributeStore:)` loads before returning.
///
/// Thread-safe: `add*` runs on the host's context while saves run on the server actor.
final class BridgedEndpointAllocator: @unchecked Sendable {

    /// The numbers a bridged device can get: 0 (root), 1 (aggregator) and 2 (reserved)
    /// belong to the bridge, and 0xFFFF is not a valid endpoint number.
    static let issuable: ClosedRange<UInt16> = 3...0xFFFE

    private let lock = NSLock()
    private var assigned: [String: UInt16] = [:]
    private var highest: UInt16 = 0
    private var live: [UInt16: String] = [:]
    private var loaded = false

    // MARK: - Allocation

    /// Issue an endpoint ID for a device.
    ///
    /// - Parameters:
    ///   - uniqueID: The device's stable identity.
    ///   - isInUse: Whether an endpoint ID is already registered by other means.
    /// - Returns: The ID, and whether the persisted allocation state changed and is
    ///   ready to be saved (never before the stored state has been loaded).
    func allocate(uniqueID: String, isInUse: (UInt16) -> Bool) -> (id: EndpointID, needsSave: Bool) {
        lock.withLock {
            if let known = assigned[uniqueID], live[known] == nil, !isInUse(known) {
                live[known] = uniqueID
                return (EndpointID(rawValue: known), false)
            }

            let candidate = nextFree(isInUse: isInUse)
            highest = max(highest, candidate)
            // A second live device with the same uniqueID gets its own ID but does not
            // take over the first one's entry.
            if assigned[uniqueID] == nil {
                assigned[uniqueID] = candidate
            }
            live[candidate] = uniqueID
            return (EndpointID(rawValue: candidate), loaded)
        }
    }

    /// The next number to issue. Must be called with `lock` held.
    private func nextFree(isInUse: (UInt16) -> Bool) -> UInt16 {
        let taken = Set(assigned.values).union(live.keys)
        func isFree(_ n: UInt16) -> Bool { !taken.contains(n) && !isInUse(n) }

        // Count up from the highest number ever issued...
        if highest < Self.issuable.upperBound {
            var n = max(highest + 1, Self.issuable.lowerBound)
            while n <= Self.issuable.upperBound {
                if isFree(n) { return n }
                if n == Self.issuable.upperBound { break }
                n += 1
            }
        }
        // ...and once 0xFFFE has been issued, take the lowest free number.
        guard let lowest = Self.issuable.first(where: isFree) else {
            preconditionFailure("All \(Self.issuable.count) bridged endpoint numbers are in use")
        }
        return lowest
    }

    /// The device on `id` was removed: free its number.
    ///
    /// - Returns: Whether the persisted allocation state changed and is ready to be saved.
    func remove(_ id: EndpointID) -> Bool {
        lock.withLock {
            live.removeValue(forKey: id.rawValue)
            let owners = assigned.filter { $0.value == id.rawValue }.map(\.key)
            for owner in owners {
                assigned.removeValue(forKey: owner)
            }
            return !owners.isEmpty && loaded
        }
    }

    // MARK: - Persistence

    /// Merge the stored allocation state. Only the first call has any effect.
    ///
    /// Stored numbers outside ``issuable`` are ignored, and a high-water mark outside it
    /// or below a stored number is replaced by the highest valid stored number.
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

            var merged = stored.filter { Self.issuable.contains($0.value) }
            let validHighest = Self.issuable.contains(storedHighest) ? storedHighest : 0
            var mergedHighest = max(validHighest, merged.values.max() ?? 0)
            for (id, uniqueID) in live {
                mergedHighest = max(mergedHighest, id)
                guard merged[uniqueID] != id else { continue }
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
