// InterfacePolicy.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

/// Which network interfaces Matter traffic may use on a multi-homed host.
public struct InterfacePolicy: Sendable, Equatable, CustomStringConvertible {
    /// Interface names tried in order before the route table's choice.
    public var preferred: [String]
    /// Interface names that are never used.
    public var excluded: Set<String>

    public init(preferred: [String] = [], excluded: Set<String> = []) {
        self.preferred = preferred
        self.excluded = excluded
    }

    /// No preference or exclusion: the route table decides.
    public static let automatic = InterfacePolicy()

    public func allows(_ interfaceName: String) -> Bool { !excluded.contains(interfaceName) }

    public var description: String {
        "preferred=[\(preferred.joined(separator: ","))] excluded=[\(excluded.sorted().joined(separator: ","))]"
    }
}

/// A point-in-time view of one network interface.
public struct InterfaceSnapshot: Sendable, Equatable {
    public var name: String
    public var index: UInt32
    /// `IFF_UP && IFF_RUNNING`.
    public var isUp: Bool
    /// Canonical literals, link-local without zone.
    public var addresses: [String]

    public init(name: String, index: UInt32, isUp: Bool, addresses: [String]) {
        self.name = name
        self.index = index
        self.isUp = isUp
        self.addresses = addresses
    }
}

/// Why a named interface is not usable as the policy expects.
public enum InterfaceProblem: Sendable, Equatable { case missing, down }

/// The result of choosing a path under an ``InterfacePolicy``.
public struct PathSelection: Sendable, Equatable {
    public enum Skip: Sendable, Equatable { case missing, down, excluded, noRoute }

    /// The chosen path, or nil when no allowed interface has a route.
    public var path: MatterPath?
    /// How the path was chosen; nil exactly when `path` is nil.
    public var outcome: PathSelectionOutcome?
    /// Preferred interfaces passed over before the chosen one, in order, with why.
    public var skipped: [(name: String, reason: Skip)]

    public init(path: MatterPath?, outcome: PathSelectionOutcome?, skipped: [(name: String, reason: Skip)] = []) {
        self.path = path
        self.outcome = outcome
        self.skipped = skipped
    }

    public static func == (lhs: PathSelection, rhs: PathSelection) -> Bool {
        lhs.path == rhs.path && lhs.outcome == rhs.outcome
            && lhs.skipped.count == rhs.skipped.count
            && zip(lhs.skipped, rhs.skipped).allSatisfy { $0.name == $1.name && $0.reason == $1.reason }
    }
}

/// Pure path selection: preferred interfaces in order, then the route table's
/// choice, then any other usable interface with a route.
public struct PathSelector: Sendable {
    public let policy: InterfacePolicy

    public init(policy: InterfacePolicy) {
        self.policy = policy
    }

    /// `route(interface)` returns the source address that interface would use for
    /// the peer, or nil (no route). `route(nil)` is the unscoped route table's
    /// choice: (interface index, source).
    public func select(
        interfaces: [InterfaceSnapshot],
        route: (InterfaceSnapshot?) -> (index: UInt32, source: String)?
    ) -> PathSelection {
        var skipped: [(name: String, reason: PathSelection.Skip)] = []

        func chosen(_ iface: InterfaceSnapshot, _ source: String, _ outcome: PathSelectionOutcome) -> PathSelection {
            PathSelection(
                path: MatterPath(interfaceIndex: iface.index, interfaceName: iface.name, localAddress: source),
                outcome: outcome,
                skipped: skipped)
        }

        for name in policy.preferred {
            guard let iface = interfaces.first(where: { $0.name == name }) else {
                skipped.append((name, .missing)); continue
            }
            guard iface.isUp else { skipped.append((name, .down)); continue }
            guard policy.allows(name) else { skipped.append((name, .excluded)); continue }
            guard let r = route(iface) else { skipped.append((name, .noRoute)); continue }
            return chosen(iface, r.source, skipped.isEmpty ? .preferred : .`fallthrough`)
        }

        if let r = route(nil),
           let iface = interfaces.first(where: { $0.index == r.index }),
           iface.isUp, policy.allows(iface.name) {
            return chosen(iface, r.source, policy.preferred.isEmpty ? .routeTable : .`fallthrough`)
        }

        for iface in interfaces
        where iface.isUp && policy.allows(iface.name) && !policy.preferred.contains(iface.name) {
            if let r = route(iface) { return chosen(iface, r.source, .`fallthrough`) }
        }

        return PathSelection(path: nil, outcome: nil, skipped: skipped)
    }
}

/// Tracks which named interfaces are missing or down, so each change is logged once.
public struct InterfacePolicyMonitor: Sendable {
    public let policy: InterfacePolicy
    private var known: [String: InterfaceProblem] = [:]

    public init(policy: InterfacePolicy) {
        self.policy = policy
    }

    /// Problems with named (preferred or excluded) interfaces now, keyed by name.
    /// A preferred interface is a problem when missing or down; an excluded one
    /// only when missing (it may be a typo), since being down is harmless.
    public static func problems(policy: InterfacePolicy, interfaces: [InterfaceSnapshot]) -> [String: InterfaceProblem] {
        var result: [String: InterfaceProblem] = [:]
        for name in policy.excluded where !interfaces.contains(where: { $0.name == name }) {
            result[name] = .missing
        }
        for name in policy.preferred {
            if let iface = interfaces.first(where: { $0.name == name }) {
                if !iface.isUp { result[name] = .down }
            } else {
                result[name] = .missing
            }
        }
        return result
    }

    /// Changes since the last call: (name, problem now, or nil = resolved).
    public mutating func update(_ interfaces: [InterfaceSnapshot]) -> [(name: String, problem: InterfaceProblem?)] {
        let now = Self.problems(policy: policy, interfaces: interfaces)
        var changes: [(name: String, problem: InterfaceProblem?)] = []
        for name in Set(now.keys).union(known.keys).sorted() where now[name] != known[name] {
            changes.append((name, now[name]))
        }
        known = now
        return changes
    }
}
