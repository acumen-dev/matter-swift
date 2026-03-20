// ConformanceModel.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

/// Represents a Matter conformance rule parsed from XML conformance elements.
indirect enum Conformance {
    case mandatory
    case optional
    case provisional
    case deprecated
    case disallowed
    /// Mandatory if the expression is true.
    case mandatoryIf(ConformanceExpression)
    /// Optional if the expression is true.
    case optionalIf(ConformanceExpression)
    /// Otherwise conformance: a list of (conformance, condition) pairs tried in order.
    case otherwise([Conformance])
    /// Unknown/unparsed conformance.
    case unknown
}

/// A boolean expression over features and attributes used in conditional conformance.
indirect enum ConformanceExpression {
    case feature(String)
    case attribute(String)
    case not(ConformanceExpression)
    case or([ConformanceExpression])
    case and([ConformanceExpression])
    case condition(String)
}

// MARK: - Text Rendering

extension Conformance {
    /// Renders the conformance as a human-readable doc comment fragment.
    var description: String {
        switch self {
        case .mandatory:
            return "mandatory"
        case .optional:
            return "optional"
        case .provisional:
            return "provisional"
        case .deprecated:
            return "deprecated"
        case .disallowed:
            return "disallowed"
        case .mandatoryIf(let expr):
            return "mandatory when \(expr.description)"
        case .optionalIf(let expr):
            return "optional when \(expr.description)"
        case .otherwise(let conformances):
            return conformances.map(\.description).joined(separator: " | ")
        case .unknown:
            return ""
        }
    }
}

extension ConformanceExpression {
    var description: String {
        switch self {
        case .feature(let name):
            return name
        case .attribute(let name):
            return name
        case .not(let expr):
            let inner = expr.description
            if case .or = expr { return "!(\(inner))" }
            if case .and = expr { return "!(\(inner))" }
            return "!\(inner)"
        case .or(let exprs):
            return exprs.map(\.description).joined(separator: " | ")
        case .and(let exprs):
            return exprs.map(\.description).joined(separator: " & ")
        case .condition(let name):
            return name
        }
    }
}
